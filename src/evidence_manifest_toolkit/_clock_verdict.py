# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the Clock acceptance verdict over the six declared checks

"""Recompute what a bound Clock subject can show of its six acceptance checks.

The acceptance body declares six checks, each ``pass``, ``fail`` or ``unavailable`` with its
evidence. A declared result is never the answer: each check this module can recompute is
recomputed, and a declared ``pass`` that the evidence contradicts is refused. A declared
``fail`` or ``unavailable`` is kept, since a source may report less than can be shown, never
more. The Clock is accepted only when all six are ``pass``.

Three checks are relational (whole sources, controller identity, acyclic whole target). Two are
read from the Clock calculation, which has already refused every inconsistent NTP exchange,
sample claim, use bound and window: synchronization and mapping holds once that calculation
exists, and the uncertainty budget holds when the drift rate is at least RFC 5905's frequency
tolerance, every sample's declared holdover covers its age since its NTP exchange, and the whole
interval lies within the profile's maximum around the evaluation origin. Without a calculation
both stay ``unavailable``. The server's identity is not captured by the selected raw source, so
synchronization is consistency of the recorded exchange, not proof of whom it was with. The
class's authority and time has no rule here yet and stays ``unavailable``.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction
from math import ceil
from typing import Literal, cast

from ._clock_method_calculate import ClockMethodCalculation
from ._clock_subject import BoundClockSubject
from ._clock_values import ClockSample, clock_integer
from ._errors import InputRefused
from ._json import JsonValue
from ._results import ReferenceObservation
from ._values import Digest, Reason

CHECK_IDS = (
    "whole_source_match",
    "controller_source_match",
    "synchronization_and_mapping",
    "proven_uncertainty_budget",
    "selected_class_authority_and_time",
    "acyclic_whole_target",
)
"""The six acceptance checks, in the order the Clock format names them."""

UNDECIDED = {"selected_class_authority_and_time": "D2"}
"""The checks without a rule yet, each with the decision its rule waits for."""

MINIMUM_DRIFT_RATE = Fraction(15, 1_000_000)
"""RFC 5905's frequency tolerance PHI: the least drift rate the uncertainty budget accepts."""

type CheckResult = Literal["pass", "fail", "unavailable"]


@dataclass(frozen=True, slots=True)
class ClockVerdict:
    """The six check results after recomputation, in the format's order.

    Attributes
    ----------
    checks : Mapping
        Each check id mapped to ``pass``, ``fail`` or ``unavailable``.
    """

    checks: Mapping[str, CheckResult]

    @property
    def accepted(self) -> bool:
        """Return whether every one of the six checks passes."""
        return all(self.checks.get(check) == "pass" for check in CHECK_IDS)


@dataclass(frozen=True, slots=True)
class SampleAge:
    """One Clock sample beside the NTP exchange it uses and its declared age terms.

    Attributes
    ----------
    utc_ns, exchange_ns : int
        The sample's UTC and its exchange's destination time T4, both Unix-epoch nanoseconds.
    holdover_ns, adjustment_ns : int
        The sample's declared elapsed-holdover and post-exchange-adjustment bounds.
    """

    utc_ns: int
    exchange_ns: int
    holdover_ns: int
    adjustment_ns: int


@dataclass(frozen=True, slots=True)
class ClockEvidence:
    """The numbers the Clock calculation proved that the uncertainty budget reads.

    Attributes
    ----------
    samples : tuple of SampleAge
        The acceptance's before and after samples, then the witness's.
    drift_rate : Fraction
        The drift record's maximum error rate, in nanoseconds per elapsed nanosecond.
    lower_ns, upper_ns : int
        The whole capture-through-entry interval.
    origin_ns, maximum_ns : int
        The evaluation origin and the profile's maximum uncertainty.
    """

    samples: tuple[SampleAge, ...]
    drift_rate: Fraction
    lower_ns: int
    upper_ns: int
    origin_ns: int
    maximum_ns: int


def clock_evidence(
    calculation: ClockMethodCalculation | None, clock: BoundClockSubject
) -> ClockEvidence | None:
    """Collect what the uncertainty budget reads from a completed Clock calculation.

    Parameters
    ----------
    calculation : ClockMethodCalculation or None
        The calculation over the bound subject, absent when it was not reached.
    clock : BoundClockSubject
        The bound subject whose samples, origin and profile the calculation used.

    Returns
    -------
    ClockEvidence or None
        ``None`` without a calculation; otherwise the four samples with their exchanges and
        declared terms, the drift rate, the whole interval, the origin and the maximum.
    """
    if calculation is None:
        return None
    acceptance = cast(dict[str, JsonValue], clock.sources.documents["acceptance"].value)
    profile = cast(dict[str, JsonValue], clock.sources.documents["profile"].value)
    annual = tuple(
        ClockSample.from_value(
            cast(dict[str, JsonValue], acceptance[name]),
            origin=clock.native_entry.origin,
            subject=clock.sources.fixed["acceptance"].source.reference.digest,
            pointer="/" + name,
        )
        for name in ("before", "after")
    )
    pairs = (
        (annual[0], calculation.acceptance.before),
        (annual[1], calculation.acceptance.after),
        (clock.before, calculation.before),
        (clock.after, calculation.after),
    )
    return ClockEvidence(
        tuple(
            SampleAge(
                sample.utc_ns,
                estimate.measurement.destination_ns,
                estimate.additional.elapsed_holdover_ns,
                estimate.additional.post_exchange_adjustment_ns,
            )
            for sample, estimate in pairs
        ),
        calculation.methods.maximum_error_rate,
        calculation.use.whole.lower_ns,
        calculation.use.whole.upper_ns,
        clock.evaluation_origin_ns,
        clock_integer(
            cast(str, profile["maximum_uncertainty_ns"]),
            signed=False,
            subject=clock.sources.fixed["profile"].source.reference.digest,
            pointer="/maximum_uncertainty_ns",
        ),
    )


def _budget_holds(evidence: ClockEvidence) -> bool:
    """Return whether the rate, every sample's holdover and the whole interval are within bounds."""
    return (
        evidence.drift_rate >= MINIMUM_DRIFT_RATE
        and all(
            sample.holdover_ns
            >= ceil(
                evidence.drift_rate * (sample.utc_ns - sample.exchange_ns + sample.adjustment_ns)
            )
            for sample in evidence.samples
        )
        and evidence.origin_ns - evidence.maximum_ns <= evidence.lower_ns
        and evidence.upper_ns <= evidence.origin_ns + evidence.maximum_ns
    )


def _refused(code: str, subject: Digest, pointer: str, detail: str) -> InputRefused:
    """Return a located refusal of the acceptance body."""
    return InputRefused(Reason(code, subject, None, pointer, detail))


def _resolved(
    index: int,
    evidence: list[JsonValue],
    acceptance_digest: Digest,
    observations: tuple[ReferenceObservation, ...],
) -> bool:
    """Return whether every evidence reference of one check resolved in the Clock closure."""
    matched = {
        observation.pointer
        for observation in observations
        if observation.subject_digest == acceptance_digest and observation.outcome == "matched"
    }
    return all(
        f"/checks/{index}/evidence_refs/{position}" in matched for position in range(len(evidence))
    )


def clock_verdict(
    *,
    acceptance: Mapping[str, JsonValue],
    acceptance_digest: Digest,
    witness: Mapping[str, JsonValue],
    subject: Mapping[str, JsonValue],
    observations: tuple[ReferenceObservation, ...],
    closure_reasons: tuple[Reason, ...],
    missing_references: int,
    source_reasons: tuple[Reason, ...],
    evidence: ClockEvidence | None,
) -> ClockVerdict:
    """Recompute the relational and calculated checks and keep the rest as the rules allow.

    Parameters
    ----------
    acceptance, witness, subject : Mapping
        The bound Clock subject's acceptance body, witness and evaluation subject documents.
    acceptance_digest : str
        The acceptance body's digest, the subject of its refusals.
    observations : tuple of ReferenceObservation
        Every edge of the Clock sources' closure.
    closure_reasons, source_reasons : tuple of Reason
        The closure's refusals and the Clock sources' acquisition refusals.
    missing_references : int
        How many required references the closure could not find.
    evidence : ClockEvidence or None
        What the Clock calculation proved, absent when it was not reached.

    Returns
    -------
    ClockVerdict
        The six results. A declared ``fail`` or ``unavailable`` is kept as declared; a check
        without a rule here, or a calculated check without a calculation, is ``unavailable``.

    Raises
    ------
    InputRefused
        ``invalid_schema`` when the checks do not name each of the six exactly once or one
        repeats an evidence reference; ``policy_unavailable`` at ``/checks/<index>/result``
        when a declared ``pass`` is contradicted by its evidence.
    """
    checks = cast(list[dict[str, JsonValue]], acceptance["checks"])
    named = [cast(str, item["check_id"]) for item in checks]
    if sorted(named) != sorted(CHECK_IDS):
        raise _refused(
            "invalid_schema",
            acceptance_digest,
            "/checks",
            "The Clock acceptance must declare each of its six checks once.",
        )
    results: dict[str, CheckResult] = {}
    for index, item in enumerate(checks):
        check = cast(str, item["check_id"])
        references = cast(list[JsonValue], item["evidence_refs"])
        if len({json.dumps(ref, sort_keys=True) for ref in references}) != len(references):
            raise _refused(
                "invalid_schema",
                acceptance_digest,
                f"/checks/{index}/evidence_refs",
                "A Clock acceptance check repeats an evidence reference.",
            )
        declared = cast(CheckResult, item["result"])
        calculated = check in ("synchronization_and_mapping", "proven_uncertainty_budget")
        if check in UNDECIDED or (calculated and evidence is None):
            results[check] = "unavailable"
            continue
        resolved = _resolved(index, references, acceptance_digest, observations)
        if check == "whole_source_match":
            holds = resolved and not source_reasons
        elif check == "controller_source_match":
            holds = (
                resolved
                and acceptance["controller_identity_ref"]
                == witness["controller_identity_ref"]
                == subject["verification_controller_identity_ref"]
                and acceptance["observer_identity_ref"] == witness["observer_identity_ref"]
            )
        elif check == "synchronization_and_mapping":
            holds = resolved
        elif check == "proven_uncertainty_budget":
            holds = resolved and _budget_holds(cast(ClockEvidence, evidence))
        else:
            holds = resolved and not closure_reasons and missing_references == 0
        if declared == "pass" and not holds:
            raise _refused(
                "policy_unavailable",
                acceptance_digest,
                f"/checks/{index}/result",
                f"The declared Clock acceptance check {check} is contradicted by its evidence.",
            )
        results[check] = declared
    return ClockVerdict({check: results[check] for check in CHECK_IDS})
