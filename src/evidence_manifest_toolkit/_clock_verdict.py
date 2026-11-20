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
more. Three checks have no rule here yet (synchronization and mapping, the uncertainty budget,
and the class's authority and time); they stay ``unavailable``. The Clock is accepted only when
all six are ``pass``.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

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

UNDECIDED = {
    "synchronization_and_mapping": "D1",
    "proven_uncertainty_budget": "D3",
    "selected_class_authority_and_time": "D2",
}
"""The checks without a rule yet, each with the decision its rule waits for."""

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
) -> ClockVerdict:
    """Recompute the relational checks and keep the rest as the rules allow.

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

    Returns
    -------
    ClockVerdict
        The six results. A declared ``fail`` or ``unavailable`` is kept as declared; a check
        without a rule here is ``unavailable``.

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
        evidence = cast(list[JsonValue], item["evidence_refs"])
        if len({json.dumps(ref, sort_keys=True) for ref in evidence}) != len(evidence):
            raise _refused(
                "invalid_schema",
                acceptance_digest,
                f"/checks/{index}/evidence_refs",
                "A Clock acceptance check repeats an evidence reference.",
            )
        declared = cast(CheckResult, item["result"])
        if check in UNDECIDED:
            results[check] = "unavailable"
            continue
        resolved = _resolved(index, evidence, acceptance_digest, observations)
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
