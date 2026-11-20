# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the Clock acceptance verdict over its six checks

"""Recompute the Clock checks the evidence decides, keep lesser declarations, refuse a false pass.

Each case builds the documents and closure edges the verdict reads from a bound Clock subject:
the acceptance body with its six declared checks, the witness, the evaluation subject, the
closure's observations and refusals, and the numbers the Clock calculation proved. A declared
``pass`` must reproduce; a declared ``fail`` or ``unavailable`` stays; a check whose evidence
is missing, or which has no rule yet, stays ``unavailable``.
"""

from dataclasses import asdict
from fractions import Fraction
from typing import TypedDict, cast

import pytest

from evidence_manifest_toolkit import InputRefused, Reason
from evidence_manifest_toolkit._clock_subject import BoundClockSubject
from evidence_manifest_toolkit._clock_verdict import (
    CHECK_IDS,
    MINIMUM_DRIFT_RATE,
    UNSIGNED_CLASS,
    ClockEvidence,
    ClockVerdict,
    SampleAge,
    clock_evidence,
    clock_verdict,
)
from evidence_manifest_toolkit._json import JsonValue
from evidence_manifest_toolkit._results import ReferenceObservation

ACCEPTANCE = "sha256:" + "a" * 64
CONTROLLER: dict[str, JsonValue] = {"name": "controller"}
OBSERVER: dict[str, JsonValue] = {"name": "observer"}
ORIGIN = 1_795_128_000_000_000_000
MAXIMUM = 5_000_000_000
AGE = 13_452_201_545
"""UTC minus T4 of a real WS capture's acceptance sample (U11-4b design addendum 1)."""
ADJUSTMENT = 1_000
HOLDOVER = 201_784
"""ceil(15/1000000 * (AGE + ADJUSTMENT)): 201783.038175 rounded up."""
COMPUTED = ("synchronization_and_mapping", "proven_uncertainty_budget")
AUTHORITY = "selected_class_authority_and_time"


def _evidence(index: int) -> dict[str, JsonValue]:
    """Return a distinct evidence reference for one check."""
    return {"evidence": index}


def _acceptance(
    results: dict[str, str],
    *,
    custody_class: str = UNSIGNED_CLASS,
    issuer: JsonValue = None,
) -> dict[str, JsonValue]:
    """Return an acceptance body declaring the given results, ``unavailable`` elsewhere."""
    return {
        "custody_class": custody_class,
        "issuer_identity_ref": issuer,
        "issuer_authorization_ref": None,
        "controller_identity_ref": CONTROLLER,
        "observer_identity_ref": OBSERVER,
        "checks": [
            {
                "check_id": check,
                "result": results.get(check, "unavailable"),
                "evidence_refs": [_evidence(i)],
            }
            for i, check in enumerate(CHECK_IDS)
        ],
    }


def _matched(indexes: range | list[int]) -> tuple[ReferenceObservation, ...]:
    """Return matched closure edges from the acceptance body to the named checks' evidence."""
    return tuple(
        ReferenceObservation(
            ACCEPTANCE, "checks", f"/checks/{i}/evidence_refs/0", True, None, "matched", ()
        )
        for i in indexes
    )


def _sample(*, age: int = AGE, holdover: int = HOLDOVER, adjustment: int = ADJUSTMENT) -> SampleAge:
    """Return one sample taken ``age`` nanoseconds after its NTP exchange."""
    utc = ORIGIN + 1_000_000
    return SampleAge(utc, utc - age, holdover, adjustment)


def _clock_evidence(
    *,
    samples: tuple[SampleAge, ...] | None = None,
    drift_rate: Fraction = MINIMUM_DRIFT_RATE,
    lower_ns: int = ORIGIN - MAXIMUM,
    upper_ns: int = ORIGIN + MAXIMUM,
) -> ClockEvidence:
    """Return calculated numbers that hold at every boundary unless a case moves one."""
    return ClockEvidence(
        samples=samples if samples is not None else (_sample(), _sample(), _sample(), _sample()),
        drift_rate=drift_rate,
        lower_ns=lower_ns,
        upper_ns=upper_ns,
        origin_ns=ORIGIN,
        maximum_ns=MAXIMUM,
    )


def _verdict(
    acceptance: dict[str, JsonValue],
    *,
    witness: dict[str, JsonValue] | None = None,
    subject: dict[str, JsonValue] | None = None,
    observations: tuple[ReferenceObservation, ...] | None = None,
    closure_reasons: tuple[Reason, ...] = (),
    missing: int = 0,
    source_reasons: tuple[Reason, ...] = (),
    evidence: ClockEvidence | None = None,
) -> ClockVerdict:
    """Run the verdict over a whole set of inputs, matching ones unless a case changes them."""
    return clock_verdict(
        acceptance=acceptance,
        acceptance_digest=ACCEPTANCE,
        witness=witness
        if witness is not None
        else {"controller_identity_ref": CONTROLLER, "observer_identity_ref": OBSERVER},
        subject=subject
        if subject is not None
        else {"verification_controller_identity_ref": CONTROLLER},
        observations=observations if observations is not None else _matched(range(len(CHECK_IDS))),
        closure_reasons=closure_reasons,
        missing_references=missing,
        source_reasons=source_reasons,
        evidence=evidence,
    )


class _Changes(TypedDict, total=False):
    """The verdict inputs one contradiction case replaces."""

    witness: dict[str, JsonValue]
    subject: dict[str, JsonValue]
    observations: tuple[ReferenceObservation, ...]
    closure_reasons: tuple[Reason, ...]
    missing: int
    source_reasons: tuple[Reason, ...]
    evidence: ClockEvidence | None


RELATIONAL = ("whole_source_match", "controller_source_match", "acyclic_whole_target")
CYCLE = Reason("cycle_detected", ACCEPTANCE, None, None, "Reference cycle.")


def test_the_verdict_keeps_six_slots_in_order_and_relational_passes_reproduce() -> None:
    """Without a calculation, the two computed checks and the undecided one stay unavailable."""
    verdict = _verdict(_acceptance({check: "pass" for check in CHECK_IDS}))
    assert tuple(verdict.checks) == CHECK_IDS
    assert {check: verdict.checks[check] for check in RELATIONAL} == dict.fromkeys(
        RELATIONAL, "pass"
    )
    assert {check: verdict.checks[check] for check in (*COMPUTED, AUTHORITY)} == dict.fromkeys(
        (*COMPUTED, AUTHORITY), "unavailable"
    )
    assert verdict.accepted is False


def test_with_a_calculation_synchronization_and_the_budget_pass_at_their_boundaries() -> None:
    """Rate at the floor, holdover at its exact ceiling, interval at plus/minus the maximum."""
    verdict = _verdict(
        _acceptance({check: "pass" for check in CHECK_IDS}), evidence=_clock_evidence()
    )
    assert {check: verdict.checks[check] for check in COMPUTED} == dict.fromkeys(COMPUTED, "pass")
    assert verdict.checks[AUTHORITY] == "pass"
    assert verdict.accepted is True


def test_unsigned_time_is_qualified_by_the_recomputed_checks_not_the_declared_ones() -> None:
    """Synchronization and the budget declared unavailable still qualify the unsigned time."""
    verdict = _verdict(_acceptance({AUTHORITY: "pass"}), evidence=_clock_evidence())
    assert verdict.checks[AUTHORITY] == "pass"
    assert {check: verdict.checks[check] for check in COMPUTED} == dict.fromkeys(
        COMPUTED, "unavailable"
    )
    assert verdict.accepted is False


def test_another_class_has_no_rule_for_its_authority_and_time() -> None:
    """A software or protected acceptance keeps the check unavailable even with every bound held."""
    for custody_class in ("software_local_unprotected", "protected_delegated"):
        verdict = _verdict(
            _acceptance({check: "pass" for check in CHECK_IDS}, custody_class=custody_class),
            evidence=_clock_evidence(),
        )
        assert verdict.checks[AUTHORITY] == "unavailable"
        assert verdict.accepted is False


def test_the_check_order_of_the_acceptance_does_not_change_the_verdict() -> None:
    """The authority check reads the recomputed time checks wherever they are declared."""
    acceptance = _acceptance({check: "pass" for check in CHECK_IDS})
    checks = acceptance["checks"]
    assert isinstance(checks, list)
    reordered = {**acceptance, "checks": list(reversed(checks))}
    observations = tuple(
        ReferenceObservation(
            ACCEPTANCE, "checks", f"/checks/{i}/evidence_refs/0", True, None, "matched", ()
        )
        for i in range(len(CHECK_IDS))
    )
    verdict = _verdict(reordered, observations=observations, evidence=_clock_evidence())
    assert verdict.accepted is True


def test_a_declared_fail_or_unavailable_is_kept_even_when_it_would_pass() -> None:
    """A source may report less than can be shown, never more."""
    verdict = _verdict(
        _acceptance({"whole_source_match": "fail", "proven_uncertainty_budget": "fail"}),
        evidence=_clock_evidence(),
    )
    assert verdict.checks["whole_source_match"] == "fail"
    assert verdict.checks["proven_uncertainty_budget"] == "fail"
    assert verdict.checks["controller_source_match"] == "unavailable"
    assert verdict.checks["synchronization_and_mapping"] == "unavailable"


def test_the_verdict_is_accepted_only_when_all_six_pass() -> None:
    """Acceptance needs every slot; one slot short is not accepted."""
    assert ClockVerdict(dict.fromkeys(CHECK_IDS, "pass")).accepted is True
    assert (
        ClockVerdict({**dict.fromkeys(CHECK_IDS, "pass"), "acyclic_whole_target": "fail"}).accepted
        is False
    )


@pytest.mark.parametrize(
    ("check", "changes"),
    [
        ("whole_source_match", {"source_reasons": (CYCLE,)}),
        ("whole_source_match", {"observations": _matched([1, 2, 3, 4, 5])}),
        (
            "controller_source_match",
            {"witness": {"controller_identity_ref": CONTROLLER, "observer_identity_ref": {}}},
        ),
        (
            "controller_source_match",
            {"witness": {"controller_identity_ref": {}, "observer_identity_ref": OBSERVER}},
        ),
        ("controller_source_match", {"subject": {"verification_controller_identity_ref": {}}}),
        ("acyclic_whole_target", {"closure_reasons": (CYCLE,)}),
        ("acyclic_whole_target", {"missing": 1}),
        (
            "synchronization_and_mapping",
            {"observations": _matched([0, 1, 3, 4, 5]), "evidence": _clock_evidence()},
        ),
        (
            "proven_uncertainty_budget",
            {"observations": _matched([0, 1, 2, 4, 5]), "evidence": _clock_evidence()},
        ),
        (
            "proven_uncertainty_budget",
            {
                "evidence": _clock_evidence(
                    samples=(_sample(), _sample(), _sample(holdover=HOLDOVER - 1), _sample())
                )
            },
        ),
        (
            "proven_uncertainty_budget",
            {
                "evidence": _clock_evidence(
                    samples=(_sample(adjustment=1_000_000), _sample(), _sample(), _sample())
                )
            },
        ),
        (
            "proven_uncertainty_budget",
            {
                "evidence": _clock_evidence(
                    samples=(_sample(holdover=10**12),) * 4,
                    drift_rate=Fraction(14, 1_000_000),
                )
            },
        ),
        (
            "proven_uncertainty_budget",
            {"evidence": _clock_evidence(drift_rate=Fraction(20, 1_000_000))},
        ),
        ("proven_uncertainty_budget", {"evidence": _clock_evidence(lower_ns=ORIGIN - MAXIMUM - 1)}),
        ("proven_uncertainty_budget", {"evidence": _clock_evidence(upper_ns=ORIGIN + MAXIMUM + 1)}),
    ],
    ids=[
        "whole_source_with_source_refusal",
        "whole_source_with_unresolved_evidence",
        "controller_with_other_observer",
        "controller_with_other_witness_controller",
        "controller_with_other_subject_controller",
        "acyclic_with_closure_refusal",
        "acyclic_with_missing_reference",
        "synchronization_with_unresolved_evidence",
        "budget_with_unresolved_evidence",
        "budget_with_holdover_one_under_its_ceiling",
        "budget_with_holdover_short_of_the_adjusted_age",
        "budget_with_a_rate_under_the_floor",
        "budget_with_holdover_short_at_the_records_higher_rate",
        "budget_with_the_interval_one_under",
        "budget_with_the_interval_one_over",
    ],
)
def test_a_declared_pass_contradicted_by_its_evidence_is_refused(
    check: str, changes: dict[str, object]
) -> None:
    """The refusal names the acceptance body and the check's result, and says it is contradicted."""
    index = CHECK_IDS.index(check)
    with pytest.raises(InputRefused) as caught:
        _verdict(_acceptance({check: "pass"}), **cast(_Changes, changes))
    assert asdict(caught.value.reason) == {
        "code": "policy_unavailable",
        "subject_digest": ACCEPTANCE,
        "claim_id": None,
        "pointer": f"/checks/{index}/result",
        "detail": f"The declared Clock acceptance check {check} is contradicted by its evidence.",
    }


@pytest.mark.parametrize(
    ("acceptance", "changes"),
    [
        (
            _acceptance({AUTHORITY: "pass"}, issuer={"name": "issuer"}),
            {"evidence": _clock_evidence()},
        ),
        (
            _acceptance({AUTHORITY: "pass"}),
            {"evidence": _clock_evidence(drift_rate=Fraction(14, 1_000_000))},
        ),
        (
            _acceptance({AUTHORITY: "pass"}),
            {"observations": _matched([0, 1, 3, 4, 5]), "evidence": _clock_evidence()},
        ),
        (
            _acceptance({AUTHORITY: "pass"}),
            {"observations": _matched([0, 1, 2, 3, 5]), "evidence": _clock_evidence()},
        ),
    ],
    ids=[
        "an_unsigned_acceptance_that_names_an_issuer",
        "unsigned_with_the_budget_not_holding",
        "unsigned_with_synchronization_unresolved",
        "unsigned_with_its_own_evidence_unresolved",
    ],
)
def test_a_declared_unsigned_authority_and_time_is_refused_when_it_does_not_hold(
    acceptance: dict[str, JsonValue], changes: dict[str, object]
) -> None:
    """No issuer, both time checks holding and its own evidence resolved, or the pass is refused."""
    with pytest.raises(InputRefused) as caught:
        _verdict(acceptance, **cast(_Changes, changes))
    assert asdict(caught.value.reason) == {
        "code": "policy_unavailable",
        "subject_digest": ACCEPTANCE,
        "claim_id": None,
        "pointer": f"/checks/{CHECK_IDS.index(AUTHORITY)}/result",
        "detail": f"The declared Clock acceptance check {AUTHORITY} is contradicted by its evidence.",
    }


def test_a_check_without_a_rule_or_without_evidence_declared_pass_is_unavailable() -> None:
    """Missing evidence is not contradicted evidence: no refusal, the result is unavailable."""
    undecided = _verdict(
        _acceptance({AUTHORITY: "pass"}, custody_class="software_local_unprotected"),
        evidence=_clock_evidence(),
    )
    assert undecided.checks[AUTHORITY] == "unavailable"
    unbound = _verdict(_acceptance({AUTHORITY: "pass"}))
    assert unbound.checks[AUTHORITY] == "unavailable"
    uncalculated = _verdict(_acceptance(dict.fromkeys(COMPUTED, "pass")))
    assert {check: uncalculated.checks[check] for check in COMPUTED} == dict.fromkeys(
        COMPUTED, "unavailable"
    )


def test_a_repeated_evidence_reference_is_an_invalid_acceptance() -> None:
    """Evidence references are unique within a check."""
    acceptance = _acceptance({})
    checks = acceptance["checks"]
    assert isinstance(checks, list) and isinstance(checks[2], dict)
    checks[2]["evidence_refs"] = [_evidence(2), _evidence(2)]
    with pytest.raises(InputRefused) as caught:
        _verdict(acceptance)
    assert (caught.value.reason.code, caught.value.reason.pointer) == (
        "invalid_schema",
        "/checks/2/evidence_refs",
    )


def test_the_six_checks_must_each_be_declared_once() -> None:
    """A missing or repeated check id is an invalid acceptance."""
    acceptance = _acceptance({})
    checks = acceptance["checks"]
    assert isinstance(checks, list) and isinstance(checks[5], dict)
    checks[5]["check_id"] = "whole_source_match"
    with pytest.raises(InputRefused) as caught:
        _verdict(acceptance)
    assert (caught.value.reason.code, caught.value.reason.pointer) == ("invalid_schema", "/checks")


def test_without_a_calculation_there_is_no_clock_evidence() -> None:
    """A verification that did not reach the Clock calculation gives the budget nothing to read."""
    assert clock_evidence(None, cast(BoundClockSubject, None)) is None
