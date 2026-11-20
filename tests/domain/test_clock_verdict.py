# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the Clock acceptance verdict over its six checks

"""Recompute the relational Clock checks, keep what is declared below them, refuse a false pass.

Each case builds the documents and closure edges the verdict reads from a bound Clock subject:
the acceptance body with its six declared checks, the witness, the evaluation subject, and the
closure's observations and refusals. A declared ``pass`` must reproduce; a declared ``fail`` or
``unavailable`` stays; the three checks without a rule yet stay ``unavailable``.
"""

from dataclasses import asdict
from typing import TypedDict, cast

import pytest

from evidence_manifest_toolkit import InputRefused, Reason
from evidence_manifest_toolkit._clock_verdict import (
    CHECK_IDS,
    UNDECIDED,
    ClockVerdict,
    clock_verdict,
)
from evidence_manifest_toolkit._json import JsonValue
from evidence_manifest_toolkit._results import ReferenceObservation

ACCEPTANCE = "sha256:" + "a" * 64
CONTROLLER: dict[str, JsonValue] = {"name": "controller"}
OBSERVER: dict[str, JsonValue] = {"name": "observer"}


def _evidence(index: int) -> dict[str, JsonValue]:
    """Return a distinct evidence reference for one check."""
    return {"evidence": index}


def _acceptance(results: dict[str, str]) -> dict[str, JsonValue]:
    """Return an acceptance body declaring the given results, ``unavailable`` elsewhere."""
    return {
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


def _verdict(
    acceptance: dict[str, JsonValue],
    *,
    witness: dict[str, JsonValue] | None = None,
    subject: dict[str, JsonValue] | None = None,
    observations: tuple[ReferenceObservation, ...] | None = None,
    closure_reasons: tuple[Reason, ...] = (),
    missing: int = 0,
    source_reasons: tuple[Reason, ...] = (),
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
    )


class _Changes(TypedDict, total=False):
    """The verdict inputs one contradiction case replaces."""

    witness: dict[str, JsonValue]
    subject: dict[str, JsonValue]
    observations: tuple[ReferenceObservation, ...]
    closure_reasons: tuple[Reason, ...]
    missing: int
    source_reasons: tuple[Reason, ...]


RELATIONAL = ("whole_source_match", "controller_source_match", "acyclic_whole_target")
CYCLE = Reason("cycle_detected", ACCEPTANCE, None, None, "Reference cycle.")


def test_the_verdict_keeps_six_slots_in_order_and_the_undecided_three_unavailable() -> None:
    """Each relational pass reproduces; the three checks without a rule stay unavailable."""
    verdict = _verdict(_acceptance({check: "pass" for check in CHECK_IDS}))
    assert tuple(verdict.checks) == CHECK_IDS
    assert {check: verdict.checks[check] for check in RELATIONAL} == dict.fromkeys(
        RELATIONAL, "pass"
    )
    assert {check: verdict.checks[check] for check in UNDECIDED} == dict.fromkeys(
        UNDECIDED, "unavailable"
    )
    assert verdict.accepted is False


def test_a_declared_fail_or_unavailable_is_kept_even_when_it_would_pass() -> None:
    """A source may report less than can be shown, never more."""
    verdict = _verdict(_acceptance({"whole_source_match": "fail"}))
    assert verdict.checks["whole_source_match"] == "fail"
    assert verdict.checks["controller_source_match"] == "unavailable"


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
    ],
    ids=[
        "whole_source_with_source_refusal",
        "whole_source_with_unresolved_evidence",
        "controller_with_other_observer",
        "controller_with_other_witness_controller",
        "controller_with_other_subject_controller",
        "acyclic_with_closure_refusal",
        "acyclic_with_missing_reference",
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


def test_an_undecided_check_declared_pass_is_unavailable_not_refused() -> None:
    """A check without a rule is missing evidence, not contradicted evidence."""
    verdict = _verdict(_acceptance({"synchronization_and_mapping": "pass"}))
    assert verdict.checks["synchronization_and_mapping"] == "unavailable"


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
