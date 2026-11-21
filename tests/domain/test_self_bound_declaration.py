# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — every field of a self-bound declaration is closed

"""Check that the declaration decoder accepts the whole form and refuses each fault at its pointer."""

import copy
from collections.abc import Callable
from fractions import Fraction
from typing import cast

import pytest
from tests.domain.self_bound_inputs import declaration_value

from evidence_manifest_toolkit import BlobRef, ConfigurationError
from evidence_manifest_toolkit._clock_verdict import CHECK_IDS
from evidence_manifest_toolkit._json import JsonValue
from evidence_manifest_toolkit._self_bound_declaration import (
    EVIDENCE_ROLES,
    decode_declaration,
)

_REF = BlobRef("sha256:" + "a" * 64, "2", "application/json", "raw_bytes")
_OTHER = {**dict(_REF.to_mapping()), "digest": "sha256:" + "b" * 64}

type Change = Callable[[dict[str, object]], None]


def _valid() -> dict[str, object]:
    """Return one whole valid declaration."""
    return declaration_value(
        rate=Fraction(15, 1_000_000),
        base_ref=_REF,
        launcher_ref=_REF,
        rule_fields={
            "identity_rule_ref": dict(_REF.to_mapping()),
            "validation_rule_ref": dict(_REF.to_mapping()),
            "foreign_rule_ref": None,
            "independent_foreign_trust_ref": None,
        },
        signature_ref=_REF,
        claim_ids=["claim-a"],
        purposes=["evidence"],
        declared_checks={"whole_source_match": "pass"},
        evidence={"acyclic_whole_target": [{"role": "profile"}, {"ref": _OTHER}]},
        sample_bounds={},
    )


def _clock(value: dict[str, object]) -> dict[str, object]:
    """Return the declaration's clock object."""
    return cast(dict[str, object], value["clock"])


def _first_check(value: dict[str, object]) -> dict[str, object]:
    """Return the first declared check."""
    return cast(list[dict[str, object]], _clock(value)["checks"])[0]


def test_a_whole_declaration_decodes_with_roles_and_references() -> None:
    """Every field is kept; roles and static references stay apart."""
    declaration = decode_declaration(cast(JsonValue, _valid()))
    assert declaration.drift_rate == Fraction(15, 1_000_000)
    assert declaration.policy_references["foreign_rule_ref"] is None
    assert [check.check_id for check in declaration.checks] == list(CHECK_IDS)
    last = declaration.checks[CHECK_IDS.index("acyclic_whole_target")].evidence
    assert [(item.role, item.reference) for item in last] == [
        ("profile", None),
        (None, BlobRef.from_mapping(_OTHER)),
    ]
    assert declaration.sample_bounds["accuracy_radius_ns"] == 1_000_000_000


def test_a_declared_foreign_rule_is_kept() -> None:
    """The two foreign references may be references as well as null."""
    value = _valid()
    cast(dict[str, object], value["policy_rules"])["foreign_rule_ref"] = _OTHER
    declaration = decode_declaration(cast(JsonValue, value))
    assert declaration.policy_references["foreign_rule_ref"] == BlobRef.from_mapping(_OTHER)


def test_the_role_vocabulary_is_closed_and_ordered() -> None:
    """The roles are exactly the records stored before the acceptance body, in that order."""
    assert EVIDENCE_ROLES == (
        "environment",
        "boot_domain",
        "process_start",
        "entry_method",
        "identity_declaration",
        "annual_before_raw_sample",
        "annual_ntp_reply",
        "annual_after_raw_sample",
        "drift_method",
        "annual_derivation",
        "uncertainty_method",
        "profile",
    )


def _set(path: tuple[str | int, ...], member: object) -> Change:
    """Return a change that replaces the value at ``path``."""

    def change(value: dict[str, object]) -> None:
        """Replace one member."""
        target: object = value
        for step in path[:-1]:
            target = (
                cast(dict[str, object], target)[step]
                if isinstance(step, str)
                else cast(list[object], target)[step]
            )
        if isinstance(path[-1], str):
            cast(dict[str, object], target)[path[-1]] = member
        else:
            cast(list[object], target)[path[-1]] = member

    return change


def _drop(path: tuple[str, ...]) -> Change:
    """Return a change that removes the member at ``path``."""

    def change(value: dict[str, object]) -> None:
        """Remove one member."""
        target: object = value
        for step in path[:-1]:
            target = cast(dict[str, object], target)[step]
        del cast(dict[str, object], target)[path[-1]]

    return change


@pytest.mark.parametrize(
    ("change", "pointer"),
    (
        (_set(("unexpected",), True), "/declaration"),
        (
            _set(("schema_id",), "evidence_manifest_toolkit.self_bound_declaration.v2"),
            "/declaration/schema_id",
        ),
        (_set(("required_claim_ids",), "claim-a"), "/declaration/required_claim_ids"),
        (_set(("required_purposes",), [""]), "/declaration/required_purposes/0"),
        (_set(("base_policy_ref",), {"digest": "x"}), "/declaration/base_policy_ref"),
        (_drop(("policy_rules", "identity_rule_ref")), "/declaration/policy_rules"),
        (
            _set(("policy_rules", "validation_rule_ref"), None),
            "/declaration/policy_rules/validation_rule_ref",
        ),
        (
            _set(("policy_rules", "foreign_rule_ref"), {"digest": "x"}),
            "/declaration/policy_rules/foreign_rule_ref",
        ),
        (
            _set(("policy_rules", "minimum_identity_class"), 1),
            "/declaration/policy_rules/minimum_identity_class",
        ),
        (
            _set(("policy_rules", "allowed_nonuse_classes"), [1]),
            "/declaration/policy_rules/allowed_nonuse_classes/0",
        ),
        (_drop(("clock", "checks")), "/declaration/clock"),
        (_set(("clock", "time_source"), ""), "/declaration/clock/time_source"),
        (_set(("clock", "drift_rate"), {"numerator": "1"}), "/declaration/clock/drift_rate"),
        (
            _set(("clock", "drift_rate", "numerator"), "0"),
            "/declaration/clock/drift_rate/numerator",
        ),
        (
            _set(("clock", "drift_rate", "denominator"), "01"),
            "/declaration/clock/drift_rate/denominator",
        ),
        (
            _set(("clock", "drift_rate", "denominator"), 7),
            "/declaration/clock/drift_rate/denominator",
        ),
        (
            _set(("clock", "maximum_uncertainty_ns"), "0"),
            "/declaration/clock/maximum_uncertainty_ns",
        ),
        (_set(("clock", "model_valid_from"), "2020-01-01"), "/declaration/clock/model_valid_from"),
        (_set(("clock", "model_valid_until"), 2030), "/declaration/clock/model_valid_until"),
        (_drop(("clock", "sample_bounds", "mapping_ns")), "/declaration/clock/sample_bounds"),
        (
            _set(("clock", "sample_bounds", "mapping_ns"), "-1"),
            "/declaration/clock/sample_bounds/mapping_ns",
        ),
        (
            _set(("clock", "entry_bounds", "acquisition_ns"), "1.5"),
            "/declaration/clock/entry_bounds/acquisition_ns",
        ),
        (_drop(("clock", "rule_refs", "term_source_ref")), "/declaration/clock/rule_refs"),
        (
            _set(("clock", "rule_refs", "term_source_ref"), "sha256:"),
            "/declaration/clock/rule_refs/term_source_ref",
        ),
        (_set(("clock", "provenance_refs"), []), "/declaration/clock/provenance_refs"),
        (
            _set(("clock", "provenance_refs"), [{"digest": "x"}]),
            "/declaration/clock/provenance_refs/0",
        ),
        (_set(("clock", "checks"), {}), "/declaration/clock/checks"),
        (_set(("clock", "checks", 0), []), "/declaration/clock/checks/0"),
        (_set(("clock", "checks", 0, "check_id"), ""), "/declaration/clock/checks/0/check_id"),
        (_set(("clock", "checks", 0, "result"), "maybe"), "/declaration/clock/checks/0/result"),
        (_set(("clock", "checks", 0, "evidence"), []), "/declaration/clock/checks/0/evidence"),
        (
            _set(("clock", "checks", 0, "evidence", 0), {"role": "witness"}),
            "/declaration/clock/checks/0/evidence/0/role",
        ),
        (
            _set(("clock", "checks", 0, "evidence", 0), {"role": 3}),
            "/declaration/clock/checks/0/evidence/0/role",
        ),
        (
            _set(("clock", "checks", 0, "evidence", 0), {"role": "profile", "ref": _OTHER}),
            "/declaration/clock/checks/0/evidence/0",
        ),
        (
            _set(("clock", "checks", 0, "evidence", 0), {"ref": {"digest": "x"}}),
            "/declaration/clock/checks/0/evidence/0/ref",
        ),
    ),
)
def test_each_fault_is_refused_at_its_pointer(change: Change, pointer: str) -> None:
    """One faulty member is refused as invalid local configuration at its own position."""
    value = copy.deepcopy(_valid())
    change(value)
    with pytest.raises(ConfigurationError) as caught:
        decode_declaration(cast(JsonValue, value))
    assert (caught.value.reason.code, caught.value.reason.pointer) == (
        "configuration_error",
        pointer,
    )


def test_a_declaration_that_is_not_an_object_is_refused() -> None:
    """The whole document must be an object."""
    with pytest.raises(ConfigurationError) as caught:
        decode_declaration([])
    assert caught.value.reason.pointer == "/declaration"
    assert _first_check(_valid())["result"] == "pass"
