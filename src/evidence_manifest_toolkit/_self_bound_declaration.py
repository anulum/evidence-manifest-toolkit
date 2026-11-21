# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the launcher's declaration of a self-bound unsigned verification

"""Decode what an unsigned launcher declares once, before any child captures anything.

A self-bound launch builds the whole unsigned V2 request inside the process that verifies it.
The launcher cannot know the records the child will capture, so it declares only what is its
own: the policy's rules, the claims and purposes, and every number and rule reference that an
``unsigned_declared`` caller states about its Clock, with the six acceptance check results.
A check's evidence names either a static object of the store by its reference or one of the
closed :data:`EVIDENCE_ROLES`, which the launch resolves to a record it stored before the
acceptance body. Every field is closed; anything else is refused at its pointer.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction
from types import MappingProxyType

from ._codecs import decode_reference
from ._errors import InputRefused
from ._json import JsonValue
from ._reference_paths import configuration_refusal
from ._values import BlobRef, Utc

DECLARATION_SCHEMA_ID = "evidence_manifest_toolkit.self_bound_declaration.v1"
"""The schema identifier every declaration names."""

EVIDENCE_ROLES = (
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
"""The records a declared check may name as evidence: those stored before the acceptance body.

The first sample, the subject, the second NTP reply, the later samples and the witness are
stored after the acceptance body, and the witness names that body; none of them can be its
evidence without a cycle or a forward reference.
"""

POLICY_REFERENCE_FIELDS = (
    "identity_rule_ref",
    "validation_rule_ref",
    "whole_conditions_and_limitations_ref",
    "signature_obligation_rule_ref",
)
POLICY_OPTIONAL_REFERENCE_FIELDS = ("foreign_rule_ref", "independent_foreign_trust_ref")
CLOCK_RULE_FIELDS = (
    "accepted_ntp_configuration_ref",
    "acquisition_rule_ref",
    "monotonic_mapping_rule_ref",
    "independence_rule_ref",
    "daemon_field_mapping_rule_ref",
    "ntp_resolution_and_rotation_rule_ref",
    "automatic_reacceptance_rule_ref",
    "sample_mapping_and_quantization_rule_ref",
    "rate_source_ref",
    "calibration_source_ref",
    "adjustment_rule_ref",
    "rule_implementation_ref",
    "complete_authorization_obligations_ref",
    "assumptions_and_limitations_ref",
    "term_source_ref",
)
SAMPLE_BOUND_FIELDS = (
    "accuracy_radius_ns",
    "mapping_ns",
    "quantization_ns",
    "source_encoding_ns",
    "post_exchange_adjustment_ns",
    "use_adjustment_ns",
)
ENTRY_BOUND_FIELDS = ("acquisition_ns", "mapping_ns", "quantization_ns", "adjustment_ns")
CHECK_RESULTS = ("pass", "fail", "unavailable")

_INTEGER = re.compile(r"0|[1-9][0-9]*")


@dataclass(frozen=True, slots=True)
class EvidenceSelection:
    """One evidence item of a declared check: a store object or a role the launch resolves.

    Attributes
    ----------
    role : str or None
        One of :data:`EVIDENCE_ROLES`, or ``None`` for a static object.
    reference : BlobRef or None
        The static object, or ``None`` for a role.
    """

    role: str | None
    reference: BlobRef | None


@dataclass(frozen=True, slots=True)
class DeclaredCheck:
    """One of the six acceptance checks as the launcher declares it.

    Attributes
    ----------
    check_id : str
        The check's identifier; the Clock verdict requires each of the six once.
    result : str
        ``pass``, ``fail`` or ``unavailable``, kept exactly as declared.
    evidence : tuple of EvidenceSelection
        The check's evidence, in declared order.
    """

    check_id: str
    result: str
    evidence: tuple[EvidenceSelection, ...]


@dataclass(frozen=True, slots=True)
class SelfBoundDeclaration:
    """The whole decoded declaration of one unsigned launcher.

    Attributes
    ----------
    required_claim_ids, required_purposes : tuple of str
        The verification policy's scope.
    base_policy_ref : BlobRef
        The local policy body whose Clock qualification the launch fills.
    policy_references : Mapping of str to BlobRef or None
        The V2 policy's rule references; the two optional foreign ones may be ``None``.
    minimum_identity_class : str
        The V2 policy's minimum identity class.
    allowed_nonuse_classes : tuple of str
        The V2 policy's allowed non-use classes.
    time_source : str
        The Clock profile's declared time source.
    drift_rate : Fraction
        The declared maximum drift rate, in nanoseconds per elapsed nanosecond.
    maximum_uncertainty_ns : int
        The profile's maximum uncertainty.
    model_valid_from, model_valid_until : Utc
        The validity window of the declared Clock models.
    sample_bounds, entry_bounds : Mapping of str to int
        The declared per-sample and verify-entry bounds, in nanoseconds.
    rule_references : Mapping of str to BlobRef
        The Clock records' declared rule and source references.
    provenance_refs : tuple of BlobRef
        The Clock models' declared provenance.
    checks : tuple of DeclaredCheck
        The six declared acceptance checks.
    """

    required_claim_ids: tuple[str, ...]
    required_purposes: tuple[str, ...]
    base_policy_ref: BlobRef
    policy_references: Mapping[str, BlobRef | None]
    minimum_identity_class: str
    allowed_nonuse_classes: tuple[str, ...]
    time_source: str
    drift_rate: Fraction
    maximum_uncertainty_ns: int
    model_valid_from: Utc
    model_valid_until: Utc
    sample_bounds: Mapping[str, int]
    entry_bounds: Mapping[str, int]
    rule_references: Mapping[str, BlobRef]
    provenance_refs: tuple[BlobRef, ...]
    checks: tuple[DeclaredCheck, ...]


def _object(value: JsonValue, fields: tuple[str, ...], pointer: str) -> dict[str, JsonValue]:
    """Require an object with exactly the named fields.

    Parameters
    ----------
    value : object
        The decoded JSON value.
    fields : tuple of str
        Its complete field population.
    pointer : str
        Its position in the declaration.

    Returns
    -------
    dict
        The value itself.

    Raises
    ------
    ConfigurationError
        It is not an object, or a field is missing or unknown.
    """
    if not isinstance(value, dict) or value.keys() != set(fields):
        raise configuration_refusal(pointer)
    return value


def _string(value: JsonValue, pointer: str) -> str:
    """Require a non-empty string.

    Parameters
    ----------
    value : object
        The decoded JSON value.
    pointer : str
        Its position in the declaration.

    Returns
    -------
    str
        The value itself.

    Raises
    ------
    ConfigurationError
        It is not a non-empty string.
    """
    if not isinstance(value, str) or not value:
        raise configuration_refusal(pointer)
    return value


def _strings(value: JsonValue, pointer: str) -> tuple[str, ...]:
    """Require an array of non-empty strings.

    Parameters
    ----------
    value : object
        The decoded JSON value.
    pointer : str
        Its position in the declaration.

    Returns
    -------
    tuple of str
        The strings in order.

    Raises
    ------
    ConfigurationError
        It is not an array, or an item is not a non-empty string.
    """
    if not isinstance(value, list):
        raise configuration_refusal(pointer)
    return tuple(_string(item, f"{pointer}/{index}") for index, item in enumerate(value))


def _integer(value: JsonValue, pointer: str, *, positive: bool = False) -> int:
    """Require a decimal integer string without sign or leading zero.

    Parameters
    ----------
    value : object
        The decoded JSON value.
    pointer : str
        Its position in the declaration.
    positive : bool
        Whether zero is refused too.

    Returns
    -------
    int
        The integer.

    Raises
    ------
    ConfigurationError
        It is not such a string, or it is zero where a positive value is required.
    """
    if not isinstance(value, str) or _INTEGER.fullmatch(value) is None:
        raise configuration_refusal(pointer)
    number = int(value)
    if positive and number == 0:
        raise configuration_refusal(pointer)
    return number


def _reference(value: JsonValue, pointer: str) -> BlobRef:
    """Decode one whole reference, mapping a malformed one to a configuration refusal.

    Parameters
    ----------
    value : object
        The decoded JSON value.
    pointer : str
        Its position in the declaration.

    Returns
    -------
    BlobRef
        The reference.

    Raises
    ------
    ConfigurationError
        It is not a valid reference.
    """
    try:
        return decode_reference(value, subject=None, pointer=pointer)
    except InputRefused:
        raise configuration_refusal(pointer) from None


def _utc(value: JsonValue, pointer: str) -> Utc:
    """Decode one UTC lexeme.

    Parameters
    ----------
    value : object
        The decoded JSON value.
    pointer : str
        Its position in the declaration.

    Returns
    -------
    Utc
        The instant.

    Raises
    ------
    ConfigurationError
        It is not a valid UTC lexeme.
    """
    try:
        return Utc(_string(value, pointer))
    except InputRefused:
        raise configuration_refusal(pointer) from None


def _bounds(value: JsonValue, fields: tuple[str, ...], pointer: str) -> Mapping[str, int]:
    """Decode one closed object of nanosecond bounds.

    Parameters
    ----------
    value : object
        The decoded JSON value.
    fields : tuple of str
        The bound names.
    pointer : str
        Its position in the declaration.

    Returns
    -------
    Mapping of str to int
        Each bound, read only.

    Raises
    ------
    ConfigurationError
        The object or one of its integers is invalid.
    """
    members = _object(value, fields, pointer)
    return MappingProxyType({name: _integer(members[name], f"{pointer}/{name}") for name in fields})


def _evidence(value: JsonValue, pointer: str) -> EvidenceSelection:
    """Decode one evidence item: exactly a role or a reference.

    Parameters
    ----------
    value : object
        The decoded JSON value.
    pointer : str
        Its position in the declaration.

    Returns
    -------
    EvidenceSelection
        The selection.

    Raises
    ------
    ConfigurationError
        It names neither or both, or an unknown role.
    """
    if isinstance(value, dict) and value.keys() == {"role"}:
        role = _string(value["role"], pointer + "/role")
        if role not in EVIDENCE_ROLES:
            raise configuration_refusal(pointer + "/role")
        return EvidenceSelection(role, None)
    members = _object(value, ("ref",), pointer)
    return EvidenceSelection(None, _reference(members["ref"], pointer + "/ref"))


def _check(value: JsonValue, pointer: str) -> DeclaredCheck:
    """Decode one declared acceptance check.

    Parameters
    ----------
    value : object
        The decoded JSON value.
    pointer : str
        Its position in the declaration.

    Returns
    -------
    DeclaredCheck
        The check.

    Raises
    ------
    ConfigurationError
        Its shape, result or evidence is invalid.
    """
    members = _object(value, ("check_id", "result", "evidence"), pointer)
    result = _string(members["result"], pointer + "/result")
    if result not in CHECK_RESULTS:
        raise configuration_refusal(pointer + "/result")
    evidence = members["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise configuration_refusal(pointer + "/evidence")
    return DeclaredCheck(
        _string(members["check_id"], pointer + "/check_id"),
        result,
        tuple(
            _evidence(item, f"{pointer}/evidence/{index}") for index, item in enumerate(evidence)
        ),
    )


def decode_declaration(value: JsonValue) -> SelfBoundDeclaration:
    """Decode a whole self-bound launch declaration.

    Parameters
    ----------
    value : object
        The strictly acquired declaration document.

    Returns
    -------
    SelfBoundDeclaration
        The decoded declaration.

    Raises
    ------
    ConfigurationError
        A field is missing, unknown or invalid, at ``/declaration`` and below.
    """
    root = _object(
        value,
        (
            "schema_id",
            "required_claim_ids",
            "required_purposes",
            "base_policy_ref",
            "policy_rules",
            "clock",
        ),
        "/declaration",
    )
    if root["schema_id"] != DECLARATION_SCHEMA_ID:
        raise configuration_refusal("/declaration/schema_id")
    rules = _object(
        root["policy_rules"],
        (
            *POLICY_REFERENCE_FIELDS,
            *POLICY_OPTIONAL_REFERENCE_FIELDS,
            "minimum_identity_class",
            "allowed_nonuse_classes",
        ),
        "/declaration/policy_rules",
    )
    references: dict[str, BlobRef | None] = {
        name: _reference(rules[name], "/declaration/policy_rules/" + name)
        for name in POLICY_REFERENCE_FIELDS
    }
    for name in POLICY_OPTIONAL_REFERENCE_FIELDS:
        member = rules[name]
        references[name] = (
            None if member is None else _reference(member, "/declaration/policy_rules/" + name)
        )
    clock = _object(
        root["clock"],
        (
            "time_source",
            "drift_rate",
            "maximum_uncertainty_ns",
            "model_valid_from",
            "model_valid_until",
            "sample_bounds",
            "entry_bounds",
            "rule_refs",
            "provenance_refs",
            "checks",
        ),
        "/declaration/clock",
    )
    rate = _object(
        clock["drift_rate"], ("numerator", "denominator"), "/declaration/clock/drift_rate"
    )
    declared_rules = _object(clock["rule_refs"], CLOCK_RULE_FIELDS, "/declaration/clock/rule_refs")
    provenance = clock["provenance_refs"]
    if not isinstance(provenance, list) or not provenance:
        raise configuration_refusal("/declaration/clock/provenance_refs")
    checks = clock["checks"]
    if not isinstance(checks, list):
        raise configuration_refusal("/declaration/clock/checks")
    return SelfBoundDeclaration(
        _strings(root["required_claim_ids"], "/declaration/required_claim_ids"),
        _strings(root["required_purposes"], "/declaration/required_purposes"),
        _reference(root["base_policy_ref"], "/declaration/base_policy_ref"),
        MappingProxyType(references),
        _string(
            rules["minimum_identity_class"], "/declaration/policy_rules/minimum_identity_class"
        ),
        _strings(
            rules["allowed_nonuse_classes"], "/declaration/policy_rules/allowed_nonuse_classes"
        ),
        _string(clock["time_source"], "/declaration/clock/time_source"),
        Fraction(
            _integer(rate["numerator"], "/declaration/clock/drift_rate/numerator", positive=True),
            _integer(
                rate["denominator"], "/declaration/clock/drift_rate/denominator", positive=True
            ),
        ),
        _integer(
            clock["maximum_uncertainty_ns"],
            "/declaration/clock/maximum_uncertainty_ns",
            positive=True,
        ),
        _utc(clock["model_valid_from"], "/declaration/clock/model_valid_from"),
        _utc(clock["model_valid_until"], "/declaration/clock/model_valid_until"),
        _bounds(clock["sample_bounds"], SAMPLE_BOUND_FIELDS, "/declaration/clock/sample_bounds"),
        _bounds(clock["entry_bounds"], ENTRY_BOUND_FIELDS, "/declaration/clock/entry_bounds"),
        MappingProxyType(
            {
                name: _reference(declared_rules[name], "/declaration/clock/rule_refs/" + name)
                for name in CLOCK_RULE_FIELDS
            }
        ),
        tuple(
            _reference(item, f"/declaration/clock/provenance_refs/{index}")
            for index, item in enumerate(provenance)
        ),
        tuple(
            _check(item, f"/declaration/clock/checks/{index}") for index, item in enumerate(checks)
        ),
    )
