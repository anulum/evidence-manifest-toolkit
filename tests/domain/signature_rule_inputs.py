# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit unqualified signature-rule source cases

"""Prepare complete raw method inputs for actual public verification, without qualifying time."""

import json
from dataclasses import replace
from pathlib import Path

from tests.domain.signature_obligation_inputs import obligation_rule
from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _array, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, reference_bytes

SIGNATURE_RULE_CASES = (
    "sig_exception",
    "sig_method",
    "sig_shape",
    "sig_object",
    "sig_class",
    "sig_renewal",
    "sig_purpose_shape",
    "sig_purpose_member",
    "sig_purpose_duplicate",
    "sig_control_purpose",
    "sig_from_type",
    "sig_until_type",
    "sig_from_invalid",
    "sig_reversed",
    "sig_class_join",
    "sig_claim_join",
    "sig_purpose_join",
    "sig_paths_join",
    "sig_conditions_join",
    "sig_base_clock",
    "sig_base_other",
    "sig_missing",
    "sig_malformed",
    "sig_raw_metadata",
    "sig_provenance_empty",
    "sig_provenance_type",
    "sig_provenance_duplicate",
    "sig_provenance_missing",
    "sig_exception_shape",
    "sig_exception_object",
    "sig_exception_claim_shape",
    "sig_exception_claim_member",
    "sig_exception_claim_empty",
    "sig_exception_claim_duplicate",
    "sig_exception_claim_unknown",
    "sig_exception_content",
    "sig_exception_purpose_unknown",
    "sig_exception_record_shape",
    "sig_exception_record_duplicate",
    "sig_exception_record_unknown",
    "software_signature_exception",
    "cli_sig_method",
    "cli_sig_missing",
    "cli_sig_claim_join",
    "cli_sig_exception",
    "sig_base_jcs",
    "sig_provenance_jcs",
    "sig_rule_basis",
    "sig_rule_schema",
    "sig_exception_empty",
    "sig_base_alias",
    "sig_base_basis_mismatch",
)


def signature_rule_input(
    condition: str,
    directory: Path,
    *,
    base_ref: BlobRef,
    conditions_ref: BlobRef,
    content_ref: BlobRef,
    content_raw: bytes,
    required_claim_ids: list[str],
    required_purposes: list[str],
    profile_class: str,
    limits: Limits,
) -> tuple[BlobRef, str, dict[str, object] | None]:
    """Retain a whole independently selected method and a deliberate single source fault.

    Parameters
    ----------
    condition : str
        Named whole source/scope fault, or an original unchanged Clock/receipt case.
    directory : Path
        Owned immutable source-input directory.
    base_ref, conditions_ref : BlobRef
        Actual earlier complete base and selected conditions, without native qualification.
    content_ref : BlobRef
        Actual complete content identity from the public reference operation.
    content_raw : bytes
        Whole original content for declared claim/reference population extraction.
    required_claim_ids, required_purposes : list of str
        Entire independently selected policy populations.
    profile_class : str
        Explicit independently paired caller class, never inferred from missing receipts.
    limits : Limits
        Whole actual caller limits for public canonical-reference construction.

    Returns
    -------
    tuple
        Full raw rule reference, expected failure kind and full expected diagnostic override.
        An accepted grammar still reaches the pending V2 state refusal; no source errors,
        empty exception, declared window or provenance label qualifies a Clock or waiver.
    """
    condition = condition.removeprefix("cli_")
    claims = [_object(item) for item in _array(_object(json.loads(content_raw)).get("claims", []))]
    identifiers = [_text(item["claim_id"]) for item in claims]
    validations = [_object(item["validation"]) for item in claims]
    records = [
        _object(item["record_ref"]) for item in validations if item.get("record_ref") is not None
    ]
    exception: dict[str, object] = {
        "content_ref": dict(content_ref.to_mapping()),
        "claim_ids": identifiers,
        "purposes": required_purposes,
        "validation_record_refs": records,
    }
    value: dict[str, object] = {
        "method_id": "emt_signature_obligations_v1",
        "profile_class": profile_class,
        "whole_base_policy_ref": dict(base_ref.to_mapping()),
        "whole_conditions_and_limitations_ref": dict(conditions_ref.to_mapping()),
        "required_claim_ids": required_claim_ids,
        "required_purposes": required_purposes,
        "required_reference_paths": [],
        "unsigned_exception": None,
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z",
        "renewal_rule": "fresh_independent_rule_before_expiry_no_implicit_extension",
        "provenance_refs": [dict(base_ref.to_mapping())],
    }
    change: dict[str, tuple[str, object]] = {
        "sig_method": ("method_id", "uninstalled_method"),
        "sig_class": ("profile_class", "unknown_class"),
        "sig_renewal": ("renewal_rule", "extend_without_fresh_sources"),
        "sig_purpose_shape": ("required_purposes", "evidence"),
        "sig_purpose_member": ("required_purposes", [False]),
        "sig_purpose_duplicate": ("required_purposes", ["evidence", "evidence"]),
        "sig_control_purpose": ("required_purposes", ["trust_snapshot"]),
        "sig_from_type": ("valid_from", None),
        "sig_until_type": ("valid_until", 0),
        "sig_from_invalid": ("valid_from", "unqualified timestamp"),
        "sig_reversed": ("valid_until", "2020-01-01T00:00:00Z"),
        "sig_class_join": ("profile_class", "software_local_unprotected"),
        "sig_claim_join": ("required_claim_ids", []),
        "sig_purpose_join": ("required_purposes", ["deployment"]),
        "sig_paths_join": ("required_reference_paths", [{"path_id": "absent"}]),
        "sig_conditions_join": (
            "whole_conditions_and_limitations_ref",
            dict(base_ref.to_mapping()),
        ),
        "sig_provenance_empty": ("provenance_refs", []),
        "sig_provenance_type": ("provenance_refs", {}),
        "sig_provenance_duplicate": ("provenance_refs", [dict(base_ref.to_mapping())] * 2),
    }
    pointer = ""
    kind = "configuration"
    if condition in change:
        field, changed = change[condition]
        value[field] = changed
        pointer = "/" + field
    if condition == "sig_shape":
        value["unexpected"] = False
    if condition in {"sig_base_jcs", "sig_provenance_jcs", "sig_base_basis_mismatch"}:
        canonical_ref = reference_bytes(
            (directory / base_ref.digest[7:]).read_bytes(),
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id=None,
            limits=limits,
        )
        (directory / canonical_ref.digest[7:]).write_bytes(
            (directory / base_ref.digest[7:]).read_bytes()
        )
        value[
            "provenance_refs" if condition == "sig_provenance_jcs" else "whole_base_policy_ref"
        ] = (
            dict(canonical_ref.to_mapping())
            if condition != "sig_provenance_jcs"
            else [dict(canonical_ref.to_mapping())]
        )
    if condition == "sig_base_alias":
        base = json.loads((directory / base_ref.digest[7:]).read_bytes())
        alias = _native_source(json.dumps(base, indent=2).encode(), directory, "application/json")
        assert alias != base_ref
        value["whole_base_policy_ref"] = dict(alias.to_mapping())
    if condition in {"sig_base_alias", "sig_base_basis_mismatch"}:
        pointer = "/whole_base_policy_ref"
    if condition in {"sig_base_clock", "sig_base_other"}:
        base = _object(json.loads((directory / base_ref.digest[7:]).read_bytes()))
        if condition == "sig_base_clock":
            base["required_evaluation_time_qualification"] = {
                **_object(base["required_evaluation_time_qualification"]),
                "clock_qualification_ref": dict(conditions_ref.to_mapping()),
            }
        else:
            base["required_principal"] = "another-explicit-principal"
        changed_base = _stored(base, directory)
        value["whole_base_policy_ref"] = dict(changed_base.to_mapping())
        pointer = "/whole_base_policy_ref"
    if condition == "sig_provenance_missing":
        missing = _stored({"unavailable": "selected provenance input"}, directory)
        value["provenance_refs"] = [dict(missing.to_mapping())]
        (directory / missing.digest[7:]).unlink()
    if condition.startswith("sig_exception") or condition == "software_signature_exception":
        value["unsigned_exception"] = exception
        pointer = "/unsigned_exception"
        if condition == "sig_exception_shape":
            exception["unexpected"] = False
        if condition == "sig_exception_object":
            value["unsigned_exception"] = []
        if condition == "sig_exception_empty":
            exception.update(claim_ids=[], purposes=[], validation_record_refs=[])
        scoped_changes: dict[str, tuple[str, object]] = {
            "sig_exception_claim_shape": ("claim_ids", None),
            "sig_exception_claim_member": ("claim_ids", [True]),
            "sig_exception_claim_empty": ("claim_ids", [""]),
            "sig_exception_claim_duplicate": ("claim_ids", identifiers * 2),
            "sig_exception_claim_unknown": ("claim_ids", ["absent-whole-claim"]),
            "sig_exception_content": ("content_ref", dict(base_ref.to_mapping())),
            "sig_exception_purpose_unknown": ("purposes", ["deployment"]),
            "sig_exception_record_shape": ("validation_record_refs", None),
            "sig_exception_record_duplicate": (
                "validation_record_refs",
                [dict(base_ref.to_mapping())] * 2,
            ),
            "sig_exception_record_unknown": (
                "validation_record_refs",
                [dict(base_ref.to_mapping())],
            ),
        }
        if condition in scoped_changes:
            field, changed = scoped_changes[condition]
            exception[field] = changed
            pointer += "/" + field
    if condition.startswith(("obligation_", "reproduction_")) and (
        condition != "obligation_missing_required_claim"
    ):
        value["unsigned_exception"] = exception
    value = obligation_rule(condition, value)
    raw = json.dumps([] if condition == "sig_object" else value, separators=(",", ":")).encode()
    if condition == "sig_malformed":
        raw = b"{"
    reference = _native_source(
        raw, directory, "text/plain" if condition == "sig_raw_metadata" else "application/json"
    )
    if condition == "sig_rule_basis":
        reference = replace(reference, digest_basis="jcs_content")
    if condition == "sig_rule_schema":
        reference = replace(reference, schema_id="evidence_manifest_toolkit.manifest.v1")
    if condition == "sig_missing":
        (directory / reference.digest[7:]).unlink()
    if condition in {"sig_missing", "sig_provenance_missing"}:
        return (
            reference,
            "unavailable",
            {
                "code": "reference_unavailable",
                "subject_digest": None,
                "claim_id": None,
                "pointer": None,
                "detail": "Required reference unavailable.",
            },
        )
    if (
        not condition.startswith("sig_")
        and condition != "software_signature_exception"
        or condition
        in {"sig_exception", "sig_exception_empty", "sig_base_jcs", "sig_provenance_jcs"}
    ):
        return reference, "pending", None
    expected: dict[str, object] = {
        "code": "configuration_error",
        "subject_digest": reference.digest,
        "claim_id": None,
        "pointer": pointer,
        "detail": "Invalid signature-obligation rule.",
    }
    conflicts = {
        "sig_class_join",
        "sig_claim_join",
        "sig_purpose_join",
        "sig_paths_join",
        "sig_conditions_join",
        "sig_base_clock",
        "sig_base_other",
        "sig_base_alias",
        "sig_base_basis_mismatch",
        "sig_exception_claim_unknown",
        "sig_exception_content",
        "sig_exception_purpose_unknown",
        "sig_exception_record_unknown",
        "software_signature_exception",
    }
    if condition in conflicts:
        kind = "input"
        expected.update(
            code="policy_unavailable",
            subject_digest=reference.digest,
            pointer=(
                "/unsigned_exception"
                if condition.startswith("sig_exception")
                or condition == "software_signature_exception"
                else pointer
            ),
            detail="Signature-obligation sources conflict.",
        )
    if condition in {"sig_from_invalid", "sig_malformed"}:
        kind = "input"
        expected.update(
            code="invalid_schema" if condition == "sig_from_invalid" else "invalid_json",
            detail="Invalid UTC timestamp."
            if condition == "sig_from_invalid"
            else "Input is not valid strict JSON.",
        )
    if condition == "sig_object":
        kind = "input"
        expected.update(code="invalid_schema", detail="Complete context object is required.")
    if condition in {"sig_raw_metadata", "sig_rule_basis", "sig_rule_schema"}:
        expected.update(subject_digest=None, pointer="/signature_obligation_rule_ref")
    return reference, kind, expected
