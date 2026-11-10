# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete raw Clock method public fault inputs

"""Prepare concrete malformed/source/window controls without replacing runtime observations."""

import json
from dataclasses import replace
from pathlib import Path

from tests.domain.test_cli_evidence_sources import _source
from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _bytes, _object

from evidence_manifest_toolkit import BlobRef

# Each row names the actual method, concrete field, changed declaration and original exit kind.
_CASES: dict[str, tuple[str, str, object, str]] = {
    "cm_drift_shape": ("drift", "extra", False, "configuration"),
    "cm_uncertainty_shape": ("uncertainty", "extra", False, "configuration"),
    "cm_use_shape": ("use", "extra", False, "configuration"),
    "cm_drift_method": ("drift", "method_id", "unknown_drift_method", "clock"),
    "cm_uncertainty_method": ("uncertainty", "method_id", "unknown_uncertainty_method", "clock"),
    "cm_use_method": ("use", "method_id", "unknown_use_method", "clock"),
    "cm_units": ("drift", "units", "seconds", "configuration"),
    "cm_renewal": ("drift", "renewal_rule", "extend_without_sources", "configuration"),
    "cm_from_type": ("drift", "valid_from", None, "configuration"),
    "cm_until_type": ("drift", "valid_until", False, "configuration"),
    "cm_from_invalid": ("drift", "valid_from", "not_a_utc", "utc"),
    "cm_window": ("drift", "valid_until", "2020-01-01T00:00:00Z", "clock"),
    "cm_expired": ("drift", "valid_until", "2025-01-01T00:00:00Z", "clock"),
    "cm_custody": ("drift", "custody_class", "protected_delegated", "clock"),
    "cm_host": ("drift", "host_identity_ref", "other_ref", "clock"),
    "cm_controller": ("drift", "controller_identity_ref", "other_ref", "clock"),
    "cm_environment": ("drift", "implementation_environment_ref", "other_ref", "clock"),
    "cm_boot": ("drift", "boot_domain_ref", "other_ref", "clock"),
    "cm_conditions": ("drift", "assumptions_and_limitations_ref", "other_ref", "clock"),
    "cm_ratio_shape": ("drift", "maximum_error_rate", [], "configuration"),
    "cm_ratio_type": ("drift", "maximum_error_rate/numerator", 1, "configuration"),
    "cm_ratio_negative": ("drift", "maximum_error_rate/numerator", "-1", "clock"),
    "cm_ratio_spelling": ("drift", "maximum_error_rate/numerator", "01", "clock"),
    "cm_ratio_zero_denominator": ("drift", "maximum_error_rate/denominator", "0", "clock"),
    "cm_ratio_unbounded_use": ("drift", "maximum_error_rate/numerator", "1000000000000", "clock"),
    "cm_provenance_shape": ("drift", "provenance_refs", None, "configuration"),
    "cm_provenance_empty": ("drift", "provenance_refs", [], "configuration"),
    "cm_provenance_duplicate": ("drift", "provenance_refs", "duplicate_refs", "configuration"),
    "cm_provenance_missing": ("drift", "provenance_refs", "missing_ref", "unavailable"),
    "cm_rate_missing": ("drift", "rate_source_ref", "missing_ref", "unavailable"),
    "cm_source_unknown_schema": ("drift", "provenance_refs", "unknown_schema", "schema"),
    "cm_uncertainty_holdover": ("uncertainty", "holdover_rule_ref", "other_ref", "clock"),
    "cm_uncertainty_mapping": (
        "uncertainty",
        "daemon_field_mapping_rule_ref",
        "other_ref",
        "clock",
    ),
    "cm_use_request": ("use", "request_id", "another_request", "clock"),
    "cm_use_subject": ("use", "subject_ref", "other_ref", "clock"),
    "cm_use_profile": ("use", "profile_ref", "other_ref", "clock"),
    "cm_use_first": ("use", "first_sample_source_ref", "other_ref", "clock"),
    "cm_use_drift": ("use", "holdover_rule_ref", "other_ref", "clock"),
    "cm_use_ntp": ("use", "before_ntp_ref", "other_ref", "clock"),
    "cm_samples_shape": ("use", "sample_bounds", [], "configuration"),
    "cm_before_shape": ("use", "sample_bounds/before", {}, "configuration"),
    "cm_bound_shape": ("use", "sample_bounds/before/source_encoding", {}, "configuration"),
    "cm_bound_type": (
        "use",
        "sample_bounds/before/source_encoding/bound_ns",
        6000,
        "configuration",
    ),
    "cm_bound_negative": ("use", "sample_bounds/before/source_encoding/bound_ns", "-1", "clock"),
    "cm_encoding_omitted": ("use", "sample_bounds/before/source_encoding/bound_ns", "0", "clock"),
    "cm_sample_understated": (
        "use",
        "sample_bounds/after/source_encoding/bound_ns",
        "5000000001",
        "clock",
    ),
    "cm_bracket_understated": ("use", "sample_bounds/before/acquisition/bound_ns", "0", "clock"),
    "cm_mapping_understated": ("use", "sample_bounds/before/mapping/bound_ns", "1001", "clock"),
    "cm_quantization_understated": (
        "use",
        "sample_bounds/before/quantization/bound_ns",
        "1001",
        "clock",
    ),
    "cm_use_terms_shape": ("use", "use_terms", {}, "configuration"),
    "cm_entry_terms_shape": ("use", "entry_terms", None, "configuration"),
    "cm_use_acquisition": ("use", "use_terms/acquisition/bound_ns", "0", "clock"),
    "cm_use_error": ("use", "use_terms/adjustment/bound_ns", "1000000000", "clock"),
    "cm_entry_acquisition": ("use", "entry_terms/acquisition/bound_ns", "0", "clock"),
    "cm_entry_budget": ("use", "entry_terms/acquisition/bound_ns", "5000000001", "clock"),
    "cm_raw_shape": ("use", "use_raw_ref", "raw_shape", "raw_configuration"),
    "cm_raw_json": ("use", "use_raw_ref", "raw_json", "raw_json"),
    "cm_raw_clock": ("use", "use_raw_ref", "raw_clock", "clock"),
    "cm_raw_uncertainty": ("use", "use_raw_ref", "raw_uncertainty", "raw_configuration"),
    "cm_raw_field_type": ("use", "use_raw_ref", "raw_field_type", "raw_configuration"),
    "cm_raw_ticks": ("use", "use_raw_ref", "raw_ticks", "clock"),
    "cm_raw_order": ("use", "use_raw_ref", "raw_order", "clock"),
    "cm_raw_utc": ("use", "use_raw_ref", "raw_utc", "clock"),
    "cm_raw_integer": ("use", "use_raw_ref", "raw_integer", "clock"),
    "cm_model_media": ("drift", "", None, "model_configuration"),
    "cm_model_json": ("drift", "", None, "model_json"),
    "cm_provenance_known": ("drift", "provenance_refs", "known_schema", "matching"),
    "cm_provenance_descendant": ("drift", "provenance_refs", "missing_descendant", "unavailable"),
    "cm_provenance_identity": ("drift", "provenance_refs", "identity_mismatch", "identity"),
    "cm_whole_conditions": ("drift", "", None, "clock"),
}
CLOCK_METHOD_CASES = tuple(_CASES) + ("cli_cm_units", "cli_cm_rate_missing", "cli_cm_use_request")


def clock_method_body(
    condition: str, record: str, value: dict[str, object], directory: Path
) -> dict[str, object]:
    """Change one complete explicit source declaration before its actual raw identity is fixed.

    Parameters
    ----------
    condition : str
        One named deliberate fault, or an existing unchanged source/capture condition.
    record : str
        Actual drift/uncertainty/use record being materialised.
    value : dict
        Whole explicitly unqualified source, never a native acceptance result.
    directory : Path
        Owned immutable real input store.

    Returns
    -------
    dict
        Full original object with the single named actual fault. No sampler or product
        helper is replaced and all original full capture/receipt sources remain.
    """
    condition = condition.removeprefix("cli_")
    if condition not in _CASES or _CASES[condition][0] != record:
        return value
    _, pointer, changed, _ = _CASES[condition]
    if not pointer:
        return value
    if isinstance(changed, str) and changed.startswith("raw_"):
        original = BlobRef.from_mapping(_object(value["use_raw_ref"]))
        raw = _object(json.loads((directory / original.digest[7:]).read_bytes()))
        if changed == "raw_shape":
            raw["unexpected_member"] = False
        if changed == "raw_clock":
            raw["clock"] = "CLOCK_MONOTONIC"
        if changed == "raw_uncertainty":
            raw["physical_uncertainty"] = None
        if changed == "raw_field_type":
            raw["utc_ns"] = 1
        if changed == "raw_ticks":
            raw["raw_after"] = str(int(str(raw["raw_after"])) + 1)
        if changed == "raw_order":
            raw["raw_before"] = str(int(str(raw["raw_after"])) + 1)
        if changed == "raw_utc":
            raw["utc_ns"] = str(int(str(raw["utc_ns"])) + 10_000_000_000)
        if changed == "raw_integer":
            raw["utc_ns"] = "01"
        replacement = (
            _native_source(b'{"clock":', directory, "application/json")
            if changed == "raw_json"
            else _stored(raw, directory)
        )
        changed = dict(replacement.to_mapping())
    if changed in ("known_schema", "missing_descendant"):
        fixture = _object(_source("verify-current-whole-fixture")["complete_library_inputs"])
        source = replace(
            _native_source(_bytes(fixture["content_json"]), directory, "application/json"),
            schema_id=str(fixture["schema_id"]),
        )
        if changed == "missing_descendant":
            manifest = _object(json.loads((directory / source.digest[7:]).read_bytes()))
            missing = _stored({"deliberately_missing_required_descendant": condition}, directory)
            payload = _object(manifest["payload_ref"])
            manifest["payload_ref"] = {**payload, **dict(missing.to_mapping())}
            (directory / missing.digest[7:]).unlink()
            source = _stored(manifest, directory, schema_id=source.schema_id)
        changed = [dict(source.to_mapping())]
    if changed == "identity_mismatch":
        raw_source = _stored({"deliberate_identity_conflict": condition}, directory)
        conflicting = replace(raw_source, digest="sha256:" + "0" * 64)
        (directory / conflicting.digest[7:]).write_bytes(
            (directory / raw_source.digest[7:]).read_bytes()
        )
        changed = [dict(conflicting.to_mapping())]
    if changed == "other_ref":
        changed = dict(
            _stored({"deliberately_different_source": condition}, directory).to_mapping()
        )
    if changed == "duplicate_refs":
        changed = [value["host_identity_ref"], value["host_identity_ref"]]
    if changed in ("missing_ref", "unknown_schema"):
        reference = _stored({"selected_clock_model_source": condition}, directory)
        if changed == "missing_ref":
            (directory / reference.digest[7:]).unlink()
        else:
            reference = replace(
                reference, schema_id="evidence_manifest_toolkit.unknown_clock_model.v1"
            )
        changed = (
            [dict(reference.to_mapping())]
            if pointer == "provenance_refs"
            else dict(reference.to_mapping())
        )
    target = value
    fields = pointer.split("/")
    for field in fields[:-1]:
        nested = target[field]
        assert isinstance(nested, dict)
        target = nested
    target[fields[-1]] = changed
    return value


def clock_method_reference(condition: str, reference: BlobRef, directory: Path) -> BlobRef:
    """Retain explicit malformed model controls as separate complete original inputs.

    Parameters
    ----------
    condition : str
        One named wrong-metadata or invalid-JSON model source control.
    reference : BlobRef
        Full originally stored drift source, preserved unchanged in the input store.
    directory : Path
        Owned complete original source population.

    Returns
    -------
    BlobRef
        Original declaration or actual separately stored malformed model input. These
        controls supply no accepted physical model or substituted native observation.
    """
    if condition == "cm_model_media":
        return replace(reference, media_type="text/plain")
    if condition == "cm_model_json":
        return _native_source(b'{"method_id":', directory, "application/json")
    return reference


def clock_method_expected(
    condition: str,
    *,
    drift: BlobRef,
    uncertainty: BlobRef,
    use: BlobRef,
    policy: BlobRef,
    profile: BlobRef,
    directory: Path,
) -> tuple[str, dict[str, object]] | None:
    """Retain complete independently specified typed diagnostics for actual public calls.

    Parameters
    ----------
    condition : str
        Named complete raw method/source/window fault.
    drift, uncertainty, use : BlobRef
        Actual entire stored method identities after fault materialisation.
    policy : BlobRef
        Whole independently selected enclosing policy for original Clock diagnostics.
    profile : BlobRef
        Entire actual containing profile for malformed raw model metadata.
    directory : Path
        Owned actual input store for locating exact missing/schema source declarations.

    Returns
    -------
    tuple or None
        Expected original exception kind and full five-field reason, or None for an old
        unchanged case. This helper performs no product calculation or acceptance check.
    """
    condition = condition.removeprefix("cli_")
    if condition not in _CASES:
        return None
    record, pointer, _, kind = _CASES[condition]
    reference = {"drift": drift, "uncertainty": uncertainty, "use": use}[record]
    expected: dict[str, object] = {
        "code": "policy_unavailable",
        "subject_digest": policy.digest,
        "claim_id": None,
        "pointer": "/required_evaluation_time_qualification/clock_qualification_ref",
        "detail": "The required evaluation-time qualification is unavailable.",
    }
    if condition in {
        "cm_ratio_negative",
        "cm_ratio_spelling",
        "cm_bound_negative",
        "cm_raw_integer",
    }:
        expected.update(
            code="invalid_schema",
            detail="Invalid Clock integer encoding.",
        )
    if kind == "configuration":
        expected.update(
            code="configuration_error",
            subject_digest=reference.digest,
            pointer="" if pointer == "extra" else "/" + pointer,
            detail="Invalid Clock method configuration.",
        )
    if kind == "model_configuration":
        kind = "configuration"
        expected.update(
            code="configuration_error",
            subject_digest=profile.digest,
            pointer="/holdover_drift_bound_rule_ref",
            detail="Invalid Clock method configuration.",
        )
    if kind.startswith("raw_") or kind == "model_json":
        raw_ref = reference
        if kind.startswith("raw_"):
            use_body = _object(json.loads((directory / use.digest[7:]).read_bytes()))
            raw_ref = BlobRef.from_mapping(_object(use_body["use_raw_ref"]))
        if kind == "raw_configuration":
            kind = "configuration"
            expected.update(
                code="configuration_error",
                subject_digest=raw_ref.digest,
                pointer={
                    "cm_raw_shape": "",
                    "cm_raw_uncertainty": "/physical_uncertainty",
                    "cm_raw_field_type": "/utc_ns",
                }[condition],
                detail="Invalid Clock method configuration.",
            )
        else:
            expected.update(
                code="invalid_json",
                subject_digest=raw_ref.digest,
                pointer=None,
                detail="Input is not valid strict JSON.",
            )
    if kind == "matching":
        kind = "configuration"
        expected.update(
            code="configuration_error",
            subject_digest=None,
            pointer="/trust",
            detail="Invalid local configuration.",
        )
    if kind == "identity":
        expected.update(
            code="reference_mismatch",
            subject_digest=drift.digest,
            pointer="/provenance_refs/0",
            detail="Reference byte identity does not match.",
        )
    if kind == "utc":
        expected.update(
            code="invalid_schema",
            subject_digest=reference.digest,
            pointer="/valid_from",
            detail="Invalid UTC timestamp.",
        )
    if kind == "unavailable":
        expected.update(
            code="reference_unavailable",
            subject_digest=None,
            pointer=None,
            detail="Required reference unavailable.",
        )
    if kind == "schema":
        body = json.loads((directory / reference.digest[7:]).read_bytes())
        expected.update(
            code="unknown_schema",
            subject_digest=body["provenance_refs"][0]["digest"],
            pointer=None,
            detail="Selected schema is not known.",
        )
    return kind, expected
