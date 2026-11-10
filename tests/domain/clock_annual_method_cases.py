# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original annual method public source cases

"""Declare annual faults and independent public diagnostics around genuine captures."""

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef

ANNUAL_SOURCE_CASES = (
    "annual_source_shape",
    "annual_source_units",
    "annual_source_unknown_method",
    "annual_source_host_mismatch",
    "annual_source_monotonic_mismatch",
    "annual_source_synchronization_population",
    "annual_source_rate_shape",
    "annual_source_rate_numerator_zero",
    "annual_source_rate_denominator_zero",
    "annual_source_rate_conflict",
    "annual_source_rate_equivalent",
    "annual_source_before_shape",
    "annual_source_before_raw",
    "annual_source_after_raw",
    "annual_source_packet_not_synchronized",
    "annual_source_offset_not_associated",
    "annual_source_sample_bounds_shape",
    "annual_source_before_bounds_shape",
    "annual_source_after_bounds_shape",
    "annual_source_bound_type",
    "annual_source_bound_encoding",
    "annual_source_bound_missing",
    "annual_source_method_media",
    "annual_source_method_basis",
    "annual_source_method_schema",
    "annual_source_method_json",
    "annual_source_method_missing",
    "cli_annual_source_units",
    "cli_annual_source_method_missing",
)
ANNUAL_DERIVATION_CASES = (
    "annual_derivation_signed_offset",
    "annual_derivation_window_before_capture",
    "annual_derivation_window_after_capture",
    "annual_derivation_sample_accuracy",
    "cli_annual_derivation_signed_offset",
)
ANNUAL_SAMPLE_CASES = (
    "annual_sample_acquisition",
    "annual_sample_mapping",
    "annual_sample_quantization",
    "annual_sample_source_encoding",
    "annual_sample_elapsed_holdover",
    "annual_sample_post_exchange_adjustment",
    "cli_annual_sample_acquisition",
)


def clock_annual_capture_input(condition: str, annual: dict[str, object]) -> dict[str, object]:
    """Add a declared annual contradiction without replacing any actual observation.

    Parameters
    ----------
    condition : str
        Explicit whole public invocation scenario.
    annual : dict
        Original genuine capture draft, before the child, profile and final body exist.

    Returns
    -------
    dict
        Entire original draft with a signed-offset or declared-radius fault only.
        This does not invent a daemon observation, physical bound or accepted class.
    """
    condition = condition.removeprefix("cli_")
    if condition == "annual_derivation_signed_offset":
        annual["measured_ntp_offset_ns"] = str(int(str(annual["measured_ntp_offset_ns"])) + 1)
    if condition == "annual_derivation_sample_accuracy":
        annual["before"] = {**_object(annual["before"]), "accuracy_radius_ns": "0"}
    return annual


def clock_annual_method_source(
    condition: str, value: dict[str, object], directory: Path
) -> BlobRef:
    """Store one complete annual method fault while retaining genuine original sources.

    Parameters
    ----------
    condition : str
        Named raw-child association, configuration, term or source fault.
    value : dict
        Complete original child before hashing; all physical premises stay unqualified.
    directory : Path
        Owned immutable source population used by the genuine API or CLI invocation.

    Returns
    -------
    BlobRef
        Exact newly materialised declaration, including deliberately absent or malformed
        sources. No private product helper or substituted clock/provider is invoked.
    """
    condition = condition.removeprefix("cli_")
    before = cast(dict[str, object], value["before"])
    after = cast(dict[str, object], value["after"])
    rows = cast(dict[str, object], value["sample_bounds"])
    before_bounds = cast(dict[str, object], rows["before"])
    mapping = cast(dict[str, object], before_bounds["mapping"])
    if condition == "annual_source_shape":
        value["unexpected_member"] = False
    if condition == "annual_source_units":
        value["units"] = "seconds"
    if condition == "annual_source_unknown_method":
        value["method_id"] = "unsupported_original_annual_method"
    if condition in {"annual_source_host_mismatch", "annual_source_monotonic_mismatch"}:
        different = _stored({"unqualified_different_original_source": condition}, directory)
        field = (
            "host_identity_ref" if condition.endswith("host_mismatch") else "monotonic_domain_ref"
        )
        value[field] = dict(different.to_mapping())
    if condition == "annual_source_synchronization_population":
        value["raw_synchronization_refs"] = []
    rates: dict[str, dict[str, object]] = {
        "annual_source_rate_shape": {"numerator": "1000000000"},
        "annual_source_rate_numerator_zero": {"numerator": "0", "denominator": "1"},
        "annual_source_rate_denominator_zero": {"numerator": "1000000000", "denominator": "0"},
        "annual_source_rate_conflict": {"numerator": "1", "denominator": "1"},
        "annual_source_rate_equivalent": {"numerator": "2000000000", "denominator": "2"},
    }
    if condition in rates:
        value["ticks_per_second"] = rates[condition]
    if condition == "annual_source_before_shape":
        value["before"] = {"ntp_ref": before["ntp_ref"]}
    if condition == "annual_source_before_raw":
        before["clock_sample_raw_ref"] = after["clock_sample_raw_ref"]
    if condition == "annual_source_after_raw":
        after["clock_sample_raw_ref"] = before["clock_sample_raw_ref"]
    if condition == "annual_source_packet_not_synchronized":
        before["ntp_ref"] = value["host_identity_ref"]
    if condition == "annual_source_offset_not_associated":
        value["measured_offset_source_ref"] = value["host_identity_ref"]
    if condition == "annual_source_sample_bounds_shape":
        value["sample_bounds"] = {}
    if condition == "annual_source_before_bounds_shape":
        rows["before"] = {}
    if condition == "annual_source_after_bounds_shape":
        rows["after"] = {}
    if condition == "annual_source_bound_type":
        mapping["bound_ns"] = 1
    if condition == "annual_source_bound_encoding":
        mapping["bound_ns"] = "01"
    if condition == "annual_source_bound_missing":
        missing = _stored({"required_absent_original_annual_bound": condition}, directory)
        (directory / missing.digest[7:]).unlink()
        mapping["source_ref"] = dict(missing.to_mapping())
    if condition.startswith("annual_sample_"):
        term = condition.removeprefix("annual_sample_")
        if term == "acquisition":
            assert int(str(_object(before_bounds[term])["bound_ns"])) > 0
        datum = cast(dict[str, object], before_bounds[term])
        datum["bound_ns"] = (
            "0"
            if term == "acquisition"
            else "1001"
            if term in {"mapping", "quantization"}
            else "3000000000"
        )
    if condition == "annual_derivation_window_before_capture":
        value["valid_until"] = "2021-01-01T00:00:00Z"
    if condition == "annual_derivation_window_after_capture":
        value["valid_from"] = "2029-01-01T00:00:00Z"
    reference = _stored(value, directory)
    if condition == "annual_source_method_media":
        return replace(reference, media_type="text/plain")
    if condition == "annual_source_method_basis":
        return replace(reference, digest_basis="jcs_content")
    if condition == "annual_source_method_schema":
        return replace(reference, schema_id="evidence_manifest_toolkit.authority_policy.v2")
    if condition == "annual_source_method_json":
        return _native_source(b'{"method_id":', directory, "application/json")
    if condition == "annual_source_method_missing":
        (directory / reference.digest[7:]).unlink()
    return reference


def clock_annual_method_expected(
    condition: str, *, uncertainty: BlobRef, policy: BlobRef, content: BlobRef, directory: Path
) -> tuple[str, dict[str, object], BlobRef | None] | None:
    """Specify whole public reasons independently of annual production calculations.

    Parameters
    ----------
    condition : str
        Named actual annual source or arithmetic scenario.
    uncertainty, policy, content : BlobRef
        Full actual uncertainty parent, selected policy and complete original content.
    directory : Path
        Whole original input store, read only to identify the exact declared child/source.

    Returns
    -------
    tuple or None
        Explicit exception kind, all five reason fields and exact missing declaration,
        or None for an unchanged existing scenario. Consistent declarations still require
        the real ordinary signature and do not establish Clock, model or class admission.
    """
    condition = condition.removeprefix("cli_")
    cases = {
        case.removeprefix("cli_")
        for case in (*ANNUAL_SOURCE_CASES, *ANNUAL_DERIVATION_CASES, *ANNUAL_SAMPLE_CASES)
    }
    if condition not in cases:
        return None
    parent = _object(json.loads((directory / uncertainty.digest[7:]).read_bytes()))
    child = BlobRef.from_mapping(_object(parent["annual_derivation_ref"]))
    expected: dict[str, object] = {
        "code": "policy_unavailable",
        "subject_digest": policy.digest,
        "claim_id": None,
        "pointer": "/required_evaluation_time_qualification/clock_qualification_ref",
        "detail": "The required evaluation-time qualification is unavailable.",
    }
    fields = {
        "annual_source_shape": "",
        "annual_source_units": "/units",
        "annual_source_rate_shape": "/ticks_per_second",
        "annual_source_before_shape": "/before",
        "annual_source_sample_bounds_shape": "/sample_bounds",
        "annual_source_before_bounds_shape": "/sample_bounds/before",
        "annual_source_after_bounds_shape": "/sample_bounds/after",
        "annual_source_bound_type": "/sample_bounds/before/mapping/bound_ns",
    }
    if condition in fields or condition in {
        "annual_source_method_media",
        "annual_source_method_basis",
        "annual_source_method_schema",
    }:
        metadata = condition.startswith("annual_source_method_")
        expected.update(
            code="configuration_error",
            subject_digest=uncertainty.digest if metadata else child.digest,
            pointer="/annual_derivation_ref" if metadata else fields[condition],
            detail="Invalid Clock method configuration.",
        )
        return "configuration", expected, None
    if condition in {"annual_source_method_missing", "annual_source_bound_missing"}:
        missing = child
        if condition == "annual_source_bound_missing":
            body = _object(json.loads((directory / child.digest[7:]).read_bytes()))
            bounds = _object(_object(body["sample_bounds"])["before"])
            missing = BlobRef.from_mapping(_object(_object(bounds["mapping"])["source_ref"]))
        expected.update(
            code="reference_unavailable",
            subject_digest=None,
            pointer=None,
            detail="Required reference unavailable.",
        )
        return "unavailable", expected, missing
    if condition == "annual_source_method_json":
        expected.update(
            code="invalid_json",
            subject_digest=child.digest,
            pointer=None,
            detail="Input is not valid strict JSON.",
        )
    if condition == "annual_source_bound_encoding":
        expected.update(code="invalid_schema", detail="Invalid Clock integer encoding.")
    if condition == "annual_source_rate_equivalent":
        expected.update(
            code="signature_required",
            subject_digest=content.digest,
            pointer=None,
            detail="The required evidence signature is unavailable.",
        )
    return "refused", expected, None
