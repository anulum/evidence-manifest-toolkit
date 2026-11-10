# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole Clock subject through actual public native entry

"""Check whole invocation joins with genuine local samples and unqualified source bounds."""

import base64
import ctypes
import json
import os
import subprocess
import sys
import sysconfig
import time
from collections.abc import Mapping
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path
from typing import cast

import pytest
from tests.domain.clock_acceptance_inputs import (
    CLOCK_ACCEPTANCE_CASES,
    clock_acceptance_expected,
    clock_acceptance_input,
)
from tests.domain.clock_annual_method_cases import (
    clock_annual_capture_input,
    clock_annual_method_expected,
)
from tests.domain.clock_method_cases import CLOCK_METHOD_CASES, clock_method_expected
from tests.domain.clock_method_inputs import clock_model_inputs, clock_use_input
from tests.domain.clock_source_inputs import software_acceptance_sources, software_manifest_receipt
from tests.domain.method_rule_inputs import method_rule_inputs
from tests.domain.native_installation_inputs import NATIVE_INSTALLATION_CASES
from tests.domain.native_possession_method_inputs import possession_registry_input
from tests.domain.native_rule_binding_inputs import NATIVE_BINDING_CASES, native_binding_input
from tests.domain.protected_control_inputs import protected_control_inputs
from tests.domain.protected_math_inputs import (
    PROTECTED_MATH_CASES,
    protected_math_expected,
    protected_math_receipt,
    protected_math_state,
)
from tests.domain.protected_ordinary_inputs import (
    ordinary_certificate_state,
    protected_manifest_receipt,
)
from tests.domain.protected_state_inputs import protected_state_inputs
from tests.domain.protected_use_interval_inputs import (
    PROTECTED_USE_INTERVAL_CASES,
    PROTECTED_USE_MATCHING_CASES,
    PROTECTED_USE_RECEIPT_CASES,
    protected_use_interval_sources,
)
from tests.domain.reproduction_default_native_inputs import (
    DEFAULT_NATIVE_REPRODUCTION_CASES,
    default_native_reproduction_input,
)
from tests.domain.reproduction_history_inputs import PARENT_HISTORY_CASES, parent_history_input
from tests.domain.reproduction_native_faults import (
    NATIVE_REPRODUCTION_CASES,
    native_reproduction_fault,
)
from tests.domain.reproduction_record_inputs import REPRODUCTION_RECORD_CASES, reproduction_inputs
from tests.domain.signature_obligation_inputs import (
    SIGNATURE_OBLIGATION_CASES,
    obligation_expected,
    obligation_inputs,
)
from tests.domain.signature_rule_cli import invoke_rule_cli
from tests.domain.signature_rule_inputs import SIGNATURE_RULE_CASES, signature_rule_input
from tests.domain.software_interval_inputs import SOFTWARE_INTERVAL_CASES, software_interval_table
from tests.domain.software_reproduction_sources import (
    PENDING_RECORD_SIGNATURE_CASES,
    SOFTWARE_RECORD_CASES,
    SOFTWARE_RECORD_INPUTS,
    software_record_expected,
)
from tests.domain.test_cli_evidence_sources import _source, _transport
from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_policy_selection_sources import _successor_policy
from tests.domain.test_software_sources import _software_table
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import (
    _array,
    _bytes,
    _FileResolver,
    _mapping,
    _object,
    _registry,
    _text,
)

from evidence_manifest_toolkit import (
    BlobRef,
    ConfigurationError,
    DelegatedTrustContextV2,
    InputRefused,
    Limits,
    ReferenceUnavailable,
    SoftwareTrustContextV2,
    UnsignedTrustContextV2,
    Utc,
    VerificationPolicy,
    reference_bytes,
    verify,
)
from evidence_manifest_toolkit._immutable import FrozenJson
from evidence_manifest_toolkit._trust_types import Purpose

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"


def _utc(nanoseconds: int) -> str:
    """Encode an actual integer Unix observation without a floating-point epoch.

    Parameters
    ----------
    nanoseconds : int
        Actual CLOCK_REALTIME integer source observation.

    Returns
    -------
    str
        Whole nine-digit UTC source token.
    """
    seconds, remainder = divmod(nanoseconds, 1_000_000_000)
    value = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    return value.strftime("%Y-%m-%dT%H:%M:%S") + f".{remainder:09d}Z"


def _sample(
    directory: Path, *, accuracy_radius_ns: int = 1_000_000_000
) -> tuple[dict[str, object], BlobRef]:
    """Retain actual bracketed local observations without pretending to qualify uncertainty.

    Parameters
    ----------
    directory : Path
        Owned source store for the entire independently captured raw observation.
    accuracy_radius_ns : int
        Explicit unqualified conditional sample radius, never physical support.

    Returns
    -------
    tuple
        Full declared sample and actual raw identity. Positive error declarations below
        are deliberately UNQUALIFIED test inputs, not admitted NTP/model measurements.
    """
    start = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    utc = time.clock_gettime_ns(time.CLOCK_REALTIME)
    end = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    raw = _stored(
        {
            "clock": "CLOCK_REALTIME",
            "utc_ns": str(utc),
            "raw_before": str(start),
            "raw_after": str(end),
            "physical_uncertainty": "unavailable",
        },
        directory,
    )
    return {
        "utc_lexeme": _utc(utc),
        "utc_epoch_ns": str(utc),
        "monotonic_ticks": str(end),
        "clock_sample_raw_ref": dict(raw.to_mapping()),
        "accuracy_radius_ns": str(accuracy_radius_ns),
        "mapping_error_bound_ns": "1000",
        "quantization_error_bound_ns": "1000",
    }, raw


def _synchronization(directory: Path) -> tuple[BlobRef, int]:
    """Retain the actual whole daemon reply and independently calculate its reported offset.

    Parameters
    ----------
    directory : Path
        Owned immutable raw source store.

    Returns
    -------
    tuple
        Entire original reply reference and exact signed reported offset in nanoseconds.
        Source authorization, installed mapping and physical bounds remain unqualified.
    """
    result = subprocess.run(
        [
            "busctl",
            "--system",
            "get-property",
            "org.freedesktop.timesync1",
            "/org/freedesktop/timesync1",
            "org.freedesktop.timesync1.Manager",
            "NTPMessage",
        ],
        capture_output=True,
        check=True,
        timeout=10,
    )
    assert not result.stderr
    tokens = result.stdout.decode("ascii").split()
    assert len(tokens) == 20 and tokens[0] == "(uuuuittayttttbtt)" and tokens[8] == "4"
    t1, t2, t3, t4 = map(int, tokens[13:17])
    return _native_source(result.stdout, directory, "text/plain"), ((t2 - t1) + (t3 - t4)) * 500


@pytest.mark.parametrize(
    "condition",
    (
        "matching",
        "content",
        "context",
        "policy",
        "entry_order",
        "rate",
        "software",
        "software_content",
        "software_historical",
        "software_receipt",
        "software_receipt_ref",
        "software_receipt_count",
        "software_receipt_digest",
        "software_receipt_length",
        "software_receipt_authorizing",
        "software_receipt_authorization",
        "software_receipt_snapshot",
        "software_receipt_scope",
        "software_receipt_claim",
        "software_receipt_key",
        "software_receipt_purpose",
        "software_receipt_time",
        "software_receipt_revocation",
        "software_receipt_split_scope",
        "software_receipt_signature",
        "software_receipt_signature_rows",
        "software_receipt_window_rows",
        "software_receipt_lower",
        "software_receipt_historical",
        "software_receipt_historical_current",
        *SIGNATURE_RULE_CASES,
        *CLOCK_METHOD_CASES,
        *CLOCK_ACCEPTANCE_CASES,
        *SIGNATURE_OBLIGATION_CASES,
        *REPRODUCTION_RECORD_CASES,
        "clock_subject_limits",
        "clock_subject_first_raw",
        "clock_subject_first_coordinate",
        "clock_subject_capture_bounds",
        "protected_control_base",
        "protected_ordinary_matching",
        "cli_protected_ordinary_matching",
        *PROTECTED_MATH_CASES,
        *NATIVE_REPRODUCTION_CASES,
        *DEFAULT_NATIVE_REPRODUCTION_CASES,
        *PARENT_HISTORY_CASES,
        *SOFTWARE_RECORD_CASES,
        *SOFTWARE_INTERVAL_CASES,
        "protected_reproduction_match",
        "protected_reproduction_identity_schema",
        "protected_reproduction_record_unknown_schema",
        "cli_protected_reproduction_record_unknown_schema",
        "protected_reproduction_custody",
        "protected_reproduction_same_vendor",
        "protected_reproduction_shared_key",
        "protected_reproduction_body_missing",
        "protected_reproduction_subject_missing_no_schema",
        "protected_reproduction_policy_json_no_schema",
        "cli_protected_reproduction_body_missing",
        "cli_protected_reproduction_same_vendor",
    ),
)
def test_whole_clock_subject_matches_actual_invocation_and_entry_before_state(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Traverse complete source bodies and reject whole joins before unavailable V2 state.

    Parameters
    ----------
    condition : str
        Complete matching sources, wrong whole content/context, future H or wrong tick rate.
    tmp_path : Path
        Owned whole original carriers and genuine process/boot/runtime/raw time records.
    capfd : pytest.CaptureFixture
        Actual command stdout/stderr capture for module-entry cases, without mocked I/O.

    launcher_implementation_bytes : bytes or None
        Whole independent descriptor input frozen before an isolated installed-source fault.
        Passed only to fixture construction, never as a product hook or admission flag.

    Notes
    -----
    All six acceptance outcomes are explicitly unavailable. Bounds and rule references
    are unqualified declarations; these are source-consistency cases, never a Clock pass.
    No private production helper, substituted clock or fabricated protected source runs.
    """
    assert_whole_clock_source_workflow(condition, tmp_path, capfd)


def assert_whole_clock_source_workflow(
    condition: str,
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    *,
    limits_override: Mapping[str, int] | None = None,
    resolver_calls: list[tuple[BlobRef | str, int]] | None = None,
    launcher_implementation_bytes: bytes | None = None,
) -> None:
    """Traverse complete source bodies and reject whole joins before unavailable V2 state.

    Parameters
    ----------
    condition : str
        Complete matching sources, wrong whole content/context, future H or wrong tick rate.
    tmp_path : Path
        Owned whole original carriers and genuine process/boot/runtime/raw time records.
    capfd : pytest.CaptureFixture
        Actual command stdout/stderr capture for module-entry cases, without mocked I/O.

    limits_override : Mapping or None
        Explicit whole caller-bound overrides before capture and context freeze.
    resolver_calls : list or None
        Receives real public Resolver arguments and bounded-read allowances after API use.
        It changes no resolver, source bytes, observation, native method or budget.
    launcher_implementation_bytes : bytes or None
        Entire independently frozen descriptor for real isolated physical installation faults.
        This is fixture source data, never a product hook or admission assertion.

    Notes
    -----
    All six acceptance outcomes are explicitly unavailable. Bounds and rule references
    are unqualified declarations; these are source-consistency cases, never a Clock pass.
    No private production helper, substituted clock or fabricated protected source runs.
    """
    native_condition = condition
    if condition in NATIVE_BINDING_CASES or condition in NATIVE_INSTALLATION_CASES:
        prefix = "cli_" if condition.startswith("cli_") else ""
        native_role = condition.removeprefix("cli_")
        condition = prefix + (
            "software_receipt"
            if native_role.startswith("software_receipt_")
            else "protected_ordinary_matching"
            if native_role.startswith("protected_ordinary_")
            else "sig_exception"
        )
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    inputs = obligation_inputs(condition, inputs, tmp_path)
    if limits_override is not None:
        inputs["limits"] = {**_object(inputs["limits"]), **limits_override}
    inputs = possession_registry_input(condition, inputs, tmp_path)
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    protected_reproduction = condition.removeprefix("cli_").startswith("protected_reproduction_")
    protected_math = condition.removeprefix("cli_").startswith("protected_math_")
    protected_use_receipt = condition.removeprefix("cli_") in PROTECTED_USE_RECEIPT_CASES
    custody_class = (
        "protected_delegated"
        if protected_reproduction
        or protected_math
        or condition in PROTECTED_USE_INTERVAL_CASES
        or condition
        in {
            "protected_unprotected_scope",
            "protected_control_base",
            "protected_ordinary_matching",
            "cli_protected_ordinary_matching",
        }
        else "software_local_unprotected"
        if condition.removeprefix("cli_").startswith("software")
        else "unsigned_declared"
    )
    original_policy = _object(inputs["policy"])
    original_ref = BlobRef.from_mapping(_object(original_policy["policy_ref"]))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    originals = {path: path.read_bytes() for path in population.values()}
    base = _object(json.loads(population[original_ref.digest + "|raw_bytes"].read_bytes()))
    for name in ("actual_accepted_configuration", "source_chain_ref"):
        base.pop(name)
    base.update(
        required_claim_ids=original_policy["required_claim_ids"],
        required_purposes=original_policy["required_purposes"],
        namespace="OWNER_LOCAL_VERIFICATION_POLICY_V1",
        time_rule="Explicit caller UTC under original half-open snapshot/certificate windows; "
        "independently qualified evaluation-time source required.",
        root_and_key_rule="Existing independently owner-approved local bootstrap/current "
        "configuration; no artifact approval or root provisioning.",
        required_evaluation_time_qualification={
            "requirement": "independent previously accepted clock/time-selection method and full "
            "source/capture/controller identity",
            "clock_qualification_ref": None,
            "actual_qualification": "unavailable",
            "caller_utc_string_is_qualification": False,
            "source_contract": "Existing selected common8 UTC/time qualification boundary; this "
            "explicit prospective policy extension needs affected selection and adds no "
            "TrustContext field.",
        },
    )
    base_ref = _stored(base, tmp_path)
    if condition == "sig_base_jcs":
        base_raw = (tmp_path / base_ref.digest[7:]).read_bytes()
        base_ref = reference_bytes(
            base_raw,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id=None,
            limits=limits,
        )
        (tmp_path / base_ref.digest[7:]).write_bytes(base_raw)
    rule_fields, _ = method_rule_inputs(
        base_ref,
        tmp_path,
        profile_class=custody_class,
        launcher_implementation_bytes=launcher_implementation_bytes,
    )
    environment = _stored(
        {
            "python_implementation": sys.implementation.name,
            "python_version": sys.version,
            "python_cache_tag": sys.implementation.cache_tag,
            "python_executable": sys.executable,
            "python_soabi": sysconfig.get_config_var("SOABI"),
            "libc_reported_version": os.confstr("CS_GNU_LIBC_VERSION"),
            "uname": list(os.uname()),
            "byte_order": sys.byteorder,
            "long_bits": str(ctypes.sizeof(ctypes.c_long) * 8),
            "pointer_bits": str(ctypes.sizeof(ctypes.c_void_p) * 8),
        },
        tmp_path,
    )
    boot = _native_source(
        Path("/proc/sys/kernel/random/boot_id").read_bytes(), tmp_path, "text/plain"
    )
    process = _native_source(Path("/proc/self/stat").read_bytes(), tmp_path, "text/plain")
    method = _native_source(
        files("evidence_manifest_toolkit").joinpath("_native_entry_method.json").read_bytes(),
        tmp_path,
        "application/json",
    )
    declared = _stored(
        {
            "pid": str(os.getpid()),
            "provenance": "declared_by_launcher_under_the_seat_account",
            "qualified_rule": False,
        },
        tmp_path,
    )
    ref = dict(declared.to_mapping())
    protected_rule, protected_selection = base_ref, base_ref
    protected_grant, protected_snapshot = declared, declared
    ordinary_certificate: BlobRef | None = None
    if custody_class == "protected_delegated":
        protected_base = (
            _native_source(
                b"\n" + (tmp_path / base_ref.digest[7:]).read_bytes(), tmp_path, "application/json"
            )
            if condition == "protected_control_base"
            else base_ref
        )
        protected_rule, protected_selection, _, _ = protected_control_inputs(
            protected_base, tmp_path, root=declared, conditions=declared
        )
        protected_grant, protected_snapshot, _ = protected_state_inputs(
            protected_base, protected_rule, declared, tmp_path
        )
        if protected_math:
            protected_grant, protected_snapshot, ordinary_certificate = protected_math_state(
                condition,
                base=base_ref,
                grant=protected_grant,
                snapshot=protected_snapshot,
                directory=tmp_path,
                limits=limits,
            )
        elif (
            protected_reproduction
            or protected_use_receipt
            or condition
            in {
                "protected_ordinary_matching",
                "cli_protected_ordinary_matching",
            }
        ):
            protected_grant, protected_snapshot, ordinary_certificate = ordinary_certificate_state(
                base_ref,
                protected_grant,
                protected_snapshot,
                tmp_path,
                case="parent" if condition == "protected_use_parent" else "matching",
            )
    reproduction_condition = (
        ("cli_" if condition.startswith("cli_") else "")
        + condition.removeprefix("cli_").removeprefix("protected_")
        if protected_reproduction
        else condition
    )
    unknown_reproduction_schema = (
        condition.removeprefix("cli_") == "protected_reproduction_record_unknown_schema"
    )
    full_record_obligation = condition.removeprefix("cli_") in PENDING_RECORD_SIGNATURE_CASES
    if full_record_obligation:
        inputs["content_json"] = _object(source["complete_library_inputs"])["content_json"]
    inputs, reproduction_expected = reproduction_inputs(
        "reproduction_match"
        if unknown_reproduction_schema
        or condition in NATIVE_REPRODUCTION_CASES
        or condition in DEFAULT_NATIVE_REPRODUCTION_CASES
        or condition in PARENT_HISTORY_CASES
        or full_record_obligation
        else SOFTWARE_RECORD_INPUTS.get(condition, reproduction_condition),
        inputs,
        tmp_path,
        rules=rule_fields,
        base=base_ref,
        conditions=declared,
        profile_class=custody_class,
        native_snapshot=protected_snapshot,
        native_certificate=ordinary_certificate,
    )
    if condition in NATIVE_REPRODUCTION_CASES:
        inputs, reproduction_expected = native_reproduction_fault(
            condition, inputs, tmp_path, limits=limits
        )
    if condition in DEFAULT_NATIVE_REPRODUCTION_CASES:
        inputs, reproduction_expected = default_native_reproduction_input(
            condition, inputs, tmp_path, base=base_ref, limits=limits
        )
    if condition in PARENT_HISTORY_CASES:
        inputs, reproduction_expected = parent_history_input(
            condition, inputs, tmp_path, limits=limits
        )
    if condition in SOFTWARE_RECORD_CASES:
        reproduction_expected = software_record_expected(condition, inputs, reproduction_expected)
    if full_record_obligation:
        reproduction_expected = None
    native_expected = native_binding_input(native_condition, rule_fields, tmp_path)
    if unknown_reproduction_schema:
        declared_content = _object(json.loads(_bytes(inputs["content_json"])))
        declared_claim = _object(_array(declared_content["claims"])[1])
        validation = _object(declared_claim["validation"])
        validation["record_ref"] = {
            **_object(validation["record_ref"]),
            "schema_id": "evidence_manifest_toolkit.uninstalled_validation_record.v99",
        }
        declared_claim["validation"] = validation
        declared_content["claims"] = [_array(declared_content["claims"])[0], declared_claim]
        content_bytes = _transport(declared_content)
        inputs["content_json"] = base64.urlsafe_b64encode(content_bytes).rstrip(b"=").decode()
        native_content = reference_bytes(
            content_bytes,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id=_text(inputs["schema_id"]),
            limits=limits,
        )
        reproduction_expected = (
            "refused",
            {
                "code": "unknown_schema",
                "subject_digest": native_content.digest,
                "claim_id": None,
                "pointer": "/claims/1/validation/record_ref",
                "detail": "Selected schema is not known.",
            },
            None,
        )
    software_table = (
        _software_table(base_ref, tmp_path, sequence="1")
        if condition.removeprefix("cli_").startswith("software")
        or custody_class == "protected_delegated"
        else None
    )
    if software_table is not None and condition.removeprefix("cli_").startswith("software_receipt"):
        table_value = _object(json.loads((tmp_path / software_table.digest[7:]).read_bytes()))
        key_entry = _object(_array(table_value["authorized_keys"])[0])
        key_entry.update(
            principal=base["required_principal"],
            role=base["required_role"],
            segment=base["required_segment"],
        )
        if condition in {
            "software_receipt_obligation_purpose",
            "software_receipt_obligation_global_purpose",
        }:
            key_entry["purposes"] = ["evidence", "human_review"]
        table_value["authorized_keys"] = [key_entry]
        if condition == "software_receipt_revocation":
            table_value["revocations"] = [
                {
                    "key_id": key_entry["key_id"],
                    "revocation_source_ref": dict(base_ref.to_mapping()),
                }
            ]
        if condition == "software_receipt_split_scope":
            table_value["authorized_keys"] = [
                {**key_entry, "role": "different-role"},
                {**key_entry, "principal": "different-principal"},
            ]
        if condition in {"software_receipt_signature_rows", "software_receipt_window_rows"}:
            table_value["authorized_keys"] = [
                {
                    **key_entry,
                    "group": "first-source-scope",
                    "valid_from": "2025-01-01T00:00:00Z",
                    "valid_until": "2026-01-01T00:00:00Z",
                },
                {**key_entry, "group": "second-source-scope"},
            ]
        table_value = software_interval_table(condition, table_value)
        software_table = _stored(table_value, tmp_path)
    current_software_table = software_table
    if condition.startswith("software_receipt_historical"):
        assert software_table is not None
        current_software_table = _software_table(
            base_ref,
            tmp_path,
            sequence="2",
            previous=software_table,
            changes={"authorized_keys": table_value["authorized_keys"]},
        )
    issuer = ref if software_table is not None else None
    issuer_authorization = dict(software_table.to_mapping()) if software_table is not None else None
    acceptance_before, _ = _sample(tmp_path)
    acceptance_raw, acceptance_offset = _synchronization(tmp_path)
    acceptance_after, _ = _sample(tmp_path)
    beginning = datetime.now(UTC) - timedelta(
        seconds=10
        if condition in SOFTWARE_INTERVAL_CASES or condition in PROTECTED_USE_INTERVAL_CASES
        else 2
    )
    validity_start = beginning.strftime("%Y-%m-%dT%H:%M:%SZ")
    validity_end = beginning.replace(
        year=beginning.year + 1,
        day=28 if beginning.month == 2 and beginning.day == 29 else beginning.day,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    rate = {"numerator": "1000000000", "denominator": "1"}
    annual_capture: dict[str, object] = {
        "raw_synchronization_refs": [dict(acceptance_raw.to_mapping())],
        "monotonic_domain_ref": dict(boot.to_mapping()),
        "ticks_per_second": rate,
        "before": acceptance_before,
        "after": acceptance_after,
        "acceptance_utc_lower_ns": str(
            int(cast(str, acceptance_before["utc_epoch_ns"])) - 1000002000
        ),
        "acceptance_utc_upper_ns": str(
            int(cast(str, acceptance_after["utc_epoch_ns"])) + 1000002000
        ),
        "valid_from": validity_start,
        "valid_until": validity_end,
        "measured_ntp_offset_ns": str(acceptance_offset),
    }
    annual_capture = clock_acceptance_input(condition, annual_capture, tmp_path)
    annual_capture = clock_annual_capture_input(condition, annual_capture)
    uncertainty_method, drift_method = clock_model_inputs(
        tmp_path,
        condition=condition,
        identity=declared,
        environment=environment,
        boot=boot,
        custody_class=custody_class,
        annual=annual_capture,
        ntp=acceptance_raw,
        original_samples=(acceptance_before, acceptance_after),
    )
    profile = {
        "format_version": "autonomous-evaluation-clock-profile-source-r4",
        "time_source": "workstation_system_clock_ntp",
        "host_identity_ref": ref,
        "controller_identity_ref": ref,
        "observer_identity_ref": ref,
        "accepted_ntp_configuration_ref": ref,
        "acquisition_rule_ref": ref,
        "implementation_environment_ref": dict(environment.to_mapping()),
        "monotonic_mapping_rule_ref": ref,
        "uncertainty_derivation_rule_ref": dict(uncertainty_method.to_mapping()),
        "issuer_identity_ref": issuer,
        "issuer_authorization_ref": issuer_authorization,
        "independence_rule_ref": ref,
        "maximum_uncertainty_ns": "5000000000",
        "renewal_rule": "one_utc_civil_year_feb29_clamped_to_feb28",
        "coordinate_encoding": "exact_proleptic_gregorian_civil_nanoseconds_without_leap_second_lexemes",
        "custody_class": custody_class,
        "daemon_field_mapping_rule_ref": ref,
        "ntp_resolution_and_rotation_rule_ref": ref,
        "automatic_reacceptance_rule_ref": ref,
        "holdover_drift_bound_rule_ref": dict(drift_method.to_mapping()),
        "handoff_rule": "fixed_at_verify_entry_extend_by_actual_monotonic_elapsed_and_complete_error_budget",
    }
    profile_ref = _stored(profile, tmp_path)
    acceptance_value: dict[str, object] = {
        **annual_capture,
        "format_version": "autonomous-evaluation-clock-acceptance-source-r4",
        "profile_ref": dict(profile_ref.to_mapping()),
        "host_identity_ref": ref,
        "controller_identity_ref": ref,
        "observer_identity_ref": ref,
        "issuer_identity_ref": issuer,
        "issuer_authorization_ref": issuer_authorization,
        "rule_implementation_ref": ref,
        "checks": [
            {"check_id": name, "result": "unavailable", "evidence_refs": [ref]}
            for name in (
                "whole_source_match",
                "controller_source_match",
                "synchronization_and_mapping",
                "proven_uncertainty_budget",
                "selected_class_authority_and_time",
                "acyclic_whole_target",
            )
        ],
        "custody_class": custody_class,
    }
    acceptance = _stored(acceptance_value, tmp_path)
    acceptance_statement = None
    acceptance_receipts: list[dict[str, str]] = []
    if software_table is not None:
        c0_ref, receipt_ref = software_acceptance_sources(
            _bytes(inputs["content_json"]),
            acceptance=acceptance,
            table=software_table,
            scope=base_ref,
            raw_source=acceptance_raw,
            environment=environment,
            created_at=cast(str, acceptance_after["utc_lexeme"]),
            directory=tmp_path,
            limits=limits,
        )
        acceptance_statement = dict(c0_ref.to_mapping())
        acceptance_receipts.append(dict(receipt_ref.to_mapping()))
    protected_grant, protected_snapshot, ordinary_certificate, protected_use_reason = (
        protected_use_interval_sources(
            condition,
            grant=protected_grant,
            snapshot=protected_snapshot,
            certificate=ordinary_certificate,
            original_sample_utc=_text(acceptance_before["utc_lexeme"]),
            directory=tmp_path,
        )
    )
    ordinary_envelopes: tuple[bytes, ...] = ()
    ordinary_receipt_refs: list[dict[str, str]] = []
    if condition.removeprefix("cli_").startswith("software_receipt"):
        assert software_table is not None
        changes: dict[str, object] = {}
        field = {
            "software_receipt_digest": "content_digest",
            "software_receipt_length": "content_byte_length",
            "software_receipt_authorizing": "authorizing_state_ref",
            "software_receipt_authorization": "authorization_ref",
            "software_receipt_snapshot": "snapshot_ref",
            "software_receipt_scope": "scope_ref",
            "software_receipt_claim": "claim_ids",
            "software_receipt_key": "signer_key_id",
            "software_receipt_purpose": "purpose",
            "software_receipt_time": "claimed_signed_at",
            "software_receipt_lower": "claimed_signed_at",
            "software_receipt_window_rows": "claimed_signed_at",
            "software_receipt_historical_current": "snapshot_ref",
        }.get(condition)
        if field is not None:
            changes[field] = (
                base_ref.digest
                if field == "content_digest"
                else "1"
                if field == "content_byte_length"
                else ["missing-claim"]
                if field == "claim_ids"
                else "ed25519:" + "0" * 64
                if field == "signer_key_id"
                else "deployment"
                if field == "purpose"
                else "2027-01-01T00:00:00Z"
                if field == "claimed_signed_at"
                else dict(declared.to_mapping())
            )
        if condition == "software_receipt_interval_issued_after_signature":
            changes["claimed_signed_at"] = "2026-01-01T00:00:00Z"
        if condition == "software_receipt_lower":
            changes["claimed_signed_at"] = "2026-01-01T00:00:00Z"
        if condition == "software_receipt_window_rows":
            changes["claimed_signed_at"] = "2025-12-31T23:59:59Z"
        if condition == "software_receipt_historical_current":
            assert current_software_table is not None
            changes["snapshot_ref"] = dict(current_software_table.to_mapping())
        if condition in {
            "software_receipt_obligation_partial",
            "software_receipt_obligation_intrinsic",
        }:
            changes["claim_ids"] = _array(original_policy["required_claim_ids"])[:1]
        if condition in {
            "software_receipt_obligation_purpose",
            "software_receipt_obligation_global_purpose",
        }:
            changes["purpose"] = "human_review"
        ordinary_ref, ordinary_raw = software_manifest_receipt(
            _bytes(inputs["content_json"]),
            table=software_table,
            scope=base_ref,
            created_at=cast(str, acceptance_after["utc_lexeme"]),
            directory=tmp_path,
            limits=limits,
            statement_changes=changes,
            signing_suffix=b"wrong-whole-message"
            if condition in {"software_receipt_signature", "software_receipt_signature_rows"}
            else b"",
        )
        ordinary_envelopes = (ordinary_raw,)
        ordinary_receipt_refs = [dict(ordinary_ref.to_mapping())]
        if condition == "software_receipt_ref":
            ordinary_receipt_refs = [acceptance_receipts[0]]
        if condition == "software_receipt_count":
            ordinary_receipt_refs = []
    if protected_math:
        assert ordinary_certificate is not None
        ordinary_ref, ordinary_raw = protected_math_receipt(
            condition,
            _bytes(inputs["content_json"]),
            snapshot=protected_snapshot,
            certificate=ordinary_certificate,
            scope=base_ref,
            created_at=_text(acceptance_after["utc_lexeme"]),
            directory=tmp_path,
            limits=limits,
        )
        ordinary_envelopes = (ordinary_raw,)
        ordinary_receipt_refs = [dict(ordinary_ref.to_mapping())]
    if (
        protected_reproduction
        or protected_use_receipt
        or condition
        in {
            "protected_ordinary_matching",
            "cli_protected_ordinary_matching",
        }
    ):
        assert ordinary_certificate is not None
        ordinary_ref, ordinary_raw = protected_manifest_receipt(
            _bytes(inputs["content_json"]),
            snapshot=protected_snapshot,
            certificate=ordinary_certificate,
            scope=base_ref,
            created_at="2026-01-01T00:00:00Z"
            if condition == "protected_use_snapshot_after_signature"
            else _text(acceptance_after["utc_lexeme"]),
            directory=tmp_path,
            limits=limits,
        )
        ordinary_envelopes = (ordinary_raw,)
        ordinary_receipt_refs = [dict(ordinary_ref.to_mapping())]
    sample_accuracy = (
        4_000_000_000
        if condition in SOFTWARE_INTERVAL_CASES or condition in PROTECTED_USE_INTERVAL_CASES
        else 1_000_000_000
    )
    before, raw_before = _sample(tmp_path, accuracy_radius_ns=sample_accuracy)
    if protected_use_reason is not None:
        source_path = tmp_path / _text(protected_use_reason["subject_digest"])[7:]
        window = _object(json.loads(source_path.read_bytes()))
        if "lifetime" in window:
            window = _object(window["lifetime"])
        lower_field = "issued_at" if "issued_at" in window else "not_before"
        upper_field = "expires_at" if "expires_at" in window else "not_after"
        center = Utc(before["utc_lexeme"])
        assert Utc(window[lower_field]).compare(center) <= 0
        assert window[upper_field] is None or center.compare(Utc(window[upper_field])) < 0
    if condition == "clock_subject_first_coordinate":
        before = {**before, "utc_epoch_ns": str(int(_text(before["utc_epoch_ns"])) + 1)}
    first = _stored(
        {
            "format_version": "autonomous-evaluation-clock-first-sample-source-r4",
            "request_id": "actual-source-subject:" + str(time.monotonic_ns()),
            "utc_lexeme": before["utc_lexeme"],
            "utc_epoch_ns": before["utc_epoch_ns"],
            "monotonic_ticks": before["monotonic_ticks"],
            "boot_domain_ref": dict(boot.to_mapping()),
            "verification_controller_identity_ref": ref,
            "process_start_identity_ref": dict(process.to_mapping()),
            "source_profile_ref": dict(profile_ref.to_mapping()),
            "raw_sample_ref": dict(raw_before.to_mapping()),
        },
        tmp_path,
    )
    first_value = _object(json.loads((tmp_path / first.digest[7:]).read_bytes()))
    binding = {
        "format_version": "emt-clock-entry-binding-source-r4",
        "request_id": first_value["request_id"],
        "first_sample_source_ref": dict(first.to_mapping()),
        "source_profile_ref": dict(profile_ref.to_mapping()),
        "boot_domain_ref": dict(boot.to_mapping()),
        "verification_controller_identity_ref": ref,
        "process_start_identity_ref": dict(process.to_mapping()),
        "entry_observation_method_ref": dict(method.to_mapping()),
        "implementation_environment_ref": dict(environment.to_mapping()),
    }
    caller = (
        DelegatedTrustContextV2(
            "EMT_CALLER_TRUST_DELEGATED_V2",
            "protected_delegated",
            "current",
            Utc(before["utc_lexeme"]),
            cast(Mapping[str, FrozenJson], binding),
            independent_root_selection_ref=declared,
            root_grant_ref=protected_grant,
            current_authority_snapshot_ref=protected_snapshot,
            accepted_authority_sequence_floor="1",
            control_envelopes=(),
            authority_control_selection_ref=protected_selection,
        )
        if custody_class == "protected_delegated"
        else SoftwareTrustContextV2(
            "EMT_CALLER_TRUST_SOFTWARE_V2",
            "software_local_unprotected",
            "historical"
            if condition == "software_historical"
            or condition.startswith("software_receipt_historical")
            else "current",
            Utc(before["utc_lexeme"]),
            cast(Mapping[str, FrozenJson], binding),
            current_software_table,
            "2" if condition.startswith("software_receipt_historical") else "1",
            archived_software_authorization_ref=software_table
            if condition == "software_historical"
            or condition.startswith("software_receipt_historical")
            else None,
        )
        if current_software_table is not None
        else UnsignedTrustContextV2(
            "EMT_CALLER_TRUST_UNSIGNED_V2",
            "unsigned_declared",
            "current",
            Utc(before["utc_lexeme"]),
            cast(Mapping[str, FrozenJson], binding),
        )
    )
    context = _object(_mapping(caller))
    if isinstance(caller, SoftwareTrustContextV2) and caller.evaluation_mode == "current":
        del context["archived_software_authorization_ref"]
    if isinstance(caller, DelegatedTrustContextV2) and caller.evaluation_mode == "current":
        del context["archived_authority_snapshot_ref"]
    if condition == "context":
        context["clock_entry_binding"] = {
            **_object(context["clock_entry_binding"]),
            "request_id": "another-real-input-request",
        }
    context_ref = _stored(context, tmp_path)
    registry_ref = _stored(inputs["registry"], tmp_path)
    limits_ref = _stored(
        {**_object(inputs["limits"]), "max_graph_depth": limits.max_graph_depth + 1}
        if condition == "clock_subject_limits"
        else inputs["limits"],
        tmp_path,
    )
    content_raw = _bytes(inputs["content_json"])
    content_ref = reference_bytes(
        content_raw,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=_text(inputs["schema_id"]),
        limits=limits,
    )
    subject_ref = _stored(
        {
            "format_version": "autonomous-evaluation-clock-subject-source-r4",
            "request_id": first_value["request_id"],
            "content_ref": dict(
                (
                    base_ref if condition in {"content", "software_content"} else content_ref
                ).to_mapping()
            ),
            "ordered_receipt_refs": ordinary_receipt_refs,
            "schema_registry_ref": dict(registry_ref.to_mapping()),
            "whole_trust_context_ref": dict(context_ref.to_mapping()),
            "whole_limits_ref": dict(limits_ref.to_mapping()),
            "whole_base_policy_ref": dict(base_ref.to_mapping()),
            "verification_controller_identity_ref": ref,
            "custody_class": custody_class,
            "first_sample_source_ref": dict(first.to_mapping()),
        },
        tmp_path,
    )
    synchronization_ref, _ = _synchronization(tmp_path)
    after, _ = _sample(tmp_path, accuracy_radius_ns=sample_accuracy)
    use, raw_use = _sample(tmp_path, accuracy_radius_ns=sample_accuracy)
    use_method = clock_use_input(
        tmp_path,
        condition=condition,
        identity=declared,
        environment=environment,
        boot=boot,
        custody_class=custody_class,
        profile=profile_ref,
        subject=subject_ref,
        first=first,
        uncertainty=uncertainty_method,
        drift=drift_method,
        ntp=synchronization_ref,
        before=before,
        after=after,
        use=use,
        request_id=_text(first_value["request_id"]),
    )
    use_method_value = _object(json.loads((tmp_path / use_method.digest[7:]).read_bytes()))
    raw_use = BlobRef.from_mapping(_object(use_method_value["use_raw_ref"]))
    witness = _stored(
        {
            "format_version": "autonomous-evaluation-clock-witness-source-r4",
            "subject_ref": dict(subject_ref.to_mapping()),
            "request_id": first_value["request_id"],
            "caller_utc_lexeme": before["utc_lexeme"],
            "profile_ref": dict(profile_ref.to_mapping()),
            "acceptance_body_ref": dict(acceptance.to_mapping()),
            "acceptance_statement_ref": acceptance_statement,
            "ordered_acceptance_receipt_refs": acceptance_receipts,
            "controller_identity_ref": ref,
            "observer_identity_ref": ref,
            "raw_synchronization_refs": [dict(synchronization_ref.to_mapping())],
            "monotonic_domain_ref": dict(boot.to_mapping()),
            "ticks_per_second": {**rate, "numerator": "1"} if condition == "rate" else rate,
            "before": {**before, "clock_sample_raw_ref": dict(raw_use.to_mapping())}
            if condition == "clock_subject_first_raw"
            else before,
            "after": after,
            "use_sample_raw_ref": dict(raw_use.to_mapping()),
            "use_monotonic_ticks": str(
                int(cast(str, use["monotonic_ticks"]))
                + (60000000000 if condition == "entry_order" else 0)
            ),
            "event_utc_lower_ns": str(
                int(cast(str, before["utc_epoch_ns"]))
                - (0 if condition == "clock_subject_capture_bounds" else sample_accuracy + 2000)
            ),
            "event_utc_upper_ns": str(
                int(cast(str, after["utc_epoch_ns"])) + sample_accuracy + 2000
            ),
            "use_utc_upper_ns": str(
                int(cast(str, after["utc_epoch_ns"]))
                + int(cast(str, use["monotonic_ticks"]))
                - int(cast(str, after["monotonic_ticks"]))
                + sample_accuracy
                + 2000
                + int(_text(use_method_value["use_error_bound_ns"]))
            ),
            "assurance": "captured_unqualified_until_full_predicate_passes",
            "custody_class": custody_class,
            "identity_class": "declared_by_launcher_under_the_seat_account",
            "whole_conditions_and_limitations_ref": ref,
            "holdover_and_use_error_derivation_ref": dict(use_method.to_mapping()),
            "complete_authorization_obligations_ref": ref,
            "use_error_bound_ns": use_method_value["use_error_bound_ns"],
            "first_sample_source_ref": dict(first.to_mapping()),
            "evaluation_origin": "first_actual_before_sample_frozen_before_whole_context",
        },
        tmp_path,
    )
    final = {
        **base,
        "required_evaluation_time_qualification": {
            **_object(base["required_evaluation_time_qualification"]),
            "clock_qualification_ref": dict(witness.to_mapping()),
        },
    }
    if condition == "policy":
        final["required_principal"] = "different-explicit-local-principal"
    final_ref = _stored(final, tmp_path)
    policy_value = _successor_policy(final_ref)
    policy_value["whole_conditions_and_limitations_ref"] = ref
    if condition == "cm_whole_conditions":
        policy_value["whole_conditions_and_limitations_ref"] = dict(base_ref.to_mapping())
    if software_table is not None:
        policy_value.update(
            profile_class=custody_class, authority_rule_ref=dict(base_ref.to_mapping())
        )
    if custody_class == "protected_delegated":
        policy_value["root_grant_ref"] = dict(protected_grant.to_mapping())
        policy_value["authority_rule_ref"] = dict(protected_rule.to_mapping())
    policy_value.update(rule_fields)
    signature_ref, rule_error_kind, rule_expected = signature_rule_input(
        condition,
        tmp_path,
        base_ref=base_ref,
        conditions_ref=BlobRef.from_mapping(
            _object(policy_value["whole_conditions_and_limitations_ref"])
        ),
        content_ref=content_ref,
        content_raw=content_raw,
        required_claim_ids=[_text(x) for x in _array(original_policy["required_claim_ids"])],
        required_purposes=[_text(x) for x in _array(original_policy["required_purposes"])],
        profile_class=custody_class,
        limits=limits,
    )
    policy_value["signature_obligation_rule_ref"] = dict(signature_ref.to_mapping())
    policy_ref = _stored(
        policy_value,
        tmp_path,
        schema_id="evidence_manifest_toolkit.authority_policy.v2",
    )
    for path in tmp_path.iterdir():
        if path.is_file():
            population["sha256:" + path.name + "|raw_bytes"] = path
            population["sha256:" + path.name + "|jcs_content"] = path
    content_path = tmp_path / "actual-content"
    content_path.write_bytes(content_raw)
    population[content_ref.digest + "|jcs_content"] = content_path
    for entry in registry.entries:
        path = tmp_path / entry.schema_ref.digest[7:]
        path.write_bytes(entry.schema_bytes)
        population[entry.schema_ref.digest + "|" + entry.schema_ref.digest_basis] = path
    matching = (
        (condition in PROTECTED_USE_MATCHING_CASES)
        or condition.endswith(("_one_full_row", "_year_zero_lower"))
        or condition
        in {
            "matching",
            "protected_ordinary_matching",
            "cli_protected_ordinary_matching",
            "software",
            "software_historical",
            "software_receipt",
            "software_receipt_lower",
            "software_receipt_historical",
            "sig_exception",
            "cli_sig_exception",
            "sig_base_jcs",
            "sig_provenance_jcs",
            "sig_exception_empty",
        }
    )
    error_type = (
        ReferenceUnavailable
        if rule_error_kind == "unavailable"
        else ConfigurationError
        if matching or rule_error_kind == "configuration"
        else InputRefused
    )
    method_expected = clock_method_expected(
        condition,
        drift=drift_method,
        uncertainty=uncertainty_method,
        use=use_method,
        policy=policy_ref,
        profile=profile_ref,
        directory=tmp_path,
    )
    if method_expected is not None:
        method_kind, method_reason = method_expected
        error_type = (
            ConfigurationError
            if method_kind == "configuration"
            else ReferenceUnavailable
            if method_kind == "unavailable"
            else InputRefused
        )
    annual_expected = clock_annual_method_expected(
        condition,
        uncertainty=uncertainty_method,
        policy=policy_ref,
        content=content_ref,
        directory=tmp_path,
    )
    if annual_expected is not None:
        error_type = (
            ConfigurationError
            if annual_expected[0] == "configuration"
            else ReferenceUnavailable
            if annual_expected[0] == "unavailable"
            else InputRefused
        )
    acceptance_expected = clock_acceptance_expected(
        condition, acceptance=acceptance, policy=policy_ref, content=content_ref, directory=tmp_path
    )
    if acceptance_expected is not None:
        error_type = (
            ConfigurationError if acceptance_expected[0] == "configuration" else InputRefused
        )
    obligation_reason = obligation_expected(condition, content=content_ref, inputs=inputs)
    if obligation_reason is not None:
        error_type = ConfigurationError if obligation_reason[0] == "configuration" else InputRefused
    if reproduction_expected is not None:
        error_type = (
            ConfigurationError
            if reproduction_expected[0] == "configuration"
            else ReferenceUnavailable
            if reproduction_expected[0] == "unavailable"
            else InputRefused
        )
    math_reason = None
    if protected_math:
        assert ordinary_certificate is not None
        math_reason = protected_math_expected(
            condition, receipt=ordinary_ref, certificate=ordinary_certificate
        )
        error_type = (
            ConfigurationError if math_reason["code"] == "configuration_error" else InputRefused
        )
    if protected_use_reason is not None:
        error_type = InputRefused
    if native_expected is not None:
        error_type = (
            ConfigurationError
            if native_expected[0] == "configuration"
            else ReferenceUnavailable
            if native_expected[0] == "unavailable"
            else InputRefused
        )
    if condition.startswith("cli_"):
        exit_code, report_path = invoke_rule_cli(
            tmp_path,
            population=population,
            schema_id=_text(inputs["schema_id"]),
            content_raw=content_raw,
            registry=inputs["registry"],
            limits=inputs["limits"],
            policy={
                "policy_ref": dict(policy_ref.to_mapping()),
                "required_claim_ids": original_policy["required_claim_ids"],
                "required_purposes": original_policy["required_purposes"],
            },
            trust=context,
            envelopes=ordinary_envelopes,
        )
        captured = capfd.readouterr()
        error = _object(json.loads(captured.out))
        actual_reason = _object(_array(error["reasons"])[0])
        assert captured.out.encode() == _transport(
            {"operation": "verify", "reasons": [actual_reason]}
        )
        assert captured.err == "" and not report_path.exists()
        assert exit_code == (
            3
            if rule_error_kind == "unavailable"
            or (method_expected is not None and method_expected[0] == "unavailable")
            or (annual_expected is not None and annual_expected[0] == "unavailable")
            or (reproduction_expected is not None and reproduction_expected[0] == "unavailable")
            or (native_expected is not None and native_expected[0] == "unavailable")
            else 4
            if error_type is ConfigurationError
            else 2
        )
    else:
        resolver = _FileResolver(population)
        with pytest.raises(error_type) as caught:
            verify(
                content_raw,
                schema_id=_text(inputs["schema_id"]),
                envelopes=ordinary_envelopes,
                registry=registry,
                resolver=resolver,
                limits=limits,
                policy=VerificationPolicy(
                    policy_ref,
                    tuple(_text(x) for x in _array(original_policy["required_claim_ids"])),
                    tuple(
                        cast(Purpose, _text(x))
                        for x in _array(original_policy["required_purposes"])
                    ),
                ),
                trust=caller,
            )
        actual_reason = asdict(caught.value.reason)
        if resolver_calls is not None:
            resolver_calls.extend(resolver.calls)
        if (
            native_expected is not None
            and native_expected[0] == "configuration"
            and (native_expected[1]["pointer"] == "/trust")
        ):
            requested = {reference for reference, _ in resolver.calls}
            for parent_field, binding_fields in (
                (
                    "identity_rule_ref",
                    ("launcher_or_observer_procedure_ref", "actual_key_possession_rule_ref"),
                ),
                (
                    "validation_rule_ref",
                    ("run_and_seal_before_comparison_procedure_ref", "comparison_rule_ref"),
                ),
            ):
                parent_ref = BlobRef.from_mapping(_object(rule_fields[parent_field]))
                parent_value = _object(json.loads((tmp_path / parent_ref.digest[7:]).read_bytes()))
                for binding_field in binding_fields:
                    binding_ref = BlobRef.from_mapping(_object(parent_value[binding_field]))
                    binding_value = _object(
                        json.loads((tmp_path / binding_ref.digest[7:]).read_bytes())
                    )
                    assert binding_ref in requested
                    assert {
                        BlobRef.from_mapping(_object(binding_value[field]))
                        for field in (
                            "implementation_ref",
                            "implementation_environment_ref",
                            "implementation_qualification_ref",
                            "semantic_law_ref",
                        )
                    } <= requested
        if annual_expected is not None:
            requested = {reference for reference, _ in resolver.calls}
            assert uncertainty_method in requested
            parent = _object(json.loads((tmp_path / uncertainty_method.digest[7:]).read_bytes()))
            annual_reference = BlobRef.from_mapping(_object(parent["annual_derivation_ref"]))
            if condition.removeprefix("cli_") not in {
                "annual_source_method_media",
                "annual_source_method_basis",
                "annual_source_method_schema",
            }:
                assert annual_reference in requested
        if condition == "software_reproduction_body_missing_no_schema":
            declared_content = _object(json.loads(content_raw))
            declared_claim = _object(_array(declared_content["claims"])[1])
            record_reference = BlobRef.from_mapping(
                _object(_object(declared_claim["validation"])["record_ref"])
            )
            record_value = _object(
                json.loads((tmp_path / record_reference.digest[7:]).read_bytes())
            )
            body_reference = BlobRef.from_mapping(_object(record_value["body_ref"]))
            assert body_reference not in {reference for reference, _ in resolver.calls}
        if condition == "reproduction_history_validation_within_depth_no_schema":
            from tests.domain.reproduction_history_depth_inputs import history_source_refs

            history_refs = history_source_refs(content_raw, tmp_path, steps=7)
            assert set(history_refs) <= {reference for reference, _ in resolver.calls}
            (tmp_path / "actual-within-depth-sources.json").write_text(
                json.dumps(
                    {
                        "actual_reason": actual_reason,
                        "required_sources": [
                            dict(reference.to_mapping()) for reference in history_refs
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
        if condition == "protected_unprotected_scope":
            requested = {reference for reference, _ in resolver.calls}
            assert {signature_ref, uncertainty_method, drift_method, use_method} <= requested
        if full_record_obligation or (
            reproduction_expected is not None
            and (
                reproduction_expected[0] == "configuration"
                or condition
                in {
                    "software_receipt_reproduction_match",
                    "software_receipt_reproduction_native_matching",
                }
            )
        ):
            declared_content = _object(json.loads(content_raw))
            declared_claim = _object(_array(declared_content["claims"])[1])
            record_reference = BlobRef.from_mapping(
                _object(_object(declared_claim["validation"])["record_ref"])
            )
            record_value = _object(
                json.loads((tmp_path / record_reference.digest[7:]).read_bytes())
            )
            body_reference = BlobRef.from_mapping(_object(record_value["body_ref"]))
            body_value = _object(json.loads((tmp_path / body_reference.digest[7:]).read_bytes()))
            required_sources = {
                record_reference,
                body_reference,
                signature_ref,
                uncertainty_method,
                drift_method,
                use_method,
                *(
                    BlobRef.from_mapping(_object(body_value[field]))
                    for field in (
                        "producer_binding_ref",
                        "runner_binding_ref",
                        "subject_ref",
                        "whole_policy_ref",
                    )
                ),
            }
            if record_value["foreign_run_identity_ref"] is not None:
                required_sources.add(
                    BlobRef.from_mapping(_object(record_value["foreign_run_identity_ref"]))
                )
            assert required_sources <= {reference for reference, _ in resolver.calls}
        if isinstance(caught.value, ReferenceUnavailable):
            missing_ref = signature_ref
            if annual_expected is not None and annual_expected[2] is not None:
                missing_ref = annual_expected[2]
            if reproduction_expected is not None and reproduction_expected[2] is not None:
                missing_ref = reproduction_expected[2]
            if native_expected is not None and native_expected[2] is not None:
                missing_ref = native_expected[2]
            if condition == "sig_provenance_missing":
                rule_body = _object(json.loads((tmp_path / signature_ref.digest[7:]).read_bytes()))
                missing_ref = BlobRef.from_mapping(_object(_array(rule_body["provenance_refs"])[0]))
            if condition in {"cm_provenance_missing", "cm_rate_missing"}:
                drift_body = _object(json.loads((tmp_path / drift_method.digest[7:]).read_bytes()))
                missing_value = (
                    _array(drift_body["provenance_refs"])[0]
                    if condition == "cm_provenance_missing"
                    else drift_body["rate_source_ref"]
                )
                missing_ref = BlobRef.from_mapping(_object(missing_value))
            if condition == "cm_provenance_descendant":
                drift_body = _object(json.loads((tmp_path / drift_method.digest[7:]).read_bytes()))
                provenance = _object(_array(drift_body["provenance_refs"])[0])
                manifest = _object(
                    json.loads((tmp_path / _text(provenance["digest"])[7:]).read_bytes())
                )
                missing_ref = BlobRef.from_mapping(_object(manifest["payload_ref"]))
            assert caught.value.reference == missing_ref
    expected: dict[str, object] = {
        "code": "configuration_error" if matching else "policy_unavailable",
        "subject_digest": None if matching else policy_ref.digest,
        "claim_id": None,
        "pointer": "/trust"
        if matching
        else "/required_evaluation_time_qualification/clock_qualification_ref",
        "detail": "Invalid local configuration."
        if matching
        else "The required evaluation-time qualification is unavailable.",
    }
    if condition == "clock_subject_first_coordinate":
        expected.update(subject_digest=witness.digest, pointer="/before/utc_epoch_ns")
    if condition == "software_receipt_ref":
        expected.update(
            code="reference_mismatch",
            subject_digest=subject_ref.digest,
            pointer="/ordered_receipt_refs/0",
            detail="Reference bytes conflict.",
        )
    if condition.removeprefix("cli_").startswith("software_receipt") and condition not in {
        "software_receipt",
        "software_receipt_ref",
        "software_receipt_count",
        "software_receipt_lower",
        "software_receipt_historical",
    }:
        expected.update(
            code="scope_missing"
            if field
            in {
                "content_digest",
                "content_byte_length",
                "authorizing_state_ref",
                "authorization_ref",
                "snapshot_ref",
                "scope_ref",
                "claim_ids",
            }
            else "key_revoked"
            if condition == "software_receipt_revocation"
            else "invalid_signature"
            if condition in {"software_receipt_signature", "software_receipt_signature_rows"}
            else "invalid_delegation",
            subject_digest=ordinary_ref.digest,
            pointer="/signature"
            if condition in {"software_receipt_signature", "software_receipt_signature_rows"}
            else "/statement/"
            + ("claim_ids/0" if field == "claim_ids" else field or "signer_key_id"),
            detail="The software statement signature is invalid."
            if condition in {"software_receipt_signature", "software_receipt_signature_rows"}
            else "Software statement does not match its independently selected source or target.",
        )
        if condition == "software_receipt_purpose":
            expected["pointer"] = "/statement/signer_key_id"
    if rule_expected is not None:
        expected = dict(rule_expected)
        if expected["subject_digest"] is None and rule_error_kind != "unavailable":
            expected["subject_digest"] = policy_ref.digest
    if method_expected is not None:
        expected = method_reason
    if acceptance_expected is not None:
        expected = acceptance_expected[1]
    if annual_expected is not None:
        expected = annual_expected[1]
    if obligation_reason is not None:
        expected = obligation_reason[1]
    if reproduction_expected is not None:
        expected = reproduction_expected[1]
    if native_expected is not None:
        expected = native_expected[1]
    if math_reason is not None:
        expected = math_reason
    if condition in SOFTWARE_INTERVAL_CASES:
        expected = (
            {
                "code": "configuration_error",
                "subject_digest": None,
                "claim_id": None,
                "pointer": "/trust",
                "detail": "Invalid local configuration.",
            }
            if condition.endswith(("_one_full_row", "_year_zero_lower"))
            else {
                "code": "invalid_delegation",
                "subject_digest": ordinary_ref.digest,
                "claim_id": None,
                "pointer": "/statement/authorization_ref",
                "detail": "Software authorization does not cover the complete verification interval.",
            }
        )
    if protected_use_reason is not None:
        expected = protected_use_reason
    if condition == "protected_control_base":
        expected = {
            "code": "policy_unavailable",
            "subject_digest": policy_ref.digest,
            "claim_id": None,
            "pointer": "/authority_rule_ref",
            "detail": "Protected control rule sources conflict.",
        }
    if condition == "reproduction_history_validation_depth_no_schema":
        allowed = expected["subject_digest"]
        assert isinstance(allowed, tuple) and actual_reason["subject_digest"] in allowed
        (tmp_path / "actual-depth-refusal.json").write_text(
            json.dumps(
                {
                    "actual_reason": actual_reason,
                    "actual_max_graph_depth": limits.max_graph_depth,
                    "independent_depth_frontier": allowed,
                },
                indent=2,
            )
            + "\n"
        )
        expected = {**expected, "subject_digest": actual_reason["subject_digest"]}
    assert actual_reason == expected
    if rule_expected is not None and rule_expected["code"] == "policy_unavailable":
        assert actual_reason["subject_digest"] == signature_ref.digest
        rule_body = _object(json.loads((tmp_path / signature_ref.digest[7:]).read_bytes()))
        location = _text(actual_reason["pointer"])
        assert location.startswith("/") and location[1:] in rule_body
    assert all(path.read_bytes() == raw for path, raw in originals.items())
