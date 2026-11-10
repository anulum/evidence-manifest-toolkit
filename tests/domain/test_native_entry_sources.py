# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — real public native entry and original source failures

"""Exercise actual native entry binding through public verify without Clock admission."""

import ctypes
import hashlib
import json
import os
import sys
import sysconfig
from dataclasses import asdict, replace
from importlib.resources import files
from pathlib import Path
from typing import Literal, cast

import pytest
from tests.domain.method_rule_inputs import method_rule_inputs
from tests.domain.protected_control_inputs import protected_control_inputs
from tests.domain.protected_state_inputs import protected_state_inputs
from tests.domain.test_cli_evidence_sources import _source, _transport
from tests.domain.test_policy_selection_sources import _successor_policy
from tests.domain.test_software_sources import _software_table
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_successor_trust import _callers, _sources
from tests.domain.test_verification_report_sources import (
    _array,
    _bytes,
    _FileResolver,
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
    VerificationPolicy,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_CLOCK = "/required_evaluation_time_qualification/clock_qualification_ref"


def _native_source(raw: bytes, directory: Path, media_type: str) -> BlobRef:
    """Store whole independently prepared native input bytes under their actual identity.

    Parameters
    ----------
    raw : bytes
        Entire genuine source or explicit fault input, unchanged.
    directory : Path
        Owned flat source directory.
    media_type : str
        Exact selected raw source format.

    Returns
    -------
    BlobRef
        Entire original raw reference, without an invented schema assertion.
    """
    digest = hashlib.sha256(raw).hexdigest()
    (directory / digest).write_bytes(raw)
    return BlobRef("sha256:" + digest, str(len(raw)), media_type, "raw_bytes")


@pytest.mark.parametrize("profile_index", (0, 1, 2))
@pytest.mark.parametrize("mode", ("current", "historical"))
@pytest.mark.parametrize(
    "condition",
    (
        "match",
        "boot_missing",
        "process_missing",
        "environment_missing",
        "boot_conflict",
        "process_conflict",
        "environment_conflict",
        "environment_malformed",
        "unknown_method",
        "source_metadata",
        "shared_budget",
    ),
)
def test_actual_native_entry_preserves_whole_source_failures_and_all_caller_classes(
    condition: str, mode: Literal["current", "historical"], profile_index: int, tmp_path: Path
) -> None:
    """Bind actual installed code and native identity before the pending V2 state boundary.

    Parameters
    ----------
    condition : str
        Real matching host sources, absent original source, conflicting input, malformed
        full environment, unknown method, wrong metadata or shared acquisition quota.
    mode : {"current", "historical"}
        One original caller evaluation selection; both complete modes remain parametrized.
    profile_index : int
        One original unsigned/software/delegated class; all three remain parametrized.
    tmp_path : Path
        Owned whole input records. No native observation or private runtime helper is mocked.

    Notes
    -----
    Matching four entry sources confers no Clock or authority acceptance. The selected
    operational policy deliberately lacks its Clock witness. All three current/historical
    public callers must retain the actual missing-Clock refusal, with no success report.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    bounds = _object(inputs["limits"])
    limits = Limits(**cast(dict[str, int], bounds))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    original = {path: path.read_bytes() for path in population.values()}
    declaration = _object(inputs["policy"])
    legacy_ref = BlobRef.from_mapping(_object(declaration["policy_ref"]))
    ordinary = _object(json.loads(population[legacy_ref.digest + "|raw_bytes"].read_bytes()))
    for field in ("actual_accepted_configuration", "source_chain_ref"):
        ordinary.pop(field)
    ordinary.update(
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
    ordinary_ref = _stored(ordinary, tmp_path)
    environment = {
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
    }
    raw_sources = {
        "entry_observation_method_ref": files("evidence_manifest_toolkit")
        .joinpath("_native_entry_method.json")
        .read_bytes(),
        "boot_domain_ref": Path("/proc/sys/kernel/random/boot_id").read_bytes(),
        "process_start_identity_ref": Path("/proc/self/stat").read_bytes(),
        "implementation_environment_ref": _transport(environment),
    }
    fault_field = {
        "boot_conflict": "boot_domain_ref",
        "process_conflict": "process_start_identity_ref",
        "environment_conflict": "implementation_environment_ref",
        "environment_malformed": "implementation_environment_ref",
        "unknown_method": "entry_observation_method_ref",
    }.get(condition)
    if fault_field is not None:
        raw_sources[fault_field] = {
            "boot_conflict": b"different-boot\n",
            "process_conflict": b"1 (original process) " + b"0 " * 20,
            "environment_conflict": _transport({**environment, "python_executable": "/other"}),
            "environment_malformed": b"{",
            "unknown_method": b"{}",
        }[condition]
    binding, references, originals = _sources()
    native = {
        name: _native_source(
            raw,
            tmp_path,
            "application/json"
            if name in {"entry_observation_method_ref", "implementation_environment_ref"}
            else "text/plain",
        )
        for name, raw in raw_sources.items()
    }
    if condition == "source_metadata":
        native["boot_domain_ref"] = replace(native["boot_domain_ref"], media_type="text/html")
    for name, reference in native.items():
        binding[name] = dict(reference.to_mapping())
    missing = {
        "boot_missing": "boot_domain_ref",
        "process_missing": "process_start_identity_ref",
        "environment_missing": "implementation_environment_ref",
    }.get(condition)
    if missing is not None:
        (tmp_path / native[missing].digest[7:]).unlink()
    population[ordinary_ref.digest + "|raw_bytes"] = tmp_path / ordinary_ref.digest[7:]
    population.update(
        {
            reference.digest + "|raw_bytes": tmp_path / reference.digest[7:]
            for reference in native.values()
        }
    )
    caller = _callers(binding, references, mode)[profile_index]
    if isinstance(caller, SoftwareTrustContextV2):
        table = _software_table(
            ordinary_ref, tmp_path, sequence=caller.accepted_authorization_sequence_floor
        )
        population[table.digest + "|raw_bytes"] = tmp_path / table.digest[7:]
        caller = replace(
            caller,
            software_authorization_ref=table,
            archived_software_authorization_ref=table if mode == "historical" else None,
        )
    selected = _successor_policy(ordinary_ref)
    selected["profile_class"] = caller.profile_class
    if caller.profile_class != "unsigned_declared":
        selected["authority_rule_ref"] = dict(ordinary_ref.to_mapping())
    if isinstance(caller, DelegatedTrustContextV2):
        selected["root_grant_ref"] = dict(caller.root_grant_ref.to_mapping())
        rule, selection, controls, control_objects = protected_control_inputs(
            ordinary_ref, tmp_path
        )
        caller = replace(
            caller,
            independent_root_selection_ref=ordinary_ref,
            authority_control_selection_ref=selection,
            control_envelopes=controls,
        )
        grant, snapshot, state_objects = protected_state_inputs(
            ordinary_ref,
            rule,
            ordinary_ref,
            tmp_path,
            sequence=caller.accepted_authority_sequence_floor,
        )
        caller = replace(
            caller,
            root_grant_ref=grant,
            current_authority_snapshot_ref=snapshot,
            archived_authority_snapshot_ref=snapshot if mode == "historical" else None,
        )
        selected["root_grant_ref"] = dict(grant.to_mapping())
        population.update(state_objects)
        selected["authority_rule_ref"] = dict(rule.to_mapping())
        population.update(control_objects)
    rule_fields, rule_objects = method_rule_inputs(
        ordinary_ref, tmp_path, profile_class=caller.profile_class
    )
    selected.update(rule_fields)
    population.update(rule_objects)
    selected_ref = _stored(
        selected, tmp_path, schema_id="evidence_manifest_toolkit.authority_policy.v2"
    )
    population[selected_ref.digest + "|raw_bytes"] = tmp_path / selected_ref.digest[7:]
    resolver = _FileResolver(population)
    actual_limits = (
        replace(limits, max_reference_count=1) if condition == "shared_budget" else limits
    )
    with pytest.raises((ConfigurationError, InputRefused, ReferenceUnavailable)) as caught:
        verify(
            _bytes(inputs["content_json"]),
            schema_id=_text(inputs["schema_id"]),
            envelopes=(),
            registry=registry,
            resolver=resolver,
            limits=actual_limits,
            policy=VerificationPolicy(
                selected_ref,
                tuple(_text(value) for value in _array(declaration["required_claim_ids"])),
                ("evidence",),
            ),
            trust=caller,
        )
    failure = caught.value
    if missing is not None:
        assert isinstance(failure, ReferenceUnavailable)
        assert failure.reference == native[missing]
        assert resolver.calls[-1][0] == native[missing]
    elif condition == "shared_budget":
        assert isinstance(failure, InputRefused) and failure.reason.code == "limit_exceeded"
    else:
        assert asdict(failure.reason) == {
            "code": "invalid_json"
            if condition == "environment_malformed"
            else "policy_unavailable",
            "subject_digest": native["implementation_environment_ref"].digest
            if condition == "environment_malformed"
            else selected_ref.digest,
            "claim_id": None,
            "pointer": "" if condition == "environment_malformed" else _CLOCK,
            "detail": "Input is not valid strict JSON."
            if condition == "environment_malformed"
            else "The required evaluation-time qualification is unavailable.",
        }
    if condition in {
        "match",
        "boot_conflict",
        "process_conflict",
        "environment_conflict",
        "environment_malformed",
    }:
        observed = [reference for reference, _ in resolver.calls]
        assert (
            observed.index(native["boot_domain_ref"])
            < observed.index(native["process_start_identity_ref"])
            < observed.index(native["implementation_environment_ref"])
        )
    assert all(path.read_bytes() == raw for path, raw in (original | originals).items())
