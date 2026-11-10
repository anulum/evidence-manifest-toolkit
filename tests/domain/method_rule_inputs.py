# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete unqualified method-rule input sources

"""Prepare whole private rule carriers without authenticating their opaque procedure sources."""

import ctypes
import hashlib
import json
import os
import sys
import sysconfig
from importlib.resources import files
from pathlib import Path

from evidence_manifest_toolkit import BlobRef


def method_rule_inputs(
    earlier_source: BlobRef,
    directory: Path,
    *,
    profile_class: str,
    foreign: bool = False,
    launcher_implementation_bytes: bytes | None = None,
) -> tuple[dict[str, object], dict[str, Path]]:
    """Store complete actual private rules with disclosed unqualified source references.

    Parameters
    ----------
    earlier_source : BlobRef
        Whole already materialized earlier source used as an unqualified semantic law.
        Method declarations retain actual implementation/runtime bytes but their
        qualification is explicitly unavailable. Its bytes are NOT asserted to be
        qualified launcher, possession, comparison, foreign trust or execution evidence.
    directory : Path
        Owned real flat input directory.
    profile_class : str
        Explicit independently paired caller class, without authorizing that class.
    foreign : bool
        Whether to construct the optional whole foreign rule and declared trust reference.

    launcher_implementation_bytes : bytes or None
        Whole independently frozen source input for actual isolated installation faults.
        None reads the current whole descriptor; this never changes product behavior.

    Returns
    -------
    tuple
        Whole enclosing policy fields and exact real file-resolver population. No native
        helper/key/Clock/run/identity acceptance or live foreign service is manufactured.
    """
    population: dict[str, Path] = {}
    ref = dict(earlier_source.to_mapping())

    def store(value: dict[str, object]) -> BlobRef:
        """Retain complete actual raw JSON under its exact whole original identity.

        Parameters
        ----------
        value : dict
            Entire private source, including every opaque original procedure field.

        Returns
        -------
        BlobRef
            Whole raw reference with no fabricated public schema identifier.
        """
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        path = directory / digest
        path.write_bytes(raw)
        result = BlobRef("sha256:" + digest, str(len(raw)), "application/json", "raw_bytes")
        population[result.digest + "|raw_bytes"] = path
        return result

    implementation_raw = (
        files("evidence_manifest_toolkit").joinpath("_native_rule_bindings.py").read_bytes()
    )
    implementation_digest = hashlib.sha256(implementation_raw).hexdigest()
    implementation_path = directory / implementation_digest
    implementation_path.write_bytes(implementation_raw)
    implementation = BlobRef(
        "sha256:" + implementation_digest,
        str(len(implementation_raw)),
        "text/x-python",
        "raw_bytes",
    )
    population[implementation.digest + "|raw_bytes"] = implementation_path
    environment = store(
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
        }
    )
    qualification = store(
        {
            "qualification": "unavailable",
            "limitations": "Unqualified method declaration. No implementation, identity, "
            "key possession, Clock, custody, native execution or comparison is accepted.",
        }
    )
    common: dict[str, object] = {
        "method_version": "1",
        "implementation_ref": dict(implementation.to_mapping()),
        "implementation_environment_ref": dict(environment.to_mapping()),
        "implementation_qualification_ref": dict(qualification.to_mapping()),
        "semantic_law_ref": ref,
    }
    contract_raw = (
        files("evidence_manifest_toolkit")
        .joinpath("_schemas", "native_launch_source.json")
        .read_bytes()
    )
    contract_digest = hashlib.sha256(contract_raw).hexdigest()
    contract_path = directory / contract_digest
    contract_path.write_bytes(contract_raw)
    contract = BlobRef(
        "sha256:" + contract_digest, str(len(contract_raw)), "application/schema+json", "raw_bytes"
    )
    population[contract.digest + "|raw_bytes"] = contract_path
    installed_raw = (
        launcher_implementation_bytes
        if launcher_implementation_bytes is not None
        else files("evidence_manifest_toolkit")
        .joinpath("_native_launch_implementation.json")
        .read_bytes()
    )
    installed_digest = hashlib.sha256(installed_raw).hexdigest()
    installed_path = directory / installed_digest
    installed_path.write_bytes(installed_raw)
    installed = BlobRef(
        "sha256:" + installed_digest, str(len(installed_raw)), "application/json", "raw_bytes"
    )
    population[installed.digest + "|raw_bytes"] = installed_path
    launcher = store(
        {
            **common,
            "implementation_ref": dict(installed.to_mapping()),
            "record_contract_ref": dict(contract.to_mapping()),
            "vendor_source": "binding_declaration_with_optional_launcher_or_client_consistency",
            "key_source": "separate_raw_key_and_possession_method_only",
        }
    )
    possession = store(
        {
            **common,
            "challenge_issuer_rule_ref": ref,
            "receiver_method_ref": ref,
            "possession_scope": "seat_account",
        }
    )
    execution = store(
        {
            **common,
            "whole_request_selection_ref": ref,
            "executor_method_ref": ref,
            "output_seal_method_ref": ref,
            "release_method_ref": ref,
            "permitted_nonuse_classes": ["procedural_nonuse"],
        }
    )
    comparison = store(
        {
            **common,
            "comparison_algorithm_ref": ref,
            "whole_comparison_parameters_ref": ref,
            "outcome_mapping_ref": ref,
        }
    )

    identity = store(
        {
            "format_version": "emt-seat-identity-rule-source-r1",
            "custody_class": profile_class,
            "permitted_identity_classes": ["declared_by_launcher_under_the_seat_account"],
            "launcher_or_observer_procedure_ref": dict(launcher.to_mapping()),
            "client_catalogue_source_ref": None,
            "actual_key_possession_rule_ref": dict(possession.to_mapping()),
            "vendor_comparison_rule": "exact_accepted_vendor_identity_no_alias_or_case_repair",
            "key_comparison_rule": "actual_public_key_identity_equality_refuses_when_required",
            "required_claim_limitations_rule_ref": ref,
        }
    )
    validation = store(
        {
            "format_version": "emt-independent-validation-rule-source-r1",
            "profile_class": profile_class,
            "permitted_record_classes": [
                "unsigned_declared_reproduction"
                if profile_class == "unsigned_declared"
                else "software_local_reproduction"
                if profile_class == "software_local_unprotected"
                else "protected_native_seat_reproduction"
            ],
            "whole_subject_and_parent_reconstruction_rule_ref": ref,
            "independent_identity_policy_ref": dict(identity.to_mapping()),
            "run_and_seal_before_comparison_procedure_ref": dict(execution.to_mapping()),
            "comparison_rule_ref": dict(comparison.to_mapping()),
            "required_nonuse_classes": ["procedural_nonuse"],
            "required_time_binding_rule_ref": ref,
            "native_or_foreign_authorization_rule_ref": ref,
            "exact_claim_limitations_and_report_mapping_ref": ref,
        }
    )
    fields: dict[str, object] = {
        "identity_rule_ref": dict(identity.to_mapping()),
        "validation_rule_ref": dict(validation.to_mapping()),
        "foreign_rule_ref": None,
        "independent_foreign_trust_ref": None,
    }
    if foreign:
        foreign_rule = store(
            {
                "format_version": "emt-foreign-github-identity-rule-source-r1",
                "verifier_implementation_qualification_ref": ref,
                "complete_argv_and_field_mapping_rule_ref": ref,
                "expected_repository_and_immutable_ids_ref": ref,
                "expected_signer_workflow_and_commit_ref": ref,
                "expected_oidc_issuer": "https://token.actions.githubusercontent.com",
                "expected_runner_environment": "github-hosted",
                "expected_predicate_type": "https://slsa.dev/provenance/v1",
                "independent_trusted_root_acquisition_rule_ref": ref,
                "raw_artifact_subject_rule": "full_raw_artifact_sha256_and_length",
                "maximum_verifier_wall_time_ms": "1000",
                "maximum_verifier_stdout_bytes": "4096",
                "maximum_verifier_stderr_bytes": "4096",
                "verification_network_rule": "offline_pinned_bundle_and_root_inputs_only",
                "root_refresh_rule_ref": ref,
                "required_authenticated_field_mapping_ref": ref,
            }
        )
        fields.update(
            foreign_rule_ref=dict(foreign_rule.to_mapping()),
            independent_foreign_trust_ref=ref,
        )
    return fields, population
