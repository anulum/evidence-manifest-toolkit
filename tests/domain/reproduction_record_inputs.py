# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole unqualified reproduction source controls

"""Materialise complete record graphs without claiming a native independent execution."""

import base64
import json
from pathlib import Path
from typing import Literal, cast

from tests.domain.method_rule_inputs import method_rule_inputs
from tests.domain.native_access_prefix_inputs import NATIVE_ACCESS_PREFIX_CASES
from tests.domain.native_launch_inputs import (
    NATIVE_LAUNCH_CASES,
    native_launch_expected,
    native_launch_input,
)
from tests.domain.native_possession_inputs import POSSESSION_CASES, native_possession_input
from tests.domain.native_possession_method_inputs import possession_method_input
from tests.domain.native_run_inputs import NATIVE_RUN_CASES, native_run_input
from tests.domain.reproduction_method_policy_inputs import (
    METHOD_POLICY_CASES,
    comparison_policy_input,
)
from tests.domain.reproduction_native_inputs import native_validation_bundle
from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _array, _bytes, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits

type ReproductionOutcome = tuple[
    Literal["configuration", "refused", "unavailable"], dict[str, object], BlobRef | None
]

REPRODUCTION_RECORD_CASES = (
    "reproduction_match",
    *POSSESSION_CASES,
    *NATIVE_RUN_CASES,
    *NATIVE_ACCESS_PREFIX_CASES,
    *NATIVE_LAUNCH_CASES,
    "reproduction_record_subject",
    "reproduction_record_claim",
    "reproduction_record_policy",
    "reproduction_conditions",
    "reproduction_body_claim",
    "reproduction_custody",
    "reproduction_outcome",
    "reproduction_record_class",
    "reproduction_nonuse",
    "reproduction_runner_identity_class",
    "reproduction_producer_identity_class",
    "reproduction_producer_principal",
    "reproduction_runner_principal",
    "reproduction_same_vendor",
    "reproduction_same_principal",
    "reproduction_shared_key",
    "reproduction_key_pair_mismatch",
    "reproduction_distinct_key_refs",
    "reproduction_only_runner_key",
    "reproduction_foreign_source",
    "reproduction_foreign_not_selected",
    "reproduction_record_missing",
    "reproduction_body_missing",
    "reproduction_producer_missing",
    "reproduction_runner_missing",
    "reproduction_subject_missing",
    "reproduction_policy_missing",
    "reproduction_record_schema",
    "reproduction_body_schema",
    "reproduction_identity_schema",
    "reproduction_foreign_missing",
    "reproduction_foreign_schema",
    "reproduction_descendant_missing",
    "reproduction_descendant_schema",
    "cli_reproduction_same_vendor",
    "cli_reproduction_body_missing",
    "reproduction_match_no_schema",
    "reproduction_body_missing_no_schema",
    "reproduction_body_schema_no_schema",
    "reproduction_subject_missing_no_schema",
    "reproduction_policy_missing_no_schema",
    "reproduction_subject_json_no_schema",
    "reproduction_policy_json_no_schema",
    "reproduction_descendant_missing_no_schema",
    "reproduction_descendant_schema_no_schema",
    "reproduction_producer_policy_binding",
    "reproduction_runner_policy_binding",
    "reproduction_producer_custody_binding",
    "reproduction_runner_custody_binding",
    "cli_reproduction_producer_policy_binding",
    "cli_reproduction_runner_policy_binding",
    "cli_reproduction_producer_custody_binding",
    "cli_reproduction_runner_custody_binding",
)


def reproduction_inputs(
    condition: str,
    inputs: dict[str, object],
    directory: Path,
    *,
    rules: dict[str, object],
    base: BlobRef,
    conditions: BlobRef,
    profile_class: str = "unsigned_declared",
    native_snapshot: BlobRef | None = None,
    native_certificate: BlobRef | None = None,
) -> tuple[dict[str, object], ReproductionOutcome | None]:
    """Keep whole original C0 bytes and add an explicitly unqualified complete record graph.

    Parameters
    ----------
    condition : str
        Actual public API or module CLI condition, with one named source contradiction.
    inputs : dict
        Whole original independent input corpus; existing fixtures are never modified.
    directory : Path
        Exact owned source directory populated before the actual Clock first sample.
    rules : dict
        Complete earlier identity/validation/foreign selections, updated as whole sources.
    base : BlobRef
        Whole original earlier ordinary policy, with its original explicit null Clock slot.
    conditions : BlobRef
        Actual earlier full limitations source. It discloses that native qualification
        and independent run evidence are unavailable; no record is passed off as a run.

    profile_class : str
        Actual selected class for complete native declarations, never an admission claim.
        Default retains every original unsigned fixture and diagnostic.
    native_snapshot, native_certificate : BlobRef or None
        Whole actual declared sources for a protected test-key validation statement.
        Their published key is unprotected and supplies no authority/custody acceptance.

    Returns
    -------
    tuple
        Entire updated inputs and an independently specified complete public diagnostic.
        A matching graph reaches the remaining V2 state guard, never reproduction admission.
    """
    if condition not in REPRODUCTION_RECORD_CASES and condition not in METHOD_POLICY_CASES:
        return inputs, None
    without_metadata = condition.endswith("_no_schema")
    case = condition.removeprefix("cli_").removesuffix("_no_schema")
    document = _object(json.loads(_bytes(inputs["content_json"])))
    if case == "reproduction_native_launch_publisher_matching":
        document["producer"] = {**_object(document["producer"]), "principal": "Arcane Sapience"}
    claims = [_object(item) for item in _array(document["claims"])]
    claim = claims[1]
    claim_id = _text(claim["claim_id"])
    principal = _text(_object(document["producer"])["principal"])
    runner_name = "deliberately-unverified-other-runner"
    if case == "reproduction_same_principal":
        runner_name = principal
    claim.update(origin="executed", evidence_maturity="executed")
    document["claims"] = claims
    earlier_subject = _stored(
        document, directory, schema_id="evidence_manifest_toolkit.manifest.v1"
    )
    earlier_policy = _stored(
        {
            **_object(json.loads((directory / base.digest[7:]).read_bytes())),
            "required_principal": "declared-unqualified-validation-policy-principal",
        },
        directory,
    )
    malformed_context: BlobRef | None = None
    if case in {"reproduction_subject_json", "reproduction_policy_json"}:
        original = earlier_subject if case == "reproduction_subject_json" else earlier_policy
        malformed_context = _native_source(
            (directory / original.digest[7:]).read_bytes()[:-1], directory, "application/json"
        )
        if case == "reproduction_subject_json":
            earlier_subject = malformed_context
        else:
            earlier_policy = malformed_context
    disclosure = "Unqualified declared test input; no actual independent run or class admission."
    raw_output = _native_source(disclosure.encode(), directory, "text/plain")
    if case == "reproduction_descendant_schema":
        raw_output = _stored(
            {"deliberately_invalid_native_output": True},
            directory,
            schema_id="evidence_manifest_toolkit.manifest.v1",
        )
    foreign_case = case.startswith("reproduction_foreign")
    if foreign_case and case != "reproduction_foreign_not_selected":
        additions, _ = method_rule_inputs(
            base, directory, profile_class=profile_class, foreign=True
        )
        rules.update(additions)
    if foreign_case:
        validation_path = directory / _text(_object(rules["validation_rule_ref"])["digest"])[7:]
        validation = _object(json.loads(validation_path.read_bytes()))
        validation["permitted_record_classes"] = ["github_hosted_verified_run_identity"]
        rules["validation_rule_ref"] = dict(_stored(validation, directory).to_mapping())
    possession_method_input(case, rules, directory, conditions=conditions)
    policy_ref = _object(rules["identity_rule_ref"])
    declared_ref = dict(conditions.to_mapping())
    producer: dict[str, object] = {
        "schema_id": "evidence_manifest_toolkit.identity_binding.v2",
        "custody_class": profile_class,
        "identity_class": "declared_by_launcher_under_the_seat_account",
        "vendor_id": "deliberately-unverified-producer-vendor",
        "principal_id": principal,
        "declared_public_key_ref": None,
        "observer_or_launcher_ref": declared_ref,
        "whole_policy_ref": policy_ref,
        "actual_launch_or_declared_source_ref": declared_ref,
        "process_identity_ref": None,
        "key_possession_ref": None,
        "endpoint_observation_ref": None,
        "client_reported_native_identity_ref": None,
        "limitations": [disclosure],
    }
    runner = {
        **producer,
        "vendor_id": "deliberately-unverified-runner-vendor",
        "principal_id": runner_name,
    }
    if case in {
        "reproduction_run_process_identity",
        "reproduction_run_execution_process",
        "reproduction_run_comparison_process",
    }:
        runner["process_identity_ref"] = declared_ref
    identity_source = _object(
        json.loads((directory / _text(policy_ref["digest"])[7:]).read_bytes())
    )
    launcher = _object(identity_source["launcher_or_observer_procedure_ref"])
    captured_sources = Path(__file__).parent / "fixtures/native-launch-sources"
    for selected_identity, role in ((producer, "producer"), (runner, "runner")):
        raw_launch = (captured_sources / (role + ".json")).read_bytes()
        declared_launch = _object(json.loads(raw_launch))
        if declared_launch["seat"] != selected_identity["principal_id"]:
            declared_launch["seat"] = selected_identity["principal_id"]
            raw_launch = json.dumps(declared_launch, ensure_ascii=False).encode()
        selected_identity["observer_or_launcher_ref"] = launcher
        selected_identity["actual_launch_or_declared_source_ref"] = dict(
            _native_source(raw_launch, directory, "application/json").to_mapping()
        )
    launch_fault = native_launch_input(
        case,
        producer,
        runner,
        rules=rules,
        base=base,
        directory=directory,
        limits=Limits(**cast(dict[str, int], _object(inputs["limits"]))),
    )
    if case == "reproduction_producer_principal":
        producer["principal_id"] = "different-declared-producer-principal"
    if case == "reproduction_runner_principal":
        runner["principal_id"] = "different-declared-runner-principal"
    if case == "reproduction_same_vendor":
        runner["vendor_id"] = producer["vendor_id"]
    if case == "reproduction_identity_schema":
        producer["unexpected"] = False
    for identity, selected in ((producer, "producer"), (runner, "runner")):
        if case == "reproduction_" + selected + "_identity_class":
            identity.update(
                identity_class="vendor_by_client_program_only",
                process_identity_ref=declared_ref,
                key_possession_ref=declared_ref,
            )
    for identity, selected in ((producer, "producer"), (runner, "runner")):
        if case == "reproduction_" + selected + "_custody_binding":
            identity["custody_class"] = "software_local_unprotected"
        if case == "reproduction_" + selected + "_policy_binding":
            independent = _object(
                json.loads((directory / _text(policy_ref["digest"])[7:]).read_bytes())
            )
            independent["client_catalogue_source_ref"] = dict(base.to_mapping())
            identity["whole_policy_ref"] = dict(_stored(independent, directory).to_mapping())
    runner_key: dict[str, str] | None = None
    if (
        case
        in {
            "reproduction_shared_key",
            "reproduction_key_pair_mismatch",
            "reproduction_distinct_key_refs",
            "reproduction_only_runner_key",
        }
        or profile_class == "protected_delegated"
        or case.startswith("reproduction_possession_")
    ):
        first = _native_source(
            bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            directory,
            "application/octet-stream",
        )
        second = _native_source(
            bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            directory,
            "application/octet-stream",
        )
        if case != "reproduction_only_runner_key":
            producer["declared_public_key_ref"] = dict(first.to_mapping())
        runner_key = dict((first if case == "reproduction_shared_key" else second).to_mapping())
        runner["declared_public_key_ref"] = runner_key
    producer_ref = _stored(
        producer,
        directory,
        schema_id=None if without_metadata else "evidence_manifest_toolkit.identity_binding.v2",
    )
    runner_ref = _stored(
        runner,
        directory,
        schema_id=None if without_metadata else "evidence_manifest_toolkit.identity_binding.v2",
    )
    body: dict[str, object] = {
        "schema_id": "evidence_manifest_toolkit.independent_validation_body.v2",
        "subject_ref": dict(earlier_subject.to_mapping()),
        "claim_id": "different-declared-claim" if case == "reproduction_body_claim" else claim_id,
        "whole_policy_ref": dict(earlier_policy.to_mapping()),
        "custody_class": "software_local_unprotected"
        if case == "reproduction_custody"
        else profile_class,
        "producer_binding_ref": dict(producer_ref.to_mapping()),
        "runner_binding_ref": dict(runner_ref.to_mapping()),
        "runner_actual_key_ref": declared_ref
        if case == "reproduction_key_pair_mismatch"
        else runner_key,
        "nonuse_class": "enforced_isolation"
        if case == "reproduction_nonuse"
        else "procedural_nonuse",
        "committed_code_recipe_environment_ref": declared_ref,
        "ordered_original_input_refs": [_object(document["source_ref"])],
        "actual_run_provenance_ref": declared_ref,
        "raw_output_and_diagnostics_refs": [dict(raw_output.to_mapping())],
        "dispatch_clock_witness_ref": None,
        "retrieval_clock_witness_ref": None,
        "raw_runner_times_ref": None,
        "sealed_independent_output_ref": dict(raw_output.to_mapping()),
        "comparison_release_order_ref": declared_ref,
        "comparison_rule_ref": comparison_policy_input(
            case,
            rules,
            base,
            directory,
            limits=Limits(**cast(dict[str, int], _object(inputs["limits"]))),
        ),
        "producer_output_refs": [_object(document["payload_ref"])],
        "whole_comparison_evidence_ref": declared_ref,
        "outcome": "diverge" if case == "reproduction_outcome" else "agree",
        "limitations": [disclosure],
    }
    body, run_conflict, run_missing = native_run_input(
        body,
        runner=runner_ref,
        rules=rules,
        conditions=conditions,
        directory=directory,
        condition=case,
    )
    body, possession_expected = native_possession_input(
        body, inputs=inputs, rules=rules, conditions=conditions, directory=directory, condition=case
    )
    if case == "reproduction_body_schema":
        body["unexpected"] = False
    body_ref = _stored(
        body,
        directory,
        schema_id=None
        if without_metadata
        else "evidence_manifest_toolkit.independent_validation_body.v2",
    )
    foreign_ref: BlobRef | None = None
    if foreign_case:
        foreign: dict[str, object] = {
            "schema_id": "evidence_manifest_toolkit.foreign_run_identity.v1",
            "evidence_class": "github_hosted_verified_run_identity",
            "attested_raw_artifact_ref": dict(body_ref.to_mapping()),
            "full_bundle_ref": declared_ref,
            "independent_trusted_root_ref": declared_ref,
            "whole_foreign_rule_ref": rules["foreign_rule_ref"] or declared_ref,
            "maintained_verifier_inventory_ref": declared_ref,
            "whole_actual_verification_inputs_outputs_ref": declared_ref,
            "authenticated_repository_identity_ref": declared_ref,
            "authenticated_workflow_commit_identity_ref": declared_ref,
            "authenticated_hosted_run_attempt_identity_ref": declared_ref,
            "verified_timestamps_source_ref": declared_ref,
            "limitations": [disclosure],
        }
        if case == "reproduction_foreign_schema":
            foreign["unexpected"] = False
        foreign_ref = _stored(
            foreign, directory, schema_id="evidence_manifest_toolkit.foreign_run_identity.v1"
        )
    validation_statement = None
    validation_receipts: list[dict[str, str]] = []
    if profile_class == "protected_delegated":
        assert native_snapshot is not None and native_certificate is not None
        limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
        validation_reference, receipt_references = native_validation_bundle(
            document,
            body_ref,
            snapshot=native_snapshot,
            certificate=native_certificate,
            scope=base,
            directory=directory,
            limits=limits,
        )
        validation_statement = dict(validation_reference.to_mapping())
        validation_receipts = [dict(reference.to_mapping()) for reference in receipt_references]
    record: dict[str, object] = {
        "schema_id": "evidence_manifest_toolkit.independent_validation_record.v2",
        "body_ref": dict(body_ref.to_mapping()),
        "subject_ref": dict(
            (base if case == "reproduction_record_subject" else earlier_subject).to_mapping()
        ),
        "claim_id": "different-declared-claim" if case == "reproduction_record_claim" else claim_id,
        "whole_policy_ref": policy_ref
        if case == "reproduction_record_policy"
        else dict(earlier_policy.to_mapping()),
        "evidence_class": "github_hosted_verified_run_identity"
        if foreign_case
        else "software_local_reproduction"
        if case == "reproduction_record_class"
        else {
            "unsigned_declared": "unsigned_declared_reproduction",
            "software_local_unprotected": "software_local_reproduction",
            "protected_delegated": "protected_native_seat_reproduction",
        }[profile_class],
        "validation_C0_statement_ref": validation_statement,
        "ordered_native_receipt_refs": validation_receipts,
        "foreign_run_identity_ref": None if foreign_ref is None else dict(foreign_ref.to_mapping()),
        "whole_conditions_and_limitations_ref": dict(
            (base if case == "reproduction_conditions" else conditions).to_mapping()
        ),
    }
    if case == "reproduction_record_schema":
        record["unexpected"] = False
    record_ref = _stored(
        record,
        directory,
        schema_id=None
        if without_metadata
        else "evidence_manifest_toolkit.independent_validation_record.v2",
    )
    claim.update(
        evidence_maturity="validated",
        verdict="agree",
        validation={
            "status": "independently_reproduced",
            "record_ref": dict(record_ref.to_mapping()),
            "runner_id": runner_name,
            "independent_of_producer": True,
        },
    )
    inputs["content_json"] = (
        base64.urlsafe_b64encode(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    if launch_fault is not None:
        return inputs, native_launch_expected(
            launch_fault, producer=producer_ref, runner=runner_ref
        )
    if possession_expected is not None:
        return inputs, possession_expected
    if run_missing is not None:
        return inputs, (
            "unavailable",
            {
                "code": "reference_unavailable",
                "subject_digest": None,
                "claim_id": None,
                "pointer": None,
                "detail": "Required reference unavailable.",
            },
            run_missing,
        )
    if run_conflict is not None:
        source, field = run_conflict
        malformed_run = case in {
            "reproduction_run_execution_extra",
            "reproduction_run_comparator_schema",
        }
        invalid_json_run = case in {
            "reproduction_run_request_json",
            "reproduction_run_comparator_json",
        }
        metadata_run = case == "reproduction_run_raw_metadata"
        return inputs, (
            "refused",
            {
                "code": "invalid_schema"
                if malformed_run or metadata_run
                else "invalid_json"
                if invalid_json_run
                else "invalid_claim",
                "subject_digest": source.digest,
                "claim_id": None if malformed_run or invalid_json_run or metadata_run else claim_id,
                "pointer": "/" + field if field else "",
                "detail": "Input violates its selected schema."
                if malformed_run
                else "Input is not valid strict JSON."
                if invalid_json_run
                else "Reference metadata conflicts."
                if metadata_run
                else "Native access event order conflicts."
                if case == "reproduction_run_access_order"
                else "Native access prefixes conflict."
                if case.startswith("reproduction_run_access_prefix_")
                else "Native execution and comparison sources conflict.",
            },
            None,
        )
    failures = {
        "reproduction_record_subject": (record_ref, "subject_ref"),
        "reproduction_record_claim": (record_ref, "claim_id"),
        "reproduction_record_policy": (record_ref, "whole_policy_ref"),
        "reproduction_conditions": (record_ref, "whole_conditions_and_limitations_ref"),
        "reproduction_body_claim": (body_ref, "claim_id"),
        "reproduction_custody": (body_ref, "custody_class"),
        "reproduction_outcome": (body_ref, "outcome"),
        "reproduction_record_class": (record_ref, "evidence_class"),
        "reproduction_nonuse": (body_ref, "nonuse_class"),
        "reproduction_comparison_rule_base": (body_ref, "comparison_rule_ref"),
        "reproduction_comparison_rule_alternate": (body_ref, "comparison_rule_ref"),
        "reproduction_comparison_rule_jcs": (body_ref, "comparison_rule_ref"),
        "reproduction_execution_nonuse_rule": (body_ref, "nonuse_class"),
        "reproduction_validation_nonuse_rule": (body_ref, "nonuse_class"),
        "reproduction_runner_identity_class": (runner_ref, "identity_class"),
        "reproduction_producer_identity_class": (producer_ref, "identity_class"),
        "reproduction_producer_principal": (producer_ref, "principal_id"),
        "reproduction_runner_principal": (runner_ref, "principal_id"),
        "reproduction_same_vendor": (runner_ref, "vendor_id"),
        "reproduction_same_principal": (runner_ref, "principal_id"),
        "reproduction_shared_key": (runner_ref, "declared_public_key_ref"),
        "reproduction_key_pair_mismatch": (body_ref, "runner_actual_key_ref"),
        "reproduction_producer_policy_binding": (producer_ref, "whole_policy_ref"),
        "reproduction_runner_policy_binding": (runner_ref, "whole_policy_ref"),
        "reproduction_producer_custody_binding": (producer_ref, "custody_class"),
        "reproduction_runner_custody_binding": (runner_ref, "custody_class"),
        "reproduction_foreign_not_selected": (record_ref, "foreign_run_identity_ref"),
    }
    if case in failures:
        reference, field = failures[case]
        return inputs, (
            "refused",
            {
                "code": "invalid_claim",
                "subject_digest": reference.digest,
                "claim_id": claim_id,
                "pointer": "/" + field,
                "detail": "Independent validation sources conflict.",
            },
            None,
        )
    missing = {
        "reproduction_record_missing": record_ref,
        "reproduction_body_missing": body_ref,
        "reproduction_producer_missing": producer_ref,
        "reproduction_runner_missing": runner_ref,
        "reproduction_subject_missing": earlier_subject,
        "reproduction_policy_missing": earlier_policy,
        "reproduction_descendant_missing": raw_output,
    }
    if foreign_ref is not None:
        missing["reproduction_foreign_missing"] = foreign_ref
    if case in missing:
        reference = missing[case]
        (directory / reference.digest[7:]).unlink()
        return inputs, (
            "unavailable",
            {
                "code": "reference_unavailable",
                "subject_digest": None,
                "claim_id": None,
                "pointer": None,
                "detail": "Required reference unavailable.",
            },
            reference,
        )
    if malformed_context is not None:
        return inputs, (
            "refused",
            {
                "code": "invalid_json",
                "subject_digest": malformed_context.digest,
                "claim_id": None,
                "pointer": "",
                "detail": "Input is not valid strict JSON.",
            },
            None,
        )
    malformed = {
        "reproduction_record_schema": record_ref,
        "reproduction_body_schema": body_ref,
        "reproduction_identity_schema": producer_ref,
        "reproduction_descendant_schema": raw_output,
    }
    if foreign_ref is not None:
        malformed["reproduction_foreign_schema"] = foreign_ref
    if case in malformed:
        return inputs, (
            "refused",
            {
                "code": "invalid_schema",
                "subject_digest": malformed[case].digest,
                "claim_id": None,
                "pointer": "",
                "detail": "Input violates its selected schema.",
            },
            None,
        )
    return inputs, (
        "configuration",
        {
            "code": "configuration_error",
            "subject_digest": None,
            "claim_id": None,
            "pointer": "/trust",
            "detail": "Invalid local configuration.",
        },
        None,
    )
