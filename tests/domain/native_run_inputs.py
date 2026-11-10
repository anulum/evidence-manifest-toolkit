# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole unqualified native run graph boundary inputs

"""Build full declared run records without inventing executed or qualified evidence."""

import json
from pathlib import Path

from tests.domain.native_access_prefix_inputs import native_access_prefix_input
from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _array, _object

from evidence_manifest_toolkit import BlobRef

NATIVE_RUN_CASES = tuple(
    "reproduction_run_" + case
    for case in (
        "matching",
        "request_subject",
        "execution_inputs",
        "release_execution",
        "comparison_implementation",
        "comparison_parameters",
        "comparison_outcome",
        "access_order",
        "execution_extra",
        "comparison_request_missing",
        "request_json",
        "comparator_missing",
        "comparator_json",
        "comparator_schema",
        "access_descendant_missing",
        "raw_metadata",
        "process_identity",
        "execution_process",
        "comparison_process",
    )
) + (
    "cli_reproduction_run_request_subject",
    "cli_reproduction_run_comparison_outcome",
    "cli_reproduction_run_comparison_request_missing",
    "protected_reproduction_run_matching",
    "protected_reproduction_run_comparison_outcome",
    "cli_protected_reproduction_run_request_subject",
)


def native_run_input(
    body: dict[str, object],
    *,
    runner: BlobRef,
    rules: dict[str, object],
    conditions: BlobRef,
    directory: Path,
    condition: str,
) -> tuple[dict[str, object], tuple[BlobRef, str] | None, BlobRef | None]:
    """Materialise complete raw record graphs and one independently chosen conflict.

    Parameters
    ----------
    body : dict
        Whole earlier unsigned/software/protected declared validation body.
    runner : BlobRef
        Complete actual stored declared runner binding and original native launch data.
    rules : dict
        Whole independently selected native identity/validation/execution/comparison rules.
    conditions : BlobRef
        Existing explicit disclosure that these sources are unqualified declarations.
    directory : Path
        Owned flat source store used by the actual public bounded file Resolver.
    condition : str
        One full graph/schema/refusal boundary, or a retained earlier reproduction case.

    Returns
    -------
    tuple
        Updated entire body, exact conflicting source/field or None, and an exact
        deliberately absent source or None. No source is an actual run/Clock proof.
    """

    def read(reference: object) -> dict[str, object]:
        """Read a complete already stored native source."""
        selected = BlobRef.from_mapping(_object(reference))
        return _object(json.loads((directory / selected.digest[7:]).read_bytes()))

    def store(value: dict[str, object]) -> BlobRef:
        """Store one complete declared raw JSON body under its actual identity."""
        return _stored(value, directory)

    def ref(reference: BlobRef) -> dict[str, str]:
        """Keep every original Ref field in each declared source use."""
        return dict(reference.to_mapping())

    case = condition.removeprefix("cli_").removeprefix("reproduction_run_")
    identity = read(ref(runner))
    validation = read(rules["validation_rule_ref"])
    execution_method = read(validation["run_and_seal_before_comparison_procedure_ref"])
    comparison_method = read(validation["comparison_rule_ref"])
    declaration = ref(conditions)
    conflict: tuple[BlobRef, str] | None = None
    request = {
        "request_kind": "independent_validation",
        "subject_ref": declaration if case == "request_subject" else body["subject_ref"],
        "claim_id": body["claim_id"],
        "whole_policy_ref": body["whole_policy_ref"],
        "identity_policy_ref": identity["whole_policy_ref"],
        "expected_principal_id": identity["principal_id"],
        "expected_vendor_id": identity["vendor_id"],
        "expected_public_key_ref": identity["declared_public_key_ref"],
        "committed_code_recipe_environment_ref": body["committed_code_recipe_environment_ref"],
        "ordered_original_input_refs": body["ordered_original_input_refs"],
        "comparison_rule_ref": body["comparison_rule_ref"],
        "whole_conditions_and_limitations_ref": declaration,
        "resource_policy_ref": declaration,
        "executor_method_ref": execution_method["executor_method_ref"],
    }
    request_ref = store(request)
    if case == "request_json":
        request_ref = _native_source(b"{", directory, "application/json")
        conflict = request_ref, ""
    if case == "request_subject":
        conflict = request_ref, "subject_ref"
    access: dict[str, object] = {
        "execution_request_ref": ref(request_ref),
        "access_method_ref": declaration,
        "access_method_qualification_ref": declaration,
        "recorder_process_identity_ref": declaration,
        "environment_ref": declaration,
        "policy_and_input_boundary_ref": declaration,
        "captured_before_time_source_ref": declaration,
        "captured_after_time_source_ref": declaration,
        "events": [],
    }
    absent_access = None
    if case in {"access_order", "access_descendant_missing"}:
        event = {
            "sequence": "123456789012345678901234567890",
            "event_kind": "input_open",
            "subject_ref": body["subject_ref"],
            "before_time_source_ref": declaration,
            "after_time_source_ref": declaration,
            "native_operation_source_ref": declaration,
            "native_outcome_source_ref": declaration,
            "observed_process_identity_ref": declaration,
        }
        if case == "access_order":
            access["events"] = [event, dict(event)]
        else:
            absent_access = _native_source(
                b"Unavailable native access event outcome source.", directory, "text/plain"
            )
            event["native_outcome_source_ref"] = ref(absent_access)
            access["events"] = [event]
    access_ref = store(access)
    if case == "access_order":
        conflict = access_ref, "events/1/sequence"
    access_refs = (access_ref, access_ref, access_ref)
    if case.startswith("access_prefix_"):
        access_refs, conflict = native_access_prefix_input(
            access, subject=body["subject_ref"], directory=directory, case=case
        )
    execution = {
        "execution_request_ref": ref(request_ref),
        "committed_code_recipe_environment_ref": body["committed_code_recipe_environment_ref"],
        "ordered_original_input_refs": [declaration]
        if case == "execution_inputs"
        else body["ordered_original_input_refs"],
        "runner_binding_ref": ref(runner),
        "launch_record_ref": identity["actual_launch_or_declared_source_ref"],
        "process_identity_ref": body["subject_ref"]
        if case == "execution_process"
        else identity["process_identity_ref"] or declaration,
        "actual_command_source_ref": declaration,
        "actual_environment_ref": declaration,
        "execution_started_time_source_ref": declaration,
        "execution_finished_time_source_ref": declaration,
        "exit_status": {"kind": "exit", "code": "0"},
        "raw_output_and_diagnostics_refs": body["raw_output_and_diagnostics_refs"],
        "actual_access_order_source_ref": ref(access_refs[0]),
        "resource_policy_ref": declaration,
        "executor_implementation_ref": declaration,
        "executor_qualification_ref": declaration,
    }
    if case == "execution_extra":
        execution["unexpected"] = True
    execution_ref = store(execution)
    if case in {"execution_inputs", "execution_extra"}:
        conflict = (
            execution_ref,
            "ordered_original_input_refs" if case == "execution_inputs" else "",
        )
    if case == "execution_process":
        conflict = execution_ref, "process_identity_ref"
    release = {
        "execution_request_ref": ref(request_ref),
        "execution_observation_ref": declaration
        if case == "release_execution"
        else ref(execution_ref),
        "sealed_independent_manifest_ref": body["sealed_independent_output_ref"],
        "ordered_independent_output_refs": [body["sealed_independent_output_ref"]],
        "ordered_producer_output_refs": body["producer_output_refs"],
        "seal_time_source_ref": declaration,
        "release_time_source_ref": declaration,
        "actual_access_order_source_ref": ref(access_refs[1]),
        "release_method_ref": execution_method["release_method_ref"],
        "release_qualification_ref": declaration,
    }
    release_ref = store(release)
    if case == "release_execution":
        conflict = release_ref, "execution_observation_ref"
    comparison_request = {
        "request_kind": "comparison",
        "execution_request_ref": ref(request_ref),
        "identity_policy_ref": identity["whole_policy_ref"],
        "comparison_rule_ref": body["comparison_rule_ref"],
        "release_observation_ref": ref(release_ref),
        "sealed_independent_manifest_ref": release["sealed_independent_manifest_ref"],
        "ordered_independent_output_refs": release["ordered_independent_output_refs"],
        "ordered_producer_output_refs": body["producer_output_refs"],
        "expected_principal_id": identity["principal_id"],
        "expected_vendor_id": identity["vendor_id"],
        "expected_public_key_ref": identity["declared_public_key_ref"],
        "comparison_implementation_ref": comparison_method["implementation_ref"],
        "comparison_environment_ref": comparison_method["implementation_environment_ref"],
        "comparison_qualification_ref": comparison_method["implementation_qualification_ref"],
        "whole_comparison_parameters_ref": declaration
        if case == "comparison_parameters"
        else comparison_method["whole_comparison_parameters_ref"],
        "outcome_mapping_ref": comparison_method["outcome_mapping_ref"],
        "resource_policy_ref": declaration,
        "whole_conditions_and_limitations_ref": declaration,
    }
    comparison_request_ref = store(comparison_request)
    if case == "comparison_parameters":
        conflict = comparison_request_ref, "whole_comparison_parameters_ref"
    comparator_ref = runner
    absent_comparator = None
    if case in {"comparator_missing", "comparator_json", "comparator_schema"}:
        comparator = {**identity, "limitations": ["Separate unqualified comparator source input."]}
        if case == "comparator_schema":
            comparator["unexpected"] = False
        comparator_ref = (
            _native_source(b"{", directory, "application/json")
            if case == "comparator_json"
            else store(comparator)
        )
        if case == "comparator_missing":
            absent_comparator = comparator_ref
        else:
            conflict = comparator_ref, ""
    raw = {
        "comparison_request_ref": ref(comparison_request_ref),
        "ordered_input_refs": [
            body["sealed_independent_output_ref"],
            *_array(body["producer_output_refs"]),
        ],
        "raw_stdout_ref": body["sealed_independent_output_ref"],
        "raw_stderr_ref": {**declaration, "media_type": "text/plain"}
        if case == "raw_metadata"
        else declaration,
        "exit_status": {"kind": "exit", "code": "0"},
        "access_observation_ref": ref(access_refs[2]),
        "native_command_source_ref": declaration,
        "process_identity_ref": body["subject_ref"]
        if case == "comparison_process"
        else identity["process_identity_ref"] or declaration,
        "environment_ref": comparison_method["implementation_environment_ref"],
        "time_sources_ref": declaration,
        "comparator_binding_ref": ref(comparator_ref),
        "launch_record_ref": identity["actual_launch_or_declared_source_ref"],
    }
    raw_ref = store(raw)
    if case in {"raw_metadata", "comparison_process"}:
        conflict = raw_ref, "raw_stderr_ref" if case == "raw_metadata" else "process_identity_ref"
    comparison = {
        field: comparison_request[field]
        for field in (
            "comparison_rule_ref",
            "execution_request_ref",
            "release_observation_ref",
            "sealed_independent_manifest_ref",
            "ordered_independent_output_refs",
            "ordered_producer_output_refs",
            "comparison_implementation_ref",
            "comparison_environment_ref",
            "comparison_qualification_ref",
        )
    }
    if case == "comparison_implementation":
        comparison["comparison_implementation_ref"] = declaration
    comparison.update(
        comparison_started_time_source_ref=declaration,
        comparison_finished_time_source_ref=declaration,
        whole_raw_comparison_inputs_outputs_ref=ref(raw_ref),
        outcome="diverge" if case == "comparison_outcome" else body["outcome"],
        limitations_ref=declaration,
    )
    comparison_ref = store(comparison)
    if case in {"comparison_implementation", "comparison_outcome"}:
        conflict = (
            comparison_ref,
            "comparison_implementation_ref" if case.endswith("implementation") else "outcome",
        )
    result = {
        **body,
        "actual_run_provenance_ref": ref(execution_ref),
        "comparison_release_order_ref": ref(release_ref),
        "whole_comparison_evidence_ref": ref(comparison_ref),
    }
    missing = (
        comparison_request_ref
        if case == "comparison_request_missing"
        else absent_comparator or absent_access
    )
    if missing is not None:
        (directory / missing.digest[7:]).unlink()
    return result, conflict, missing


def rebind_native_run_runner(
    body: dict[str, object], *, runner: BlobRef, directory: Path
) -> dict[str, object]:
    """Rebind every whole declared native record after a deliberate fixture key change.

    Parameters
    ----------
    body : dict
        Entire original validation body, including all earlier native records.
    runner : BlobRef
        Whole newly stored declared runner with the intended public-key source.
    directory : Path
        Actual owned flat source store; original records remain unchanged.

    Returns
    -------
    dict
        Entire body with newly referenced whole records in acyclic construction order.
        All unchanged fields and arrays retain their values; this grants no run proof.
    """

    def read(reference: object) -> dict[str, object]:
        """Read a complete earlier declared body without mutating its stored bytes."""
        selected = BlobRef.from_mapping(_object(reference))
        return _object(json.loads((directory / selected.digest[7:]).read_bytes()))

    def store(value: dict[str, object]) -> dict[str, str]:
        """Retain a newly constructed entire raw source under its own exact reference."""
        return dict(_stored(value, directory).to_mapping())

    identity = read(dict(runner.to_mapping()))
    execution = read(body["actual_run_provenance_ref"])
    request = read(execution["execution_request_ref"])
    request["expected_public_key_ref"] = identity["declared_public_key_ref"]
    request_ref = store(request)

    def access(reference: object) -> dict[str, str]:
        """Preserve the full access record and every ordered event under the new request."""
        return store({**read(reference), "execution_request_ref": request_ref})

    execution.update(
        execution_request_ref=request_ref,
        runner_binding_ref=dict(runner.to_mapping()),
        actual_access_order_source_ref=access(execution["actual_access_order_source_ref"]),
    )
    execution_ref = store(execution)
    release = read(body["comparison_release_order_ref"])
    release.update(
        execution_request_ref=request_ref,
        execution_observation_ref=execution_ref,
        actual_access_order_source_ref=access(release["actual_access_order_source_ref"]),
    )
    release_ref = store(release)
    comparison = read(body["whole_comparison_evidence_ref"])
    raw = read(comparison["whole_raw_comparison_inputs_outputs_ref"])
    comparison_request = read(raw["comparison_request_ref"])
    comparison_request.update(
        execution_request_ref=request_ref,
        release_observation_ref=release_ref,
        expected_public_key_ref=identity["declared_public_key_ref"],
    )
    raw.update(
        comparison_request_ref=store(comparison_request),
        comparator_binding_ref=dict(runner.to_mapping()),
        access_observation_ref=access(raw["access_observation_ref"]),
    )
    comparison.update(
        execution_request_ref=request_ref,
        release_observation_ref=release_ref,
        whole_raw_comparison_inputs_outputs_ref=store(raw),
    )
    return {
        **body,
        "actual_run_provenance_ref": execution_ref,
        "comparison_release_order_ref": release_ref,
        "whole_comparison_evidence_ref": store(comparison),
    }
