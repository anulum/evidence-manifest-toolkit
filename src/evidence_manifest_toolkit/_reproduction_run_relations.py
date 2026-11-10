# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact whole native run release and comparison relations

"""Check complete native record joins without promoting declarations into run qualification."""

from typing import cast

from ._format_sources import FixedSource
from ._json import AcquiredDocument, JsonValue
from ._method_rule_sources import MethodRuleSources
from ._reproduction_access_prefixes import native_access_prefix_reasons
from ._reproduction_run_sources import ReproductionRunSources
from ._values import Reason


def reproduction_run_reasons(
    run: ReproductionRunSources,
    *,
    record: FixedSource,
    body: FixedSource,
    runner: FixedSource,
    rules: MethodRuleSources,
) -> tuple[Reason, ...]:
    """Compare whole request, source, method, output and outcome identities in native records.

    Parameters
    ----------
    run : ReproductionRunSources
        All actual closed execution/release/comparison/access sources.
    record, body, runner : FixedSource
        Entire original package, earlier validation body and selected runner binding.
    rules : MethodRuleSources
        Independently selected whole identity and native execution/comparison declarations.

    Returns
    -------
    tuple of Reason
        Every located exact-field conflict, preserving original arrays and Ref metadata.
        Empty reasons establish only correspondence. Actual qualified execution,
        access capture, seal/release chronology, comparison algorithm, custody and
        Clock remain required; no assertion in these records supplies those predicates.
    """

    def value(source: FixedSource) -> dict[str, JsonValue]:
        """Retain every field of the actual validated document."""
        return cast(dict[str, JsonValue], cast(AcquiredDocument, source.source.document).value)

    def ref(source: FixedSource) -> dict[str, JsonValue]:
        """Keep the complete source identity without digest-only aliasing."""
        return dict(source.source.reference.to_mapping())

    b, r, identity = value(body), value(record), value(runner)
    request, execution = value(run.request), value(run.execution)
    release, comparison = value(run.release), value(run.comparison)
    comparison_request, raw = value(run.comparison_request), value(run.raw_comparison)
    comparator = value(run.comparator)
    execution_method = value(rules.native_bindings.execution)
    comparison_method = value(rules.native_bindings.comparison)
    claim = cast(str, b["claim_id"])
    reasons: list[Reason] = []

    def check(source: FixedSource, field: str, actual: JsonValue, expected: JsonValue) -> None:
        """Locate an actual complete field mismatch without echoing raw source data."""
        if actual != expected:
            reasons.append(
                Reason(
                    "invalid_claim",
                    source.source.reference.digest,
                    claim,
                    "/" + field,
                    "Native execution and comparison sources conflict.",
                )
            )

    for field, expected in (
        ("request_kind", "independent_validation"),
        ("subject_ref", b["subject_ref"]),
        ("claim_id", b["claim_id"]),
        ("whole_policy_ref", b["whole_policy_ref"]),
        ("identity_policy_ref", ref(rules.identity)),
        ("expected_principal_id", identity["principal_id"]),
        ("expected_vendor_id", identity["vendor_id"]),
        ("expected_public_key_ref", identity["declared_public_key_ref"]),
        ("committed_code_recipe_environment_ref", b["committed_code_recipe_environment_ref"]),
        ("ordered_original_input_refs", b["ordered_original_input_refs"]),
        ("comparison_rule_ref", b["comparison_rule_ref"]),
        ("whole_conditions_and_limitations_ref", r["whole_conditions_and_limitations_ref"]),
        ("executor_method_ref", execution_method["executor_method_ref"]),
    ):
        check(run.request, field, request[field], expected)
    for field, expected in (
        ("execution_request_ref", ref(run.request)),
        ("committed_code_recipe_environment_ref", request["committed_code_recipe_environment_ref"]),
        ("ordered_original_input_refs", request["ordered_original_input_refs"]),
        ("runner_binding_ref", ref(runner)),
        ("launch_record_ref", identity["actual_launch_or_declared_source_ref"]),
        ("raw_output_and_diagnostics_refs", b["raw_output_and_diagnostics_refs"]),
        ("resource_policy_ref", request["resource_policy_ref"]),
    ):
        check(run.execution, field, execution[field], expected)
    if identity["process_identity_ref"] is not None:
        check(
            run.execution,
            "process_identity_ref",
            execution["process_identity_ref"],
            identity["process_identity_ref"],
        )
    for field, expected in (
        ("execution_request_ref", ref(run.request)),
        ("execution_observation_ref", ref(run.execution)),
        ("ordered_producer_output_refs", b["producer_output_refs"]),
        ("release_method_ref", execution_method["release_method_ref"]),
    ):
        check(run.release, field, release[field], expected)
    for field, expected in (
        ("execution_request_ref", ref(run.request)),
        ("identity_policy_ref", ref(rules.identity)),
        ("comparison_rule_ref", b["comparison_rule_ref"]),
        ("release_observation_ref", ref(run.release)),
        ("sealed_independent_manifest_ref", release["sealed_independent_manifest_ref"]),
        ("ordered_independent_output_refs", release["ordered_independent_output_refs"]),
        ("ordered_producer_output_refs", release["ordered_producer_output_refs"]),
        ("expected_principal_id", identity["principal_id"]),
        ("expected_vendor_id", identity["vendor_id"]),
        ("expected_public_key_ref", identity["declared_public_key_ref"]),
        ("comparison_implementation_ref", comparison_method["implementation_ref"]),
        ("comparison_environment_ref", comparison_method["implementation_environment_ref"]),
        ("comparison_qualification_ref", comparison_method["implementation_qualification_ref"]),
        ("whole_comparison_parameters_ref", comparison_method["whole_comparison_parameters_ref"]),
        ("outcome_mapping_ref", comparison_method["outcome_mapping_ref"]),
        ("resource_policy_ref", request["resource_policy_ref"]),
        ("whole_conditions_and_limitations_ref", r["whole_conditions_and_limitations_ref"]),
    ):
        check(run.comparison_request, field, comparison_request[field], expected)
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
    ):
        check(run.comparison, field, comparison[field], comparison_request[field])
    check(run.comparison, "outcome", comparison["outcome"], b["outcome"])
    for field, expected in (
        ("principal_id", comparison_request["expected_principal_id"]),
        ("vendor_id", comparison_request["expected_vendor_id"]),
        ("declared_public_key_ref", comparison_request["expected_public_key_ref"]),
        ("whole_policy_ref", ref(rules.identity)),
        ("custody_class", identity["custody_class"]),
    ):
        check(run.comparator, field, comparator[field], expected)
    check(
        run.raw_comparison,
        "launch_record_ref",
        raw["launch_record_ref"],
        comparator["actual_launch_or_declared_source_ref"],
    )
    if comparator["process_identity_ref"] is not None:
        check(
            run.raw_comparison,
            "process_identity_ref",
            raw["process_identity_ref"],
            comparator["process_identity_ref"],
        )
    check(
        run.raw_comparison,
        "environment_ref",
        raw["environment_ref"],
        comparison_request["comparison_environment_ref"],
    )
    for access_source in run.access:
        access = value(access_source)
        check(
            access_source,
            "execution_request_ref",
            access["execution_request_ref"],
            ref(run.request),
        )
        previous = -1
        for index, event in enumerate(cast(list[dict[str, JsonValue]], access["events"])):
            sequence = int(cast(str, event["sequence"]))
            if sequence <= previous:
                reasons.append(
                    Reason(
                        "invalid_claim",
                        access_source.source.reference.digest,
                        claim,
                        "/events/" + str(index) + "/sequence",
                        "Native access event order conflicts.",
                    )
                )
            previous = sequence
    return tuple(reasons) + native_access_prefix_reasons(run.access, claim_id=claim)
