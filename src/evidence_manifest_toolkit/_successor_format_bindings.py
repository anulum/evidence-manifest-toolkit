# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — fixed complete successor format bindings

"""Pin installed source bytes and exact selectors without modifying caller registries."""

from collections.abc import Mapping
from types import MappingProxyType

type Selector = tuple[str | None, ...]
type Binding = tuple[str, str, tuple[Selector, ...]]

NATIVE_FORMAT_IDS = frozenset(
    {
        "evidence_manifest_toolkit.authority_policy.v2",
        "evidence_manifest_toolkit.authority_grant.v2",
        "evidence_manifest_toolkit.delegated_certificate.v2",
        "evidence_manifest_toolkit.authority_rotation.v2",
        "evidence_manifest_toolkit.authority_snapshot.v2",
        "evidence_manifest_toolkit.signed_statement.v2",
        "evidence_manifest_toolkit.identity_binding.v2",
        "evidence_manifest_toolkit.independent_validation_body.v2",
        "evidence_manifest_toolkit.independent_validation_record.v2",
        "evidence_manifest_toolkit.foreign_run_identity.v1",
    }
)

RESOURCES: Mapping[str, tuple[int, str]] = MappingProxyType(
    {
        "successor_authority": (
            37529,
            "649b5c03400bc362811467300e6acc05158e48eb4297e85449cb0c187d1f31e1",
        ),
        "successor_caller_trust": (
            11392,
            "e65ff95e20bc0cc9233e2ed62c19df8a8db5a93200628d06235a560a7cc889a0",
        ),
        "successor_clock": (
            22758,
            "2446c2a862d7cf49f195e2c16ec760439539df5ebf4ee7169f3398b07d863e8e",
        ),
        "successor_control": (
            9774,
            "705fe4368566b2dfcd41eec19a31a283443972919648c401d4bf866fa6ef446e",
        ),
        "successor_identity_rules": (
            7838,
            "ad41ec0ddb21e55c0aff17a5339c8e6d2876d5e7685fac5c6e324916da610268",
        ),
        "successor_class_context": (
            4078,
            "0ad9d3d5c2ec6d42858c865961554468eb0bbc188a2aad98c1242be1005c3cd0",
        ),
    }
)

FORMAT_BINDINGS: Mapping[str, Binding] = MappingProxyType(
    {
        "evidence_manifest_toolkit.authority_policy.v2": (
            "successor_authority",
            "policy",
            (
                ("authority_rule_ref",),
                ("foreign_rule_ref",),
                ("identity_rule_ref",),
                ("independent_foreign_trust_ref",),
                ("root_grant_ref",),
                ("signature_obligation_rule_ref",),
                ("validation_rule_ref",),
                ("whole_conditions_and_limitations_ref",),
                ("whole_legacy_artifact_policy_ref",),
            ),
        ),
        "evidence_manifest_toolkit.authority_grant.v2": (
            "successor_authority",
            "authority_grant",
            (
                ("automation_policy_ref",),
                ("initial_issuer_public_key_ref",),
                ("owner_revocation_only_path_ref",),
                ("protected_controller_custody_ref",),
                ("root_selection_source_ref",),
                ("rotation_rule_ref",),
            ),
        ),
        "evidence_manifest_toolkit.delegated_certificate.v2": (
            "successor_authority",
            "delegated_certificate",
            (
                ("identity_custody_source_ref",),
                ("parent_authorization_ref",),
                ("subject_public_key_ref",),
            ),
        ),
        "evidence_manifest_toolkit.authority_rotation.v2": (
            "successor_authority",
            "authority_rotation",
            (
                ("actual_generation_custody_ref",),
                ("controller_ref",),
                ("new_public_key_ref",),
                ("previous_rotation_ref",),
                ("root_grant_ref",),
                ("unchanged_scope_ref",),
            ),
        ),
        "evidence_manifest_toolkit.authority_snapshot.v2": (
            "successor_authority",
            "authority_snapshot",
            (
                ("certificate_refs", None),
                ("current_rotation_ref",),
                ("identity_rule_refs", None),
                ("previous_snapshot_ref",),
                ("registry_ref",),
                ("revocations", None, "compromise_time_bounds_ref"),
                ("revocations", None, "target_ref"),
                ("root_grant_ref",),
            ),
        ),
        "evidence_manifest_toolkit.signed_statement.v2": (
            "successor_authority",
            "signed_statement",
            (("authorization_ref",), ("authorizing_state_ref",), ("scope_ref",), ("snapshot_ref",)),
        ),
        "evidence_manifest_toolkit.identity_binding.v2": (
            "successor_authority",
            "identity_binding",
            (
                ("actual_launch_or_declared_source_ref",),
                ("client_reported_native_identity_ref",),
                ("declared_public_key_ref",),
                ("endpoint_observation_ref",),
                ("key_possession_ref",),
                ("observer_or_launcher_ref",),
                ("process_identity_ref",),
                ("whole_policy_ref",),
            ),
        ),
        "evidence_manifest_toolkit.independent_validation_body.v2": (
            "successor_authority",
            "validation_body",
            (
                ("actual_run_provenance_ref",),
                ("committed_code_recipe_environment_ref",),
                ("comparison_release_order_ref",),
                ("comparison_rule_ref",),
                ("dispatch_clock_witness_ref",),
                ("ordered_original_input_refs", None),
                ("producer_binding_ref",),
                ("producer_output_refs", None),
                ("raw_output_and_diagnostics_refs", None),
                ("raw_runner_times_ref",),
                ("retrieval_clock_witness_ref",),
                ("runner_actual_key_ref",),
                ("runner_binding_ref",),
                ("sealed_independent_output_ref",),
                ("subject_ref",),
                ("whole_comparison_evidence_ref",),
                ("whole_policy_ref",),
            ),
        ),
        "evidence_manifest_toolkit.independent_validation_record.v2": (
            "successor_authority",
            "validation_record",
            (
                ("body_ref",),
                ("foreign_run_identity_ref",),
                ("ordered_native_receipt_refs", None),
                ("subject_ref",),
                ("validation_C0_statement_ref",),
                ("whole_conditions_and_limitations_ref",),
                ("whole_policy_ref",),
            ),
        ),
        "evidence_manifest_toolkit.foreign_run_identity.v1": (
            "successor_authority",
            "foreign_run_identity",
            (
                ("attested_raw_artifact_ref",),
                ("authenticated_hosted_run_attempt_identity_ref",),
                ("authenticated_repository_identity_ref",),
                ("authenticated_workflow_commit_identity_ref",),
                ("full_bundle_ref",),
                ("independent_trusted_root_ref",),
                ("maintained_verifier_inventory_ref",),
                ("verified_timestamps_source_ref",),
                ("whole_actual_verification_inputs_outputs_ref",),
                ("whole_foreign_rule_ref",),
            ),
        ),
        "emt-clock-entry-binding-source-r4": (
            "successor_caller_trust",
            "entry_binding",
            (
                ("boot_domain_ref",),
                ("entry_observation_method_ref",),
                ("first_sample_source_ref",),
                ("implementation_environment_ref",),
                ("process_start_identity_ref",),
                ("source_profile_ref",),
                ("verification_controller_identity_ref",),
            ),
        ),
        "emt-software-authorization-source-r4": (
            "successor_caller_trust",
            "software_authorization",
            (
                ("authorized_keys", None, "identity_binding_ref"),
                ("authorized_keys", None, "possession_and_software_custody_ref"),
                ("limitations_ref",),
                ("local_controller_identity_ref",),
                ("previous_authorization_ref",),
                ("revocations", None, "revocation_source_ref"),
                ("whole_scope_and_signature_rule_ref",),
            ),
        ),
        "autonomous-evaluation-clock-profile-source-r4": (
            "successor_clock",
            "profile",
            (
                ("accepted_ntp_configuration_ref",),
                ("acquisition_rule_ref",),
                ("automatic_reacceptance_rule_ref",),
                ("controller_identity_ref",),
                ("daemon_field_mapping_rule_ref",),
                ("holdover_drift_bound_rule_ref",),
                ("host_identity_ref",),
                ("implementation_environment_ref",),
                ("independence_rule_ref",),
                ("issuer_authorization_ref",),
                ("issuer_identity_ref",),
                ("monotonic_mapping_rule_ref",),
                ("ntp_resolution_and_rotation_rule_ref",),
                ("observer_identity_ref",),
                ("uncertainty_derivation_rule_ref",),
            ),
        ),
        "autonomous-evaluation-clock-acceptance-source-r4": (
            "successor_clock",
            "acceptance_body",
            (
                ("after", "clock_sample_raw_ref"),
                ("before", "clock_sample_raw_ref"),
                ("checks", None, "evidence_refs", None),
                ("controller_identity_ref",),
                ("host_identity_ref",),
                ("issuer_authorization_ref",),
                ("issuer_identity_ref",),
                ("monotonic_domain_ref",),
                ("observer_identity_ref",),
                ("profile_ref",),
                ("raw_synchronization_refs", None),
                ("rule_implementation_ref",),
            ),
        ),
        "autonomous-evaluation-clock-subject-source-r4": (
            "successor_clock",
            "evaluation_subject",
            (
                ("content_ref",),
                ("first_sample_source_ref",),
                ("ordered_receipt_refs", None),
                ("schema_registry_ref",),
                ("verification_controller_identity_ref",),
                ("whole_base_policy_ref",),
                ("whole_limits_ref",),
                ("whole_trust_context_ref",),
            ),
        ),
        "autonomous-evaluation-clock-witness-source-r4": (
            "successor_clock",
            "evaluation_witness",
            (
                ("acceptance_body_ref",),
                ("acceptance_statement_ref",),
                ("after", "clock_sample_raw_ref"),
                ("before", "clock_sample_raw_ref"),
                ("complete_authorization_obligations_ref",),
                ("controller_identity_ref",),
                ("first_sample_source_ref",),
                ("holdover_and_use_error_derivation_ref",),
                ("monotonic_domain_ref",),
                ("observer_identity_ref",),
                ("ordered_acceptance_receipt_refs", None),
                ("profile_ref",),
                ("raw_synchronization_refs", None),
                ("subject_ref",),
                ("use_sample_raw_ref",),
                ("whole_conditions_and_limitations_ref",),
            ),
        ),
        "autonomous-evaluation-clock-first-sample-source-r4": (
            "successor_clock",
            "first_sample",
            (
                ("boot_domain_ref",),
                ("process_start_identity_ref",),
                ("raw_sample_ref",),
                ("source_profile_ref",),
                ("verification_controller_identity_ref",),
            ),
        ),
        "emt-protected-control-rule-source-r6": (
            "successor_control",
            "control_rule",
            (
                ("bootstrap_rule_ref",),
                ("certificate_rule_ref",),
                ("controller_identity_rule_ref",),
                ("implementation_environment_ref",),
                ("implementation_method_ref",),
                ("independent_root_selection_ref",),
                ("protected_custody_rule_ref",),
                ("revocation_rule_ref",),
                ("rotation_rule_ref",),
                ("scope_source_ref",),
                ("snapshot_rule_ref",),
                ("whole_conditions_and_limitations_ref",),
                ("whole_legacy_base_policy_ref",),
            ),
        ),
        "emt-protected-control-selection-source-r6": (
            "successor_control",
            "control_selection",
            (
                ("control_rule_ref",),
                ("entries", None, "authorization_ref"),
                ("entries", None, "authorizing_state_ref"),
                ("entries", None, "scope_ref"),
                ("entries", None, "statement_ref"),
                ("entries", None, "target_ref"),
            ),
        ),
        "emt-foreign-github-identity-rule-source-r1": (
            "successor_identity_rules",
            "foreign_rule",
            (
                ("complete_argv_and_field_mapping_rule_ref",),
                ("expected_repository_and_immutable_ids_ref",),
                ("expected_signer_workflow_and_commit_ref",),
                ("independent_trusted_root_acquisition_rule_ref",),
                ("required_authenticated_field_mapping_ref",),
                ("root_refresh_rule_ref",),
                ("verifier_implementation_qualification_ref",),
            ),
        ),
        "emt-seat-identity-rule-source-r1": (
            "successor_identity_rules",
            "identity_rule",
            (
                ("actual_key_possession_rule_ref",),
                ("client_catalogue_source_ref",),
                ("launcher_or_observer_procedure_ref",),
                ("required_claim_limitations_rule_ref",),
            ),
        ),
        "emt-independent-validation-rule-source-r1": (
            "successor_identity_rules",
            "validation_rule",
            (
                ("comparison_rule_ref",),
                ("exact_claim_limitations_and_report_mapping_ref",),
                ("independent_identity_policy_ref",),
                ("native_or_foreign_authorization_rule_ref",),
                ("required_time_binding_rule_ref",),
                ("run_and_seal_before_comparison_procedure_ref",),
                ("whole_subject_and_parent_reconstruction_rule_ref",),
            ),
        ),
        "emt-successor-class-context-presentation-r4": (
            "successor_class_context",
            "",
            (
                ("claim_classes", None, "tuple", "limitations_ref"),
                ("claim_classes", None, "whole_source_refs", None),
                ("content_ref",),
                ("policy_ref",),
            ),
        ),
        "EMT_CALLER_TRUST_UNSIGNED_V2": ("successor_caller_trust", "unsigned_context", ()),
        "EMT_CALLER_TRUST_SOFTWARE_V2": ("successor_caller_trust", "software_context", ()),
        "EMT_CALLER_TRUST_DELEGATED_V2": ("successor_caller_trust", "delegated_context", ()),
    }
)
