# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — fixed native declaration positions

"""Retain the eight known common declaration shapes without artifact discovery."""

from collections.abc import Mapping
from types import MappingProxyType

# None denotes the reviewed array-each step; every string is a literal member.
DECLARED_PATHS: Mapping[str, tuple[tuple[str | None, ...], ...]] = MappingProxyType(
    {
        "evidence_manifest_toolkit.adapter_conformance.v1": (
            ("descriptor_ref",),
            ("adapter_source_ref",),
            ("profile_ref",),
            ("vectors_ref",),
            ("results", None, "evidence_ref"),
        ),
        "evidence_manifest_toolkit.group_certificate.v1": (),
        "evidence_manifest_toolkit.manifest.v1": (
            ("payload_ref",),
            ("source_ref",),
            ("environment_ref",),
            ("claims", None, "scope", "conditions_ref"),
            ("claims", None, "source_refs", None),
            ("claims", None, "validation", "record_ref"),
            ("claims", None, "measurement", "target_ref"),
            ("claims", None, "measurement", "instrument_ref"),
            ("claims", None, "measurement", "acceptance_record_ref"),
            ("claims", None, "measurement", "uncertainty_record_ref"),
            ("derived_from", None),
        ),
        "evidence_manifest_toolkit.registry_snapshot.v1": (
            ("entries", None, "schema_ref"),
            ("entries", None, "schema_dependencies", None, "schema_ref"),
            ("entries", None, "domain_verifier_ref"),
            ("entries", None, "domain_qualification_ref"),
        ),
        "evidence_manifest_toolkit.signed_statement.v1": (),
        "evidence_manifest_toolkit.studio_mapping.v1": (
            ("source_bundle_ref",),
            ("destination_content_ref",),
            ("platform_source_ref",),
            ("platform_vectors_ref",),
            ("policy_ref",),
            ("freshness_evaluation", "expected_source_identity_ref"),
            ("freshness_evaluation", "observed_source_identity_ref"),
            ("freshness_evaluation", "evaluation_record_ref"),
        ),
        "evidence_manifest_toolkit.target_descriptor.v1": (
            ("hardware_ref",),
            ("environment_ref",),
            ("toolchain_ref",),
            ("capabilities", "timebase", "parameters_ref"),
            ("capabilities", "timebase", "limits_ref"),
            ("capabilities", "event_transport", "parameters_ref"),
            ("capabilities", "event_transport", "limits_ref"),
            ("capabilities", "power_monitor", "parameters_ref"),
            ("capabilities", "power_monitor", "limits_ref"),
            ("capabilities", "fault_control", "parameters_ref"),
            ("capabilities", "fault_control", "limits_ref"),
            ("capabilities", "run_control", "parameters_ref"),
            ("capabilities", "run_control", "limits_ref"),
            ("capabilities", "boot_reset", "parameters_ref"),
            ("capabilities", "boot_reset", "limits_ref"),
        ),
        "evidence_manifest_toolkit.trust_snapshot.v1": (
            ("group_certificate_refs", None),
            ("revocations", None, "compromise_time_bounds_ref"),
            ("registry_ref",),
            ("previous_snapshot_ref",),
        ),
    }
)
