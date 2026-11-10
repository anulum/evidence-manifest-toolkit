# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — fixed local policy procedure selectors

"""Select only the finite authored policy procedures; arbitrary prose is never executable."""

FIXTURE_NAMESPACE = "PROSPECTIVE_PUBLISHED_RFC_FIXTURE_ONLY_NOT_OPERATIONAL"
OPERATIONAL_NAMESPACE = "OWNER_LOCAL_VERIFICATION_POLICY_V1"
CLOSURE_RULE = (
    "All original independently selected when_present/common/control references; "
    "preserve all optional absence diagnostics."
)
FIXTURE_TIME_RULE = (
    "Explicit fixture point2026-10-03T12:00:00Z under original half-open snapshot/certificate "
    "windows, never actual trusted current clock."
)
OPERATIONAL_TIME_RULE = (
    "Explicit caller UTC under original half-open snapshot/certificate windows; "
    "independently qualified evaluation-time source required."
)
FIXTURE_ROOT_RULE = (
    "Prior independent acceptance of the exact published fixture root/control namespace "
    "is a required future premise; these inputs do not authenticate operational keys "
    "or enroll hardware."
)
OPERATIONAL_ROOT_RULE = (
    "Existing independently owner-approved local bootstrap/current configuration; "
    "no artifact approval or root provisioning."
)
CLOCK_REQUIREMENT = (
    "independent previously accepted clock/time-selection method and full source/capture/controller "
    "identity"
)
CLOCK_SOURCE_CONTRACT = (
    "Existing selected common8 UTC/time qualification boundary; this explicit prospective "
    "policy extension needs affected selection and adds no TrustContext field."
)
BASE_FIELDS = (
    "namespace",
    "required_claim_ids",
    "required_purposes",
    "required_principal",
    "required_role",
    "required_segment",
    "required_closure",
    "time_rule",
    "root_and_key_rule",
)
CLOCK_FIELD = "required_evaluation_time_qualification"
