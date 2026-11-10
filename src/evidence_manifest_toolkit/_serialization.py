# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact diagnostic result transport

"""Serialize existing report values without assigning an evidence schema or eligibility."""

import rfc8785

from ._immutable import thaw_json
from ._json import JsonValue
from ._results import Difference, Inspection, ReferenceObservation, VerificationReport
from ._values import BlobRef, Reason


def reference_mapping(reference: BlobRef) -> dict[str, JsonValue]:
    """Retain exact reference strings and omit absent optional schema metadata.

    Parameters
    ----------
    reference : BlobRef
        Complete existing public value, checked through its actual value method.

    Returns
    -------
    dict
        Four required fields plus the optional nonnull schema_id; no identity is recomputed.
    """
    return dict(reference.to_mapping())


def reason_mapping(reason: Reason) -> dict[str, JsonValue]:
    """Preserve all five located reason fields, including their documented nulls.

    Parameters
    ----------
    reason : Reason
        Existing whole caller-safe refusal without interpreter or filesystem details.

    Returns
    -------
    dict
        Exact code, actual subject/claim/pointer and deliberately authored detail.
    """
    return {
        "code": reason.code,
        "subject_digest": reason.subject_digest,
        "claim_id": reason.claim_id,
        "pointer": reason.pointer,
        "detail": reason.detail,
    }


def observation_mapping(observation: ReferenceObservation) -> dict[str, JsonValue]:
    """Preserve every original edge observation independently of read deduplication.

    Parameters
    ----------
    observation : ReferenceObservation
        Actual selected subject/path/pointer, declared requirement and acquired outcome.

    Returns
    -------
    dict
        Entire seven-field observation; missing digest-only metadata stays reference=null.
    """
    return {
        "subject_digest": observation.subject_digest,
        "path_id": observation.path_id,
        "pointer": observation.pointer,
        "required": observation.required,
        "reference": None
        if observation.reference is None
        else reference_mapping(observation.reference),
        "outcome": observation.outcome,
        "reasons": [reason_mapping(reason) for reason in observation.reasons],
    }


def report_mapping(report: Inspection | Difference | VerificationReport) -> dict[str, JsonValue]:
    """Serialize the existing closed result type field-for-field.

    Parameters
    ----------
    report : Inspection, Difference or VerificationReport
        Entire returned library report. Tuple order and all actual null fields are retained.

    Returns
    -------
    dict
        Six inspection, eight difference or fifteen verification fields, with no added
        accepted/eligible flag, registered evidence schema or inferred domain decision.
    """
    if isinstance(report, Inspection):
        return {
            "schema_id": report.schema_id,
            "content_ref": None
            if report.content_ref is None
            else reference_mapping(report.content_ref),
            "declared_claims": [thaw_json(claim) for claim in report.declared_claims],
            "declared_references": [reference_mapping(ref) for ref in report.declared_references],
            "acceptance": report.acceptance,
            "reasons": [reason_mapping(reason) for reason in report.reasons],
        }
    if isinstance(report, Difference):
        return {
            "left_ref": reference_mapping(report.left_ref),
            "right_ref": reference_mapping(report.right_ref),
            "content_equal": report.content_equal,
            "changed_paths": list(report.changed_paths),
            "left_envelope_refs": [reference_mapping(ref) for ref in report.left_envelope_refs],
            "right_envelope_refs": [reference_mapping(ref) for ref in report.right_envelope_refs],
            "receipts_equal": report.receipts_equal,
            "acceptance": report.acceptance,
        }
    return {
        "content_ref": reference_mapping(report.content_ref),
        "policy_ref": reference_mapping(report.policy_ref),
        "registry_ref": reference_mapping(report.registry_ref),
        "evaluation_mode": report.evaluation_mode,
        "evaluation_time": report.evaluation_time,
        "evaluated_claim_ids": list(report.evaluated_claim_ids),
        "structure": report.structure,
        "integrity": report.integrity,
        "authenticity": report.authenticity,
        "availability": report.availability,
        "common_eligibility": report.common_eligibility,
        "domain_verdict": report.domain_verdict,
        "current_eligibility": report.current_eligibility,
        "reference_observations": [
            observation_mapping(edge) for edge in report.reference_observations
        ],
        "reasons": [reason_mapping(reason) for reason in report.reasons],
    }


def report_bytes(report: Inspection | Difference | VerificationReport) -> bytes:
    """Encode the complete diagnostic mapping as the selected canonical transport bytes.

    Parameters
    ----------
    report : Inspection, Difference or VerificationReport
        Actual complete library result, without private schema or trust reconstruction.

    Returns
    -------
    bytes
        RFC8785 bytes with no BOM, padding or trailing newline; stdout and file share these bytes.
    """
    return rfc8785.dumps(report_mapping(report))


def error_bytes(operation: str, reasons: tuple[Reason, ...]) -> bytes:
    """Encode the original ErrorResult with no success or eligibility fields.

    Parameters
    ----------
    operation : str
        Actual recognized operation or the executable's invocation diagnostic context.
    reasons : tuple of Reason
        Whole deliberately authored refusal population; no exception text is substituted.

    Returns
    -------
    bytes
        Exactly operation and reasons under the same canonical diagnostic byte contract.
    """
    return rfc8785.dumps(
        {"operation": operation, "reasons": [reason_mapping(reason) for reason in reasons]}
    )
