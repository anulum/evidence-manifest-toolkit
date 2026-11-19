# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original fifteen-field verification gate composition

"""Compose actual independent common gates without assigning a scientific verdict."""

from typing import Literal

from ._difference import utf16_key
from ._errors import InputRefused
from ._receipt_authority import ReceiptAuthority
from ._registry_types import SchemaRegistry
from ._results import ReferenceObservation, VerificationReport
from ._successor_trust import UnsignedTrustContextV2
from ._trust_state import SelectedTrustState
from ._trust_types import TrustContext, VerificationPolicy
from ._values import Reason, Utc
from ._verification_inputs import VerificationInputs


def _observations(
    inputs: VerificationInputs,
    state: SelectedTrustState | None,
    receipts: tuple[ReceiptAuthority, ...],
) -> tuple[ReferenceObservation, ...]:
    """Retain every actual distinct edge in the original UTF-16 diagnostic order.

    Parameters
    ----------
    inputs : VerificationInputs
        Whole selected content edges, including actual optional absence and failures.
    state : SelectedTrustState or None
        Complete selected current/archive control and catalogue edges; None for the
        unsigned V2 route, which selects no authority state and so has no state edges.
    receipts : tuple of ReceiptAuthority
        Actual typed-control observations for every explicitly supplied statement.

    Returns
    -------
    tuple of ReferenceObservation
        Complete ordered edge population, preserving original metadata and all located reasons.

    Raises
    ------
    InputRefused
        Repeated instances of one actual edge contradict their observed source facts.
    """
    selected: dict[tuple[str, str, str], ReferenceObservation] = {}
    source = (
        *inputs.content.closure.observations,
        *(() if state is None else state.closure.observations),
        *(edge for receipt in receipts for edge in receipt.observations),
    )
    for edge in source:
        key = edge.subject_digest, edge.path_id, edge.pointer
        previous = selected.get(key)
        if previous is not None and previous != edge:
            raise InputRefused(
                Reason(
                    "invalid_schema",
                    edge.subject_digest,
                    None,
                    edge.pointer,
                    "Reference observations conflict.",
                )
            )
        selected[key] = edge
    ordered = sorted(selected, key=lambda key: tuple(utf16_key(part) for part in key))
    return tuple(selected[key] for key in ordered)


def compose_verification_report(
    inputs: VerificationInputs,
    *,
    state: SelectedTrustState | None,
    receipts: tuple[ReceiptAuthority, ...],
    policy: VerificationPolicy,
    trust: TrustContext | UnsignedTrustContextV2,
    registry: SchemaRegistry,
) -> VerificationReport:
    """Return all fifteen original fields from the complete actually evaluated common sources.

    Parameters
    ----------
    inputs : VerificationInputs
        Whole acquired content/native semantics and referenced local policy.
    state : SelectedTrustState or None
        Complete independently selected current/archive state and all computable failures;
        None for the unsigned V2 route, which never selects bootstrap or current state.
    receipts : tuple of ReceiptAuthority
        Complete actual full-message receipt outcomes and signed claim/purpose populations;
        always empty for the unsigned route, whose pairing refuses every envelope.
    policy : VerificationPolicy
        Original caller's exact claim/purpose/reference selection.
    trust : TrustContext or UnsignedTrustContextV2
        Original explicit mode/UTC/floor and already accepted independent local selection,
        or the unsigned V2 context, whose current eligibility is always refused.
    registry : SchemaRegistry
        Original independent complete registry and its unmodified source identity.

    Returns
    -------
    VerificationReport
        Separate structure/integrity/authenticity/availability/common/domain/current axes.
        Historical or claim/domain output never becomes a current scientific pass.
    """
    content = inputs.content
    state_reasons = () if state is None else state.reasons
    reasons = [*content.reasons, *inputs.policy_source.reasons, *state_reasons]
    reasons.extend(reason for receipt in receipts for reason in receipt.reasons)
    obligations = content.content_claim_obligations
    unsigned = isinstance(trust, UnsignedTrustContextV2)
    # The unsigned V2 route has already applied the selected signature-obligation rule (its exception and
    # scope) and raised its first reason; the legacy receipt rules below would contradict that exception.
    if not unsigned:
        available = {claim.claim_id for claim in content.content_claim_obligations}
        for identifier in policy.required_claim_ids:
            if identifier not in available:
                reasons.append(
                    Reason(
                        "scope_missing",
                        content.content_ref.digest,
                        identifier,
                        "/claims",
                        "Required claim scope does not resolve in the complete content.",
                    )
                )
        requires_signature = (
            bool(policy.required_purposes)
            or any(claim.signature_required for claim in obligations)
            or content.content_ref.schema_id
            in (
                "evidence_manifest_toolkit.group_certificate.v1",
                "evidence_manifest_toolkit.trust_snapshot.v1",
            )
        )
        if requires_signature and not receipts:
            reasons.append(
                Reason(
                    "signature_required",
                    content.content_ref.digest,
                    None,
                    None,
                    "The required evidence signature is unavailable.",
                )
            )
        for identifier in policy.required_claim_ids:
            for purpose in policy.required_purposes:
                if receipts and not any(
                    receipt.verified
                    and receipt.purpose == purpose
                    and identifier in receipt.claim_ids
                    for receipt in receipts
                ):
                    reasons.append(
                        Reason(
                            "scope_missing",
                            content.content_ref.digest,
                            identifier,
                            "/claims",
                            "Required signed claim and purpose scope is unavailable.",
                        )
                    )
        for purpose in policy.required_purposes:
            if receipts and not any(
                receipt.verified and receipt.purpose == purpose for receipt in receipts
            ):
                reasons.append(
                    Reason(
                        "scope_missing",
                        content.content_ref.digest,
                        None,
                        None,
                        "Required signed purpose is unavailable.",
                    )
                )
        for obligation in obligations:
            if (
                obligation.signature_required
                and not any(
                    receipt.verified and obligation.claim_id in receipt.claim_ids
                    for receipt in receipts
                )
                and receipts
            ):
                reasons.append(
                    Reason(
                        "signature_required",
                        content.content_ref.digest,
                        obligation.claim_id,
                        "/claims",
                        "The required evidence signature is unavailable.",
                    )
                )
            if obligation.validation_record_signature_required:
                reference = obligation.validation_record
                if reference is not None:
                    reasons.append(
                        Reason(
                            "signature_required",
                            reference.digest,
                            obligation.claim_id,
                            None,
                            "The required validation record signature is unavailable.",
                        )
                    )
    declaration = inputs.policy_declaration
    if declaration is None:
        reasons.append(
            Reason(
                "policy_unavailable",
                policy.policy_ref.digest,
                None,
                None,
                "Required local verification policy is unavailable.",
            )
        )
    elif declaration.requires_clock:
        reasons.append(
            Reason(
                "policy_unavailable",
                policy.policy_ref.digest,
                None,
                "/required_evaluation_time_qualification/clock_qualification_ref",
                "The required evaluation-time qualification is unavailable.",
            )
        )
    codes = {reason.code for reason in reasons}
    structure: Literal["valid", "invalid", "unsupported"] = (
        "unsupported"
        if codes & {"unknown_schema", "unsupported_profile"}
        else "invalid"
        if codes & {"invalid_schema", "invalid_claim", "cycle_detected", "limit_exceeded"}
        else "valid"
    )
    observations = _observations(inputs, state, receipts)
    required = tuple(edge for edge in observations if edge.required)
    unavailable = "reference_unavailable" in codes
    integrity: Literal["matched", "mismatched", "unavailable"] = (
        "mismatched"
        if "reference_mismatch" in codes
        else "unavailable"
        if unavailable
        else "matched"
    )
    availability: Literal["complete", "partial", "unavailable"] = (
        "complete"
        if not unavailable
        else "partial"
        if any(edge.outcome == "matched" for edge in required)
        else "unavailable"
    )
    authenticity: Literal["trusted", "untrusted", "unsigned", "unavailable"] = (
        "unsigned"
        if not receipts
        else "unavailable"
        if any(
            edge.outcome == "unavailable" for receipt in receipts for edge in receipt.observations
        )
        else "trusted"
        if all(receipt.verified for receipt in receipts) and not state_reasons
        else "untrusted"
    )
    eligible = not reasons
    if trust.evaluation_mode == "historical":
        reasons.append(
            Reason(
                "historical_only",
                content.content_ref.digest,
                None,
                None,
                "Historical verification does not establish current eligibility.",
            )
        )
    static = inputs.schemas.get(content.content_ref.schema_id or "")
    domain_required = (
        content.content_ref.schema_id == "evidence_manifest_toolkit.manifest.v1"
        or (
            static is not None
            and (
                static.entry.schema_role.startswith("domain_")
                or static.entry.domain_support != "not_required"
            )
        )
        or bool(obligations)
    )
    if domain_required:
        reasons.append(
            Reason(
                "domain_verifier_required",
                content.content_ref.digest,
                None,
                None,
                "Domain verification is required.",
            )
        )
    return VerificationReport(
        content.content_ref,
        policy.policy_ref,
        registry.snapshot_ref,
        trust.evaluation_mode,
        Utc(trust.evaluation_time),
        policy.required_claim_ids,
        structure,
        integrity,
        authenticity,
        availability,
        "eligible" if eligible else "refused",
        "not_evaluated",
        "eligible"
        if eligible and trust.evaluation_mode == "current" and not domain_required and not unsigned
        else "refused",
        observations,
        tuple(reasons),
    )
