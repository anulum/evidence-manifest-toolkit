# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — ordinary protected statement source bounds

"""Keep necessary declared source bounds separate from actual protected admission."""

from typing import cast

from ._codecs import decode_reference, reference_value
from ._content import CompleteContent
from ._errors import InputRefused
from ._format_sources import FixedSource
from ._immutable import thaw_json
from ._json import AcquiredDocument, JsonValue
from ._policy_source import PolicyDeclaration
from ._protected_certificate_issuers import match_certificate_parent_issuer
from ._protected_control_sources import ProtectedControlSources
from ._successor_envelopes import SuccessorEnvelope
from ._trust_types import VerificationPolicy
from ._values import Reason, Utc


def match_protected_ordinary_certificate(
    envelope: SuccessorEnvelope,
    *,
    content: CompleteContent,
    protected: ProtectedControlSources,
    declaration: PolicyDeclaration,
    evaluation_time: Utc,
    policy: VerificationPolicy,
) -> FixedSource:
    """Check whole target, selected certificate and declared ordinary source bounds.

    Parameters
    ----------
    envelope : SuccessorEnvelope
        Actual complete parsed ordinary native receipt, without signature admission.
    content : CompleteContent
        Whole actual structurally and semantically prepared C0 and claim inventory.
    protected : ProtectedControlSources
        Entire independently selected state and bounded complete certificate parent graph.
    declaration : PolicyDeclaration
        Whole ordinary principal, role, segment and purpose requirements.
    evaluation_time : Utc
        Original declared caller UTC, not independently qualified Clock evidence.
    policy : VerificationPolicy
        Whole original independent invocation policy for caller-field diagnostics.

    Returns
    -------
    FixedSource
        Whole selected certificate after necessary source matching. Actual group/scope
        interpretation, identity/custody/own-key/signature/Clock admission remain required.

    Raises
    ------
    InputRefused
        Full target/state/certificate/key/parent/scope/claim or declared window conflicts.
    """
    selected = protected.state_sources.selected.fixed
    snapshot = cast(dict[str, JsonValue], cast(AcquiredDocument, selected.source.document).value)
    certificates = {item.source.reference: item for item in protected.certificates}
    grant_reference = protected.state_sources.grant.source.reference
    actual_claims = {claim.claim_id for claim in content.content_claim_obligations}

    def refuse(
        envelope: SuccessorEnvelope, field: str, code: str = "invalid_delegation"
    ) -> InputRefused:
        """Locate a complete statement-source contradiction without echoing received text."""
        return InputRefused(
            Reason(
                code,
                envelope.reference.digest,
                None,
                "/statement/" + field,
                "Protected statement does not match its independently selected source or target.",
            )
        )

    statement = envelope.statement.value
    for field, expected in (
        ("content_digest", content.content_ref.digest),
        ("content_byte_length", content.content_ref.byte_length),
        ("content_schema_id", content.content_ref.schema_id),
        ("authorizing_state_ref", reference_value(selected.source.reference)),
        ("snapshot_ref", reference_value(selected.source.reference)),
    ):
        if statement[field] != expected:
            raise refuse(envelope, field, "scope_missing")
    authorization = thaw_json(statement["authorization_ref"])
    if authorization not in cast(list[JsonValue], snapshot["certificate_refs"]):
        raise refuse(envelope, "authorization_ref")
    reference = decode_reference(
        authorization, subject=envelope.reference.digest, pointer="/statement/authorization_ref"
    )
    certificate = certificates[reference]
    body = cast(dict[str, JsonValue], cast(AcquiredDocument, certificate.source.document).value)
    if statement["signer_key_id"] != body["subject_key_id"]:
        raise refuse(envelope, "signer_key_id")
    scope = cast(dict[str, JsonValue], body["scope"])
    for field, required in (
        ("principal_ids", declaration.required_principal),
        ("roles", declaration.required_role),
        ("tool_segments", declaration.required_segment),
        ("permitted_operations", statement["purpose"]),
    ):
        if required not in cast(list[JsonValue], scope[field]):
            raise refuse(
                envelope, "purpose" if field == "permitted_operations" else "authorization_ref"
            )
    lower, upper = Utc(body["not_before"]), Utc(body["not_after"])
    signed_at = Utc(statement["claimed_signed_at"])
    if signed_at.compare(lower) < 0 or signed_at.compare(upper) >= 0:
        raise refuse(envelope, "claimed_signed_at")
    evaluation = Utc(evaluation_time)
    if evaluation.compare(lower) < 0 or evaluation.compare(upper) >= 0:
        raise InputRefused(
            Reason(
                "invalid_delegation",
                policy.policy_ref.digest,
                None,
                "/trust/evaluation_time",
                "Protected statement does not match its independently selected source or target.",
            )
        )
    for index, identifier in enumerate(cast(tuple[str, ...], statement["claim_ids"])):
        if identifier not in actual_claims:
            raise refuse(envelope, "claim_ids/" + str(index), "scope_missing")
    child = certificate
    parent_reference = decode_reference(
        body["parent_authorization_ref"],
        subject=reference.digest,
        pointer="/parent_authorization_ref",
    )
    while parent_reference != grant_reference:
        parent = certificates[parent_reference]
        ancestor = cast(dict[str, JsonValue], cast(AcquiredDocument, parent.source.document).value)
        match_certificate_parent_issuer(child, parent=parent)
        child, body = parent, ancestor
        parent_reference = decode_reference(
            body["parent_authorization_ref"],
            subject=child.source.reference.digest,
            pointer="/parent_authorization_ref",
        )
    return certificate
