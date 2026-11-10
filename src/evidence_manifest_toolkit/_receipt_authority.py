# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact whole receipt delegation and scope

"""Verify supplied complete receipt messages under independently selected native authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

from ._budget import ReferenceBudget
from ._codecs import decode_bytes, decode_reference
from ._control_authentication import authenticate_control
from ._control_context import references_agree
from ._envelopes import ParsedEnvelope
from ._interfaces import Resolver
from ._json import JsonValue
from ._policy_source import PolicyDeclaration
from ._results import ReferenceObservation
from ._snapshot_history import revocation_reasons
from ._statements import key_id
from ._trust_state import SelectedTrustState
from ._trust_types import TrustContext
from ._typed_control import acquire_control_link
from ._utc import utc_key
from ._values import BlobRef, Reason

if TYPE_CHECKING:
    from ._native_signature import NativeVerifier


@dataclass(frozen=True, slots=True)
class ReceiptAuthority:
    """Retain actual signature correspondence, accepted scope and every located failure.

    Attributes
    ----------
    verified : bool
        Complete cryptography, native delegation and scope checks succeeded for this receipt.
    claim_ids : tuple of str
        Entire actual scoped population; no receipt broadens its original signed scope.
    purpose : str
        Exact original native purpose, distinct from a caller's required purpose population.
    observations : tuple of ReferenceObservation
        Both actual typed-control lookups, including full original absence diagnostics.
    reasons : tuple of Reason
        All actual receipt profile, signature, source, purpose, role and scope refusals.
    """

    verified: bool
    claim_ids: tuple[str, ...]
    purpose: str
    observations: tuple[ReferenceObservation, ...]
    reasons: tuple[Reason, ...]


def receipt_authority(
    envelope: ParsedEnvelope,
    *,
    content_reference: BlobRef,
    actual_claim_ids: tuple[str, ...],
    state: SelectedTrustState,
    trust: TrustContext,
    policy: PolicyDeclaration | None,
    resolver: Resolver,
    budget: ReferenceBudget,
    verifier: NativeVerifier,
) -> ReceiptAuthority:
    """Evaluate the entire supplied receipt without replacing unavailable source facts.

    Parameters
    ----------
    envelope : ParsedEnvelope
        Original full schema-valid receipt and exact domain-prefixed message bytes.
    content_reference : BlobRef
        Actual whole independently validated content identity and selected schema.
    actual_claim_ids : tuple of str
        Whole native inventory against which the actual receipt scope resolves.
    state : SelectedTrustState
        Entire independently selected current/archive control graph and authenticated sources.
    trust : TrustContext
        Original explicit UTC/current/floor/archive selection, never a producer clock assertion.
    policy : PolicyDeclaration or None
        Complete selected principal/role/segment requirements, absent only if source unavailable.
    resolver : Resolver
        Actual bounded source for the two original known control digest links.
    budget : ReferenceBudget
        Sole shared acquisition budget, retaining cached actual bytes and every assertion.
    verifier : NativeVerifier
        Actual full-profile whole-message verification implementation.

    Returns
    -------
    ReceiptAuthority
        Entire receipt outcome. Prior caller approval and external clock/domain qualification
        are separate; neither a signed timestamp nor a matching key supplies them.
    """
    statement = envelope.statement
    reasons = list(envelope.reasons)
    observations: list[ReferenceObservation] = []
    claims = tuple(cast(list[str], statement.get("claim_ids", [])))
    purpose = cast(str, statement["purpose"])

    def refuse(name: str, code: str = "invalid_delegation") -> None:
        """Append an exact receipt-field refusal while retaining other actual failures.

        Parameters
        ----------
        name : str
            Original statement field, not a fabricated JSON position.
        code : str
            Applicable native delegation, scope or root code.
        """
        reasons.append(
            Reason(
                code,
                envelope.envelope_ref.digest,
                None,
                "/statement/" + name,
                "Detached statement does not match its independently selected authority or scope.",
            )
        )

    for name, expected in (
        ("content_digest", content_reference.digest),
        ("content_schema_id", content_reference.schema_id),
        ("content_byte_length", content_reference.byte_length),
    ):
        if statement[name] != expected:
            refuse(name, "scope_missing")
    if statement["signature_context"] == "root_control":
        if content_reference.schema_id not in (
            "evidence_manifest_toolkit.group_certificate.v1",
            "evidence_manifest_toolkit.trust_snapshot.v1",
        ):
            refuse("content_schema_id", "scope_missing")
        if statement["bootstrap_policy_digest"] != trust.bootstrap_policy_ref.digest:
            refuse("bootstrap_policy_digest", "untrusted_root")
        if statement["signer_key_id"] != state.bootstrap.root_key_id:
            refuse("signer_key_id", "untrusted_root")
        expected_purpose = (
            (content_reference.schema_id or "")
            .removeprefix("evidence_manifest_toolkit.")
            .removesuffix(".v1")
        )
        if purpose != expected_purpose:
            refuse("purpose", "scope_missing")
        public_key = state.bootstrap.root_public_key
    else:
        if content_reference.schema_id != "evidence_manifest_toolkit.manifest.v1":
            refuse("content_schema_id", "scope_missing")
        for index, identifier in enumerate(claims):
            if identifier not in actual_claim_ids:
                reasons.append(
                    Reason(
                        "scope_missing",
                        envelope.envelope_ref.digest,
                        identifier,
                        "/statement/claim_ids/" + str(index),
                        "Signed claim scope does not resolve in the complete content.",
                    )
                )
        control_fields: tuple[Literal["group_certificate_digest", "trust_snapshot_digest"], ...] = (
            "group_certificate_digest",
            "trust_snapshot_digest",
        )
        links = tuple(
            acquire_control_link(
                cast(str, statement[field]),
                field=field,
                statement_digest=envelope.statement_ref.digest,
                resolver=resolver,
                budget=budget,
            )
            for field in control_fields
        )
        for link in links:
            observations.append(link.observation)
            reasons.extend(link.observation.reasons)
        certificate_link, snapshot_link = links
        if snapshot_link.reference is not None and not references_agree(
            snapshot_link.reference,
            state.selected_reference,
            expected_schema="evidence_manifest_toolkit.trust_snapshot.v1",
        ):
            refuse("trust_snapshot_digest")
        certificate_ref, document = certificate_link.reference, certificate_link.document
        if certificate_ref is None or document is None or not state.selected_history.nodes:
            return ReceiptAuthority(False, claims, purpose, tuple(observations), tuple(reasons))
        certificate = cast(dict[str, JsonValue], document.value)
        selected = cast(dict[str, JsonValue], state.selected_history.nodes[0].document.value)
        delegates = tuple(
            decode_reference(
                value,
                subject=state.selected_reference.digest,
                pointer="/group_certificate_refs/" + str(index),
            )
            for index, value in enumerate(cast(list[JsonValue], selected["group_certificate_refs"]))
        )
        if not any(
            references_agree(
                certificate_ref,
                candidate,
                expected_schema="evidence_manifest_toolkit.group_certificate.v1",
            )
            for candidate in delegates
        ):
            refuse("group_certificate_digest")
        authenticated = authenticate_control(
            certificate_ref,
            purpose="group_certificate",
            issuer_root_key_id=cast(str, certificate["issuer_root_key_id"]),
            bootstrap_policy_digest=trust.bootstrap_policy_ref.digest,
            pinned_root_public_key=state.bootstrap.root_public_key,
            envelopes=state.envelopes,
            verifier=verifier,
        )
        reasons.extend(authenticated.reasons)
        if statement["signer_key_id"] != certificate["subject_key_id"]:
            refuse("signer_key_id")
        if purpose not in cast(list[str], certificate["allowed_purposes"]):
            refuse("purpose")
        if policy is not None:
            if policy.required_principal != certificate["principal"]:
                refuse("signer_key_id")
            if policy.required_role not in cast(list[str], certificate["roles"]):
                refuse("group_certificate_digest")
            if policy.required_segment not in cast(
                list[str], certificate["permitted_tool_segments"]
            ):
                refuse("group_certificate_digest")
        if "evidence_manifest_toolkit" not in cast(
            list[str], certificate["permitted_tool_segments"]
        ):
            refuse("group_certificate_digest")
        evaluation = utc_key(trust.evaluation_time)
        if (
            not utc_key(cast(str, certificate["not_before"]))
            <= evaluation
            < utc_key(cast(str, certificate["not_after"]))
        ):
            refuse("group_certificate_digest")
        reasons.extend(
            revocation_reasons(
                state.history,
                key_id=cast(str, statement["signer_key_id"]),
            )
        )
        if state.selected_history is not state.history:
            reasons.extend(
                revocation_reasons(
                    state.selected_history,
                    key_id=cast(str, statement["signer_key_id"]),
                )
            )
        try:
            public_key = decode_bytes(cast(str, certificate["public_key_base64url"]))
        except ValueError:
            refuse("group_certificate_digest")
            return ReceiptAuthority(False, claims, purpose, tuple(observations), tuple(reasons))
        if (
            not verifier.public_key_valid(public_key)
            or key_id(public_key) != certificate["subject_key_id"]
        ):
            refuse("group_certificate_digest")
    if not verifier.verify(public_key, envelope.message, envelope.signature):
        reasons.append(
            Reason(
                "invalid_signature",
                envelope.envelope_ref.digest,
                None,
                "/signature",
                "Detached signature does not verify for its complete message.",
            )
        )
    return ReceiptAuthority(not reasons, claims, purpose, tuple(observations), tuple(reasons))
