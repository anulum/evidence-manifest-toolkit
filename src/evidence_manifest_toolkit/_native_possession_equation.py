# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact full-message native own-key equation

"""Verify the source-bound own-key equation without admitting issuer freshness or custody."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from ._acquisition import acquire_reference
from ._budget import ReferenceBudget
from ._closure import ClosureResult, ClosureRoot
from ._codecs import decode_reference
from ._content import CompleteContent
from ._errors import InputRefused
from ._format_sources import FixedSource, close_fixed_sources
from ._interfaces import Resolver
from ._json import JsonValue
from ._native_possession_context import build_native_possession_message
from ._native_possession_issuance import NativeIssuanceSources, check_native_issuance_sources
from ._native_possession_receiver import NativeReceiverSources, check_native_receiver_sources
from ._native_possession_sources import (
    NativePossessionSources,
    acquire_possession_manifest,
    acquire_possession_record,
    possession_receipts,
    possession_value,
)
from ._native_record_formats import NativePossessionRecord, NativeRunRecord
from ._signature_provider import initialize_verifier
from ._subject_formats import SubjectFormat
from ._values import BlobRef, Reason, Utc


@dataclass(frozen=True, slots=True)
class NativePossessionEquation:
    """Retain exact whole inputs and the verified mathematical message, never an admitted class.

    Attributes
    ----------
    sources : NativePossessionSources
        Whole result/challenge/issuer/request, C0s, receipts and actual raw key/proof.
    issuance : NativeIssuanceSources
        Whole independently bound declared issuance state/head and original raw journal,
        without issuer eligibility, unpredictable nonce or native atomic qualification.
    receiver : NativeReceiverSources
        Complete declared candidate/commit/head transition with original event time.
    closure : ClosureResult
        Complete connected graph under the SAME original invocation quota.
    message : bytes
        Exact application domain and entire canonical eight-field message actually verified.
    issued_at, expires_at : Utc
        Original finite half-open challenge tokens, without accepted Clock/issuance time.
    """

    sources: NativePossessionSources
    issuance: NativeIssuanceSources
    receiver: NativeReceiverSources
    closure: ClosureResult
    message: bytes
    issued_at: Utc
    expires_at: Utc


def check_native_possession_equation(
    identity: FixedSource,
    *,
    identity_rule: FixedSource,
    method: FixedSource,
    role: Literal["producer", "runner"],
    expected_request: BlobRef | None,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> NativePossessionEquation | None:
    """Check all supplied native proof sources and the exact own-key message equation.

    Parameters
    ----------
    identity : FixedSource
        Entire earlier selected producer/runner identity, not chosen by the proof.
    identity_rule, method : FixedSource
        Independently selected whole identity and possession method declarations.
    role : {"producer", "runner"}
        Owning callsite role, never an artifact-selected request decoder.
    expected_request : BlobRef or None
        Full independently committed runner request, or absent for an earlier producer
        request whose complete external selection still needs native qualification.
    formats : Mapping
        Original validated structural/native lookup.
    resolver : Resolver
        Sole bounded offline source. Historical paths and commands remain data.
    budget : ReferenceBudget
        SAME original operation quota, cache and graph bounds.

    Returns
    -------
    NativePossessionEquation or None
        Actual raw32/raw64 full-message equation and whole declared receiver evidence,
        or None only when no proof was supplied. None satisfies no required proof.
        A returned equation supplies no independently accepted issuer/request population,
        unpredictable nonce, complete receipts/authority, event Clock, durable receiver,
        observed process capability, key custody or final possession/class admission.

    Raises
    ------
    InputRefused
        Actual method/context/key/request/challenge/receiver/source graph or raw equation fails.
    ReferenceUnavailable
        An exact original required whole source is absent.
    ConfigurationError
        A required known grammar, source configuration or maintained verifier is unavailable.
    """
    declared = possession_value(identity)
    if declared["key_possession_ref"] is None:
        return None
    subject = identity.source.reference.digest

    def refuse(source: FixedSource, field: str, *, signature: bool = False) -> InputRefused:
        """Locate an exact proof contradiction without exposing received source strings."""
        return InputRefused(
            Reason(
                "invalid_signature" if signature else "invalid_claim",
                source.source.reference.digest,
                None,
                "/" + field,
                "Native key-possession sources conflict."
                if not signature
                else "The native key-possession signature is invalid.",
            )
        )

    def child(
        parent: FixedSource, field: str, kind: NativePossessionRecord | NativeRunRecord
    ) -> FixedSource:
        """Keep the entire original field reference and owning fixed interpretation."""
        parent_subject = parent.source.reference.digest
        return acquire_possession_record(
            decode_reference(
                possession_value(parent)[field], subject=parent_subject, pointer="/" + field
            ),
            kind=kind,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=parent_subject,
            pointer="/" + field,
        )

    if declared["declared_public_key_ref"] is None:
        raise refuse(identity, "declared_public_key_ref")
    result = child(identity, "key_possession_ref", "possession_result")
    challenge = child(result, "challenge_ref", "challenge")
    issuer = child(method, "challenge_issuer_rule_ref", "challenge_issuer_rule")
    request = child(challenge, "execution_request_ref", "execution_request")
    value = possession_value(result)
    context = build_native_possession_message(
        identity,
        identity_rule,
        method,
        result,
        challenge,
        issuer,
        request,
        role=role,
        expected_request=expected_request,
    )
    key_reference = decode_reference(
        declared["declared_public_key_ref"], subject=subject, pointer="/declared_public_key_ref"
    )
    public = acquire_reference(
        key_reference,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer="/declared_public_key_ref",
    )
    proof_reference = decode_reference(
        value["proof_bytes_ref"], subject=result.source.reference.digest, pointer="/proof_bytes_ref"
    )
    proof = acquire_reference(
        proof_reference,
        resolver=resolver,
        budget=budget,
        subject=result.source.reference.digest,
        pointer="/proof_bytes_ref",
    )
    manifests: list[CompleteContent] = []
    roots: list[ClosureRoot] = []
    for field in ("challenge_manifest_ref", "receiver_completion_manifest_ref"):
        reference = decode_reference(
            value[field], subject=result.source.reference.digest, pointer="/" + field
        )
        content = acquire_possession_manifest(
            reference,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=result.source.reference.digest,
            pointer="/" + field,
        )
        manifests.append(content)
        raw = budget.cached(reference, subject=result.source.reference.digest, pointer="/" + field)
        roots.append(
            ClosureRoot(
                reference,
                cast(bytes, raw),
                expected_schema_id="evidence_manifest_toolkit.manifest.v1",
            )
        )
    target = manifests[0].content_ref
    manifest = cast(
        dict[str, JsonValue],
        manifests[0]
        .closure.documents[target.digest, target.digest_basis, target.byte_length]
        .value,
    )
    if manifest["payload_ref"] != value["challenge_ref"]:
        raise refuse(result, "challenge_manifest_ref")
    sources = NativePossessionSources(
        result,
        challenge,
        issuer,
        request,
        manifests[0],
        manifests[1],
        possession_receipts(
            value["ordered_challenge_receipt_refs"],
            content=manifests[0],
            resolver=resolver,
            budget=budget,
            subject=result.source.reference.digest,
            pointer="/ordered_challenge_receipt_refs",
        ),
        possession_receipts(
            value["ordered_receiver_receipt_refs"],
            content=manifests[1],
            resolver=resolver,
            budget=budget,
            subject=result.source.reference.digest,
            pointer="/ordered_receiver_receipt_refs",
        ),
        key_reference,
        proof_reference,
        public,
        proof,
    )
    issuance = check_native_issuance_sources(
        sources, formats=formats, resolver=resolver, budget=budget
    )
    receiver = check_native_receiver_sources(
        sources, method=method, formats=formats, resolver=resolver, budget=budget
    )
    closure = close_fixed_sources(
        (
            identity,
            identity_rule,
            method,
            result,
            challenge,
            issuer,
            request,
            *issuance.records,
            *receiver.records,
        ),
        formats=formats,
        resolver=resolver,
        budget=budget,
        additional_roots=(*roots, receiver.candidate_root),
    )
    if closure.missing_references:
        from ._errors import ReferenceUnavailable

        raise ReferenceUnavailable(closure.missing_references[0])
    if closure.reasons:
        raise InputRefused(closure.reasons[0])
    message = context.message
    verifier = initialize_verifier()
    if not verifier.verify(public, message, proof):
        raise refuse(result, "proof_bytes_ref", signature=True)
    return NativePossessionEquation(
        sources, issuance, receiver, closure, message, context.issued_at, context.expires_at
    )
