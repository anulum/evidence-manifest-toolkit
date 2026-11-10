# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole native challenge and own-key proof source acquisition

"""Read complete possession inputs without inferring challenge freshness or issuer authority."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._acquisition import acquire_reference
from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._content import CompleteContent, prepare_content
from ._context_sources import acquire_context_source
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._native_record_formats import NativePossessionRecord, NativeRunRecord, native_record_format
from ._schema_resources import StaticSchema
from ._subject_formats import SubjectFormat, subject_format_reasons
from ._successor_envelopes import SuccessorEnvelope, parse_successor_envelope
from ._values import BlobRef, Digest, Reason


def possession_value(source: FixedSource) -> dict[str, JsonValue]:
    """Return the entire already validated native source, retaining every original field.

    Parameters
    ----------
    source : FixedSource
        Complete native record after its fixed schema and byte identity checks.

    Returns
    -------
    dict
        Whole original document; the reader never mutates this mapping.
    """
    return cast(dict[str, JsonValue], cast(AcquiredDocument, source.source.document).value)


def acquire_possession_record(
    reference: BlobRef,
    *,
    kind: NativePossessionRecord | NativeRunRecord,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> FixedSource:
    """Bind one exact source to the owning callsite's complete fixed native record grammar.

    Parameters
    ----------
    reference : BlobRef
        Entire original source argument, without metadata aliases or path discovery.
    kind : NativePossessionRecord or NativeRunRecord
        Literal internal expected record, never selected by received document fields.
    formats : Mapping
        Whole independently selected structural lookup.
    resolver : Resolver
        Sole bounded offline source.
    budget : ReferenceBudget
        SAME invocation limits and metadata cache for every source and schema.
    subject : str
        Actual selecting whole source identity.
    pointer : str
        Original selecting field position.

    Returns
    -------
    FixedSource
        Complete original record, not a qualified controller, possession or time verdict.

    Raises
    ------
    ReferenceUnavailable
        The exact whole required source is absent.
    InputRefused
        Source, metadata, grammar or original cumulative bounds fail.
    ConfigurationError
        The fixed installed grammar or caller resolver is invalid.
    """
    source = acquire_context_source(
        reference,
        expected_control=None,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer=pointer,
    )
    if source.raw_bytes is None:
        raise ReferenceUnavailable(reference)
    if source.document is None:
        raise InputRefused(source.reasons[0])
    grammar = native_record_format(kind, budget=budget, subject=subject, pointer=pointer)
    reasons = subject_format_reasons(
        grammar, source.document, reference, formats=formats, subject=subject, pointer=pointer
    )
    if reasons:
        raise InputRefused(reasons[0])
    return FixedSource(source, grammar)


def acquire_possession_manifest(
    reference: BlobRef,
    *,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> CompleteContent:
    """Validate an entire native C0 and its complete original required source graph.

    Parameters
    ----------
    reference : BlobRef
        Whole actual challenge, candidate receiver or final commit C0 reference.
    formats : Mapping
        Original known caller schemas and fixed Common-native bindings.
    resolver : Resolver
        Sole original bounded source; no issuer or receipt discovery.
    budget : ReferenceBudget
        SAME complete operation budget and graph constraints.
    subject : str
        Actual referring record identity.
    pointer : str
        Original whole C0 reference position.

    Returns
    -------
    CompleteContent
        Full native content, common semantics and source observations. This authenticates
        no issuer, receiver, event time, receipt, transaction or actual execution.

    Raises
    ------
    InputRefused
        Actual C0/schema/reference/common semantics or cumulative bounds fail.
    ReferenceUnavailable
        An exact original required source is absent.
    """
    raw = acquire_reference(
        reference, resolver=resolver, budget=budget, subject=subject, pointer=pointer
    )
    content = prepare_content(
        raw,
        schema_id="evidence_manifest_toolkit.manifest.v1",
        schemas={name: item for name, item in formats.items() if isinstance(item, StaticSchema)},
        formats=formats,
        requirements=(),
        resolver=resolver,
        budget=budget,
    )
    if content.closure.missing_references:
        raise ReferenceUnavailable(content.closure.missing_references[0])
    if content.reasons:
        raise InputRefused(content.reasons[0])
    return content


def possession_receipts(
    value: JsonValue,
    *,
    content: CompleteContent,
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> tuple[SuccessorEnvelope, ...]:
    """Parse every ordered receipt and compare its entire actual C0 target and claim scope.

    Parameters
    ----------
    value : object
        Whole original ordered reference array from a schema-valid result.
    content : CompleteContent
        Actual complete challenge or receiver commit C0.
    resolver : Resolver
        Sole bounded original source.
    budget : ReferenceBudget
        SAME invocation quota for every receipt and native grammar.
    subject : str
        Whole selecting possession-result identity.
    pointer : str
        Original receipt-array field.

    Returns
    -------
    tuple of SuccessorEnvelope
        Every complete target-matched ordinary receipt in its original order. No
        controller signature, issuer eligibility or receipt requirement is admitted.

    Raises
    ------
    InputRefused
        Native context, full target, claim scope, duplicate or source encoding fails.
    ReferenceUnavailable
        An exact original whole receipt is absent.
    """
    result: list[SuccessorEnvelope] = []
    seen: set[BlobRef] = set()
    for index, item in enumerate(cast(list[JsonValue], value)):
        location = pointer + "/" + str(index)
        reference = decode_reference(item, subject=subject, pointer=location)
        raw = acquire_reference(
            reference, resolver=resolver, budget=budget, subject=subject, pointer=location
        )
        envelope = parse_successor_envelope(raw, context="ordinary_statement", budget=budget)
        statement = envelope.statement.value
        target = content.content_ref
        if (
            envelope.reference in seen
            or statement["content_schema_id"] != target.schema_id
            or statement["content_digest"] != target.digest
            or statement["content_byte_length"] != target.byte_length
            or not set(cast(tuple[str, ...], statement["claim_ids"]))
            <= {claim.claim_id for claim in content.content_claim_obligations}
        ):
            raise InputRefused(
                Reason(
                    "scope_missing",
                    subject,
                    None,
                    location,
                    "Native possession receipt target conflicts.",
                )
            )
        seen.add(envelope.reference)
        result.append(envelope)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class NativePossessionSources:
    """Retain all whole proof inputs without granting identity, freshness or custody.

    Attributes
    ----------
    result, challenge, issuer, request : FixedSource
        Complete selected result, original challenge, independent issuer rule and request.
    challenge_manifest, completion_manifest : CompleteContent
        Whole native challenge and final receiver commit C0, not authenticated controllers.
    challenge_receipts, completion_receipts : tuple of SuccessorEnvelope
        Ordered complete target-matched receipts, without native eligibility admission.
    public_key_reference, proof_reference : BlobRef
        Entire original independent key and supplied raw proof references.
    public_key, proof : bytes
        Entire actual source bytes; mathematical verification remains separate.
    """

    result: FixedSource
    challenge: FixedSource
    issuer: FixedSource
    request: FixedSource
    challenge_manifest: CompleteContent
    completion_manifest: CompleteContent
    challenge_receipts: tuple[SuccessorEnvelope, ...]
    completion_receipts: tuple[SuccessorEnvelope, ...]
    public_key_reference: BlobRef
    proof_reference: BlobRef
    public_key: bytes
    proof: bytes
