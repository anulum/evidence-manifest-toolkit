# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete disjoint successor statement and envelope parsing

"""Bind the whole V2 statement and native message without assigning signing authority."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

import rfc8785

from ._budget import ReferenceBudget
from ._codecs import DECIMAL_PATTERN, DIGEST_PATTERN, decode_bytes, decode_reference
from ._difference import utf16_key
from ._errors import InputRefused
from ._immutable import FrozenJson, freeze_json
from ._json import AcquiredDocument, JsonValue, acquire_document
from ._references import reference_bytes
from ._successor_formats import load_fixed_format
from ._utc import utc_key
from ._values import BlobRef, Digest, Reason

type SuccessorSignatureContext = Literal["ordinary_statement", "authority_control"]

_STATEMENT_ID = "evidence_manifest_toolkit.signed_statement.v2"
_KEY_ID = re.compile(r"ed25519:[0-9a-f]{64}")
_MESSAGE_PREFIX = b"GOTM-EMT-AUTHORITY-V2\x00"


@dataclass(frozen=True, slots=True)
class SuccessorStatement:
    """Retain the entire admitted V2 declaration and its exact disjoint signing bytes.

    Attributes
    ----------
    value : Mapping
        Complete immutable original sixteen-field statement, including all scope/state
        references, unchanged signing UTC and original sorted unique claim population.
    canonical_bytes : bytes
        Whole RFC8785 statement; no digest projection or invented authorization enters it.
    reference : BlobRef
        Complete canonical statement reference under the independently selected native ID.
    message : bytes
        Exact ASCII authority-v2 domain, one NUL and those complete canonical bytes.
    context : {"ordinary_statement", "authority_control"}
        Explicit owning-method selection, matched against the complete actual statement.
        Shape/context/message matching supplies no authority or provider qualification.
    """

    value: Mapping[str, FrozenJson]
    canonical_bytes: bytes
    reference: BlobRef
    message: bytes
    context: SuccessorSignatureContext


@dataclass(frozen=True, slots=True)
class SuccessorEnvelope:
    """Retain the complete two-field receipt without borrowing legacy or foreign meaning.

    Attributes
    ----------
    canonical_bytes : bytes
        Entire actual statement/signature object represented by RFC8785.
    reference : BlobRef
        Whole envelope identity; no extra registered envelope schema is fabricated.
    statement : SuccessorStatement
        Whole V2 declaration and exact disjoint message, not a V1 ParsedEnvelope.
    signature : bytes
        Exact canonical Base64URL-decoded raw64 response. Parsing does not verify it.
    """

    canonical_bytes: bytes
    reference: BlobRef
    statement: SuccessorStatement
    signature: bytes


def parse_successor_statement(
    document: AcquiredDocument,
    *,
    context: SuccessorSignatureContext,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> SuccessorStatement:
    """Check every original field before constructing the complete V2 signing target.

    Parameters
    ----------
    document : AcquiredDocument
        Complete strict source, retaining original JSON bytes and numeric token custody.
    context : {"ordinary_statement", "authority_control"}
        Independently selected ordinary or protected internal method; never a received
        field choosing code, new public operation or legacy-purpose reinterpretation.
    budget : ReferenceBudget
        SAME operation budget for the complete installed native schema and all dependencies.
    subject : str
        Actual containing envelope or requested content identity for safe diagnostics.
    pointer : str
        Actual complete statement position in its containing source.

    Returns
    -------
    SuccessorStatement
        Full immutable declaration and exact domain-separated message. Actual target,
        key, class, state, scope, time and revocation authority are separately required.

    Raises
    ------
    ConfigurationError
        The complete fixed installed source definition is unavailable or changed.
    InputRefused
        Source shape/context, exact lexical Ref/key/digest/length/UTC or UTF16 claim
        order conflicts, or the shared source/canonical bounds are exceeded.
    """
    selected = load_fixed_format(_STATEMENT_ID, pointer=pointer, budget=budget)
    failures = selected.reasons(document.value, subject=subject)
    if failures:
        error = failures[0]
        raise InputRefused(
            Reason(
                error.code, subject, error.claim_id, pointer + (error.pointer or ""), error.detail
            )
        )
    value = cast(dict[str, JsonValue], document.value)
    if value["signature_context"] != context:
        raise InputRefused(
            Reason(
                "invalid_schema",
                subject,
                None,
                pointer + "/signature_context",
                "Native statement context conflicts with its independently selected route.",
            )
        )
    if (
        context == "ordinary_statement"
        and value["content_schema_id"] != "evidence_manifest_toolkit.manifest.v1"
    ):
        raise InputRefused(
            Reason(
                "scope_missing",
                subject,
                None,
                pointer + "/content_schema_id",
                "Ordinary statements require the complete native manifest.",
            )
        )
    for name, pattern in (
        ("content_digest", DIGEST_PATTERN),
        ("content_byte_length", DECIMAL_PATTERN),
        ("signer_key_id", _KEY_ID),
    ):
        if pattern.fullmatch(cast(str, value[name])) is None:
            raise InputRefused(
                Reason(
                    "invalid_schema",
                    subject,
                    None,
                    pointer + "/" + name,
                    "Invalid native statement field encoding.",
                )
            )
    for name in ("authorizing_state_ref", "authorization_ref", "scope_ref", "snapshot_ref"):
        if value[name] is not None:
            decode_reference(value[name], subject=subject, pointer=pointer + "/" + name)
    utc_key(
        cast(str, value["claimed_signed_at"]),
        subject_digest=subject,
        pointer=pointer + "/claimed_signed_at",
    )
    identifiers = cast(list[str], value["claim_ids"])
    if identifiers != sorted(identifiers, key=utf16_key):
        raise InputRefused(
            Reason(
                "scope_missing",
                subject,
                None,
                pointer + "/claim_ids",
                "Statement claim scope is not in its required UTF16 order.",
            )
        )
    canonical = rfc8785.dumps(document.value)
    reference = reference_bytes(
        canonical,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=_STATEMENT_ID,
        limits=budget.limits,
    )
    return SuccessorStatement(
        cast(Mapping[str, FrozenJson], freeze_json(value)),
        canonical,
        reference,
        _MESSAGE_PREFIX + canonical,
        context,
    )


def parse_successor_envelope(
    data: bytes, *, context: SuccessorSignatureContext, budget: ReferenceBudget
) -> SuccessorEnvelope:
    """Acquire only an explicitly supplied complete V2 native receipt.

    Parameters
    ----------
    data : bytes
        Entire original caller-selected envelope, never discovered from resolver contents.
    context : {"ordinary_statement", "authority_control"}
        Explicit owning operation; ordinary Root receipt acquisition cannot admit controls.
    budget : ReferenceBudget
        Sole invocation budget for the whole fixed schema, source and canonical limits.

    Returns
    -------
    SuccessorEnvelope
        Exact original whole declaration/message and raw64 signature, without an
        authentication, protected custody, Clock or current-use assertion.

    Raises
    ------
    ConfigurationError
        The independently selected installed V2 schema binding is invalid.
    InputRefused
        Strict source, closed two-field shape, complete native statement, canonical
        raw64 signature encoding or the shared acquisition bounds are invalid.
    """
    document = acquire_document(data, limits=budget.limits)
    canonical = rfc8785.dumps(document.value)
    reference = reference_bytes(
        canonical,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=None,
        limits=budget.limits,
    )
    value = document.value
    if not isinstance(value, dict) or set(value) != {"statement", "signature"}:
        raise InputRefused(
            Reason(
                "invalid_schema", reference.digest, None, "", "Detached envelope shape is invalid."
            )
        )
    statement = parse_successor_statement(
        acquire_document(rfc8785.dumps(value["statement"]), limits=budget.limits),
        context=context,
        budget=budget,
        subject=reference.digest,
        pointer="/statement",
    )
    try:
        encoded = value["signature"]
        if not isinstance(encoded, str):
            raise ValueError("Signature must be an encoded string.")
        signature = decode_bytes(encoded)
        if len(signature) != 64:
            raise ValueError("Signature must decode to raw64 bytes.")
    except ValueError as error:
        raise InputRefused(
            Reason(
                "invalid_signature",
                reference.digest,
                None,
                "/signature",
                "Detached signature encoding is invalid.",
            )
        ) from error
    return SuccessorEnvelope(canonical, reference, statement, signature)
