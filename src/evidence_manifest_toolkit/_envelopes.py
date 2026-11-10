# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete explicitly supplied detached envelopes

"""Acquire whole native statement/signature pairs without discovering receipts in a store."""

from dataclasses import dataclass
from typing import cast

import rfc8785
from jsonschema import Draft202012Validator

from ._codecs import decode_bytes
from ._errors import InputRefused
from ._json import JsonValue, parse_document
from ._references import reference_bytes
from ._registry import common_schema
from ._statements import statement_message, statement_reasons
from ._utc import utc_key
from ._values import BlobRef, Limits, Reason


@dataclass(frozen=True, slots=True)
class ParsedEnvelope:
    """Keep complete supplied receipt fields and identities separate from authenticity.

    Attributes
    ----------
    canonical_bytes : bytes
        Entire two-field detached envelope represented by RFC8785.
    envelope_ref : BlobRef
        Canonical diagnostic receipt identity, with no invented registered envelope schema.
    statement : dict
        Entire schema-valid original context-specific native statement.
    statement_ref : BlobRef
        Canonical identity of the whole statement, excluding its detached signature.
    message : bytes
        Exact applicable native domain prefix/LF plus JCS of the complete statement.
    signature : bytes
        Canonical decoded raw64 response; no cryptographic acceptance is inferred.
    reasons : tuple of Reason
        Common scope contradictions retained for later complete report composition.
    """

    canonical_bytes: bytes
    envelope_ref: BlobRef
    statement: dict[str, JsonValue]
    statement_ref: BlobRef
    message: bytes
    signature: bytes
    reasons: tuple[Reason, ...]


def parse_envelope(data: bytes, *, limits: Limits) -> ParsedEnvelope:
    """Acquire an explicitly supplied whole envelope under the independently fixed native schema.

    Parameters
    ----------
    data : bytes
        Actual complete caller-supplied receipt bytes, never selected by resolver contents.
    limits : Limits
        Entire operation acquisition/canonical bounds.

    Returns
    -------
    ParsedEnvelope
        Complete native receipt and scope diagnostics. Root/delegation/time/signature and
        current/domain eligibility remain separate checks against independently selected inputs.

    Raises
    ------
    InputRefused
        Strict source, closed envelope, native statement, UTC or raw signature codec is invalid.
    ConfigurationError
        The independently fixed packaged native schema is unavailable.
    """
    value = parse_document(data, limits=limits)
    canonical = rfc8785.dumps(value)
    envelope_ref = reference_bytes(
        canonical,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=None,
        limits=limits,
    )
    if not isinstance(value, dict) or set(value) != {"statement", "signature"}:
        raise InputRefused(
            Reason(
                "invalid_schema",
                envelope_ref.digest,
                None,
                "",
                "Detached envelope shape is invalid.",
            )
        )
    statement = value["statement"]
    validator = Draft202012Validator(common_schema("signed_statement", limits=limits))
    if not isinstance(statement, dict) or not validator.is_valid(statement):
        raise InputRefused(
            Reason(
                "invalid_schema",
                envelope_ref.digest,
                None,
                "/statement",
                "Native statement shape is invalid.",
            )
        )
    statement_bytes = rfc8785.dumps(statement)
    statement_ref = reference_bytes(
        statement_bytes,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id="evidence_manifest_toolkit.signed_statement.v1",
        limits=limits,
    )
    try:
        utc_key(cast(str, statement["claimed_signed_at"]))
    except InputRefused as error:
        reason = error.reason
        raise InputRefused(
            Reason(
                reason.code,
                envelope_ref.digest,
                None,
                "/statement/claimed_signed_at",
                reason.detail,
            )
        ) from error
    encoded = value["signature"]
    try:
        if not isinstance(encoded, str):
            raise ValueError("Signature must be an encoded string.")
        signature = decode_bytes(encoded)
        if len(signature) != 64:
            raise ValueError("Signature must decode to raw64 bytes.")
    except ValueError as error:
        raise InputRefused(
            Reason(
                "invalid_signature",
                envelope_ref.digest,
                None,
                "/signature",
                "Detached signature encoding is invalid.",
            )
        ) from error
    scope_reasons = tuple(
        Reason(
            reason.code,
            envelope_ref.digest,
            reason.claim_id,
            None if reason.pointer is None else "/statement" + reason.pointer,
            reason.detail,
        )
        for reason in statement_reasons(statement, subject=statement_ref.digest)
    )
    return ParsedEnvelope(
        canonical,
        envelope_ref,
        statement,
        statement_ref,
        statement_message(statement),
        signature,
        scope_reasons,
    )
