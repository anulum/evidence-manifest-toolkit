# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — closed reference and byte encodings

"""Decode complete references and canonical unpadded Base64URL without coercion."""

import base64
import binascii
import re
from collections.abc import Mapping
from typing import cast

from ._errors import InputRefused
from ._json import JsonValue
from ._values import BlobRef, Digest, DigestBasis, Reason

DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
DECIMAL_PATTERN = re.compile(r"0|[1-9][0-9]*")
_BASE64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]*")
_REFERENCE_FIELDS = {"digest", "byte_length", "media_type", "digest_basis"}


def encode_bytes(data: bytes) -> str:
    """Encode exact bytes as canonical unpadded Base64URL.

    Parameters
    ----------
    data : bytes
        Entire original byte population.

    Returns
    -------
    str
        Canonical encoding without padding or aliases.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_bytes(token: str) -> bytes:
    """Decode a canonical unpadded Base64URL string, rejecting alternate spellings.

    Parameters
    ----------
    token : str
        Complete declared byte encoding, without whitespace or padding.

    Returns
    -------
    bytes
        Exact original bytes after a round-trip spelling check.

    Raises
    ------
    ValueError
        Input type, alphabet, size modulo four or trailing bits are invalid.
    """
    if not isinstance(token, str) or _BASE64URL_PATTERN.fullmatch(token) is None:
        raise ValueError("Invalid canonical Base64URL.")
    try:
        data = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("Invalid canonical Base64URL.") from error
    if encode_bytes(data) != token:
        raise ValueError("Invalid canonical Base64URL.")
    return data


def decode_reference(value: object, *, subject: Digest | None, pointer: str) -> BlobRef:
    """Require every original BlobRef field without inventing absent metadata.

    Parameters
    ----------
    value : object
        Entire received JSON reference, with optional schema_id omitted when absent.
    subject : str or None
        Actual containing identity, if available.
    pointer : str
        Literal concrete position of the complete reference declaration.

    Returns
    -------
    BlobRef
        Complete validated original reference, preserving its declared basis.

    Raises
    ------
    InputRefused
        A missing/extra member, malformed identity/length or invalid declaration occurs.
    """
    refusal = InputRefused(
        Reason("invalid_schema", subject, None, pointer, "Invalid reference declaration.")
    )
    if not isinstance(value, Mapping) or len(value) not in (4, 5):
        raise refusal
    received: dict[str, object] = {}
    for name, field in value.items():
        if not isinstance(name, str):
            raise refusal
        received[name] = field
    if not _REFERENCE_FIELDS <= received.keys() or received.keys() - _REFERENCE_FIELDS - {
        "schema_id"
    }:
        raise refusal
    digest, length = received["digest"], received["byte_length"]
    media, basis = received["media_type"], received["digest_basis"]
    schema_id = received.get("schema_id")
    if not (
        isinstance(digest, str)
        and DIGEST_PATTERN.fullmatch(digest)
        and isinstance(length, str)
        and len(length) <= 256
        and DECIMAL_PATTERN.fullmatch(length)
        and isinstance(media, str)
        and media
        and isinstance(basis, str)
        and basis in ("raw_bytes", "jcs_content")
    ):
        raise refusal
    if "schema_id" in received and (not isinstance(schema_id, str) or not schema_id):
        raise refusal
    try:
        media.encode("utf-8")
        if isinstance(schema_id, str):
            schema_id.encode("utf-8")
    except UnicodeError as error:
        raise refusal from error
    return BlobRef(digest, length, media, cast(DigestBasis, basis), cast(str | None, schema_id))


def reference_value(reference: BlobRef) -> dict[str, JsonValue]:
    """Serialize the whole original reference without adding an absent schema declaration.

    Parameters
    ----------
    reference : BlobRef
        Entire immutable declaration.

    Returns
    -------
    dict
        Original fields; schema_id remains omitted when absent.
    """
    value: dict[str, JsonValue] = {
        "digest": reference.digest,
        "byte_length": reference.byte_length,
        "media_type": reference.media_type,
        "digest_basis": reference.digest_basis,
    }
    if reference.schema_id is not None:
        value["schema_id"] = reference.schema_id
    return value
