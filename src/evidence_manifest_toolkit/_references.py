# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit byte identity construction

"""Bind raw or canonical bytes without enrolling a schema or accepting evidence."""

import hashlib

from ._errors import ConfigurationError, InputRefused
from ._json import canonicalize_json, validate_limits
from ._values import BlobRef, DigestBasis, Limits, Reason


def reference_bytes(
    data: bytes,
    *,
    media_type: str,
    digest_basis: DigestBasis,
    schema_id: str | None,
    limits: Limits,
) -> BlobRef:
    """Identify bytes using only the caller's explicitly selected digest basis.

    Parameters
    ----------
    data : bytes
        Actual source bytes, never rewritten or stored by this helper.
    media_type : str
        Nonempty declared media type.
    digest_basis : {"raw_bytes", "jcs_content"}
        Hash original bytes or the strict RFC8785 canonical document.
    schema_id : str or None
        Optional nonempty declaration; its presence does not register a schema.
    limits : Limits
        Complete operation bounds, including the individual blob bound.

    Returns
    -------
    BlobRef
        SHA-256 identity and decimal length of the same identified byte sequence.

    Raises
    ------
    ConfigurationError
        Invalid basis, media/schema declaration or operation bounds.
    InputRefused
        Blob bounds or strict canonical JSON representation refuse the source.
    """
    validate_limits(limits)
    if (
        not isinstance(media_type, str)
        or not media_type
        or digest_basis not in ("raw_bytes", "jcs_content")
        or (schema_id is not None and (not isinstance(schema_id, str) or not schema_id))
    ):
        raise ConfigurationError(
            Reason("configuration_error", None, None, None, "Invalid reference configuration.")
        )
    try:
        media_type.encode("utf-8")
        if schema_id is not None:
            schema_id.encode("utf-8")
    except UnicodeError as error:
        raise ConfigurationError(
            Reason("configuration_error", None, None, None, "Invalid reference configuration.")
        ) from error
    if len(data) > limits.max_blob_bytes:
        raise InputRefused(Reason("limit_exceeded", None, None, None, "Blob byte bound exceeded."))
    identified = canonicalize_json(data, limits=limits) if digest_basis == "jcs_content" else data
    if len(identified) > limits.max_blob_bytes:
        raise InputRefused(Reason("limit_exceeded", None, None, None, "Blob byte bound exceeded."))
    return BlobRef(
        "sha256:" + hashlib.sha256(identified).hexdigest(),
        str(len(identified)),
        media_type,
        digest_basis,
        schema_id,
    )
