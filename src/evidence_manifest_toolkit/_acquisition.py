# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — bounded exact-identity resolver acquisition

"""Retrieve only selected references, preserving presence independently of byte integrity."""

from ._budget import ReferenceBudget
from ._errors import InputRefused, ReferenceUnavailable
from ._interfaces import Resolver
from ._reference_paths import configuration_refusal
from ._references import reference_bytes
from ._values import BlobRef, Digest, Reason


def acquire_reference(
    reference: BlobRef,
    *,
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> bytes:
    """Retrieve exact bounded original bytes once, checking every edge's metadata.

    Parameters
    ----------
    reference : BlobRef
        Entire selected original declaration, never a converted raw/canonical alias.
    resolver : Resolver
        Explicit caller-supplied bounded source interface.
    budget : ReferenceBudget
        Sole cumulative operation budget; uncached reads receive the smaller of
        the per-object cap and remaining unique-reference byte allowance.
    subject : str
        Actual containing subject identity.
    pointer : str
        Actual edge position in the containing subject.

    Returns
    -------
    bytes
        Actual original acquired bytes; identity validation is a separate gate.

    Raises
    ------
    ReferenceUnavailable
        Required original lookup has no bytes; its exact whole argument is preserved.
    ConfigurationError
        The resolver supplies a value other than bytes.
    InputRefused
        Metadata conflicts or a shared acquisition bound is exceeded.
    """
    cached = budget.cached(reference, subject=subject, pointer=pointer)
    if cached is not None:
        return cached
    maximum = min(
        budget.limits.max_blob_bytes,
        budget.limits.max_total_reference_bytes - budget.total_bytes,
    )
    if maximum <= 0:
        raise InputRefused(
            Reason(
                "limit_exceeded",
                subject,
                None,
                pointer,
                "Reference acquisition bound exceeded.",
            )
        )
    try:
        data = resolver.resolve(reference, max_bytes=maximum)
    except ReferenceUnavailable as error:
        raise ReferenceUnavailable(reference) from error
    if not isinstance(data, bytes):
        raise configuration_refusal("/resolver")
    budget.charge(reference, data, subject=subject, pointer=pointer)
    return data


def identity_reason(
    reference: BlobRef,
    data: bytes,
    *,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> Reason | None:
    """Check the declared basis and length of present bytes without calling them missing.

    Parameters
    ----------
    reference : BlobRef
        Complete original selected identity.
    data : bytes
        Actual present source, kept unchanged.
    budget : ReferenceBudget
        Complete operation limits, already charged for acquisition.
    subject : str
        Actual containing subject for the declaration diagnostic.
    pointer : str
        Actual declaration location.

    Returns
    -------
    Reason or None
        Actual strict-source or identity refusal, or None when the bytes match.
        Present mismatching bytes remain present for availability composition.
    """
    try:
        actual = reference_bytes(
            data,
            media_type=reference.media_type,
            digest_basis=reference.digest_basis,
            schema_id=reference.schema_id,
            limits=budget.limits,
        )
    except InputRefused as error:
        reason = error.reason
        return Reason(reason.code, subject, reason.claim_id, pointer, reason.detail)
    if actual.digest != reference.digest or actual.byte_length != reference.byte_length:
        return Reason(
            "reference_mismatch", subject, None, pointer, "Reference byte identity does not match."
        )
    return None
