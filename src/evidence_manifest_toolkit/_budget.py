# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — cumulative selected-reference acquisition bounds

"""Share one byte/count budget across schema resources and every selected content root."""

from ._errors import InputRefused
from ._values import BlobRef, Digest, Limits, Reason

type ByteIdentity = tuple[Digest, str, str]


class ReferenceBudget:
    """Account for unique physical reads while checking every edge's metadata.

    Parameters
    ----------
    limits : Limits
        Entire already validated operation bounds, shared by all roots.

    Attributes
    ----------
    limits : Limits
        Caller-selected bounds retained without per-selector resets.
    total_bytes : int
        Actual original bytes of unique acquired reference identities.
    """

    def __init__(self, limits: Limits) -> None:
        """Initialize one shared operation budget without per-root resets.

        Parameters
        ----------
        limits : Limits
            Entire already configuration-validated operation bounds.
        """
        self.limits = limits
        self.total_bytes = 0
        self._metadata: dict[ByteIdentity, tuple[str, str | None]] = {}
        self._bytes: dict[ByteIdentity, bytes] = {}

    def cached(self, reference: BlobRef, *, subject: Digest, pointer: str) -> bytes | None:
        """Read an already acquired identity after checking this edge's full metadata.

        Parameters
        ----------
        reference : BlobRef
            Actual complete edge declaration, preserving basis, length and schema.
        subject : str
            Containing selected subject identity.
        pointer : str
            Actual containing position for metadata-conflict diagnostics.

        Returns
        -------
        bytes or None
            Exact previously acquired bytes, or None when not yet acquired.

        Raises
        ------
        InputRefused
            The same byte identity has conflicting schema/media declarations.
        """
        identity = reference.digest, reference.digest_basis, reference.byte_length
        metadata = reference.media_type, reference.schema_id
        previous = self._metadata.get(identity)
        if previous is not None and (
            previous[0] != reference.media_type
            or (
                previous[1] is not None
                and reference.schema_id is not None
                and previous[1] != reference.schema_id
            )
        ):
            raise InputRefused(
                Reason("invalid_schema", subject, None, pointer, "Reference metadata conflicts.")
            )
        if previous is None and len(self._metadata) >= self.limits.max_reference_count:
            raise InputRefused(
                Reason("limit_exceeded", subject, None, pointer, "Reference count bound exceeded.")
            )
        # Omission is not a contradictory schema assertion. Retain every actual assertion.
        self._metadata[identity] = (
            metadata if previous is None else (previous[0], previous[1] or reference.schema_id)
        )
        return self._bytes.get(identity)

    def digest_bytes(self, digest: Digest) -> bytes | None:
        """Reuse actual acquired canonical-control bytes without inventing a missing length.

        Parameters
        ----------
        digest : str
            Exact digest-only native control argument, with its schema independently known.

        Returns
        -------
        bytes or None
            Already acquired JCS-basis source, or None when no such source was acquired.
            The control consumer still computes/checks its full actual reference and schema.

        Raises
        ------
        InputRefused
            Multiple acquired declarations for this canonical digest retain different bytes.
        """
        selected = [
            data
            for identity, data in self._bytes.items()
            if identity[0] == digest and identity[1] == "jcs_content"
        ]
        if not selected:
            return None
        if any(data != selected[0] for data in selected):
            raise InputRefused(
                Reason("reference_mismatch", digest, None, None, "Reference bytes conflict.")
            )
        return selected[0]

    def charge(self, reference: BlobRef, data: bytes, *, subject: Digest, pointer: str) -> None:
        """Charge actual source bytes once, without discarding repeated graph edges.

        Parameters
        ----------
        reference : BlobRef
            Complete exact selected identity.
        data : bytes
            Actual original bytes returned by the bounded resolver or static source.
        subject : str
            Containing selected subject identity.
        pointer : str
            Actual edge or local static-resource position.

        Raises
        ------
        InputRefused
            Conflicting metadata, distinct bytes for one identity or a quota violation.
        """
        previous = self.cached(reference, subject=subject, pointer=pointer)
        if previous is not None:
            if previous != data:
                raise InputRefused(
                    Reason(
                        "reference_mismatch", subject, None, pointer, "Reference bytes conflict."
                    )
                )
            return
        if (
            len(data) > self.limits.max_blob_bytes
            or len(self._bytes) >= self.limits.max_reference_count
            or self.total_bytes + len(data) > self.limits.max_total_reference_bytes
        ):
            raise InputRefused(
                Reason(
                    "limit_exceeded",
                    subject,
                    None,
                    pointer,
                    "Reference acquisition bound exceeded.",
                )
            )
        identity = reference.digest, reference.digest_basis, reference.byte_length
        self._bytes[identity] = data
        self.total_bytes += len(data)
