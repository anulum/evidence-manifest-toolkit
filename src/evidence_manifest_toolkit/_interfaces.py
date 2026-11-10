# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit caller-supplied byte interfaces

"""Type caller-owned retrieval and signing implementations without selecting code."""

from abc import abstractmethod
from typing import Protocol

from ._values import BlobRef, Digest


class Resolver(Protocol):
    """Supply bounded bytes for the exact selected original reference argument."""

    @abstractmethod
    def resolve(self, reference: BlobRef, *, max_bytes: int) -> bytes:
        """Retrieve original bytes without treating a locator as their identity.

        Parameters
        ----------
        reference : BlobRef
            Entire original reference; all metadata survives an unavailable lookup.
        max_bytes : int
            Explicit cap before read/allocation, additionally checked by EMT.

        Returns
        -------
        bytes
            Actual retrieved source bytes; EMT independently checks identity/length/basis.

        Raises
        ------
        ReferenceUnavailable
            The object is absent; the exact original reference is preserved.
        """
        ...

    @abstractmethod
    def resolve_digest(self, digest: Digest, *, max_bytes: int) -> bytes:
        """Retrieve a bounded digest-only control target without inventing its length.

        Parameters
        ----------
        digest : str
            Exact original known control digest, with its expected schema held by EMT.
        max_bytes : int
            Explicit read cap shared with the complete operation's limits.

        Returns
        -------
        bytes
            Actual control source bytes, independently checked against canonical identity.

        Raises
        ------
        ReferenceUnavailable
            The object is absent; .reference is the original Digest string.
        """
        ...


class Signer(Protocol):
    """Expose a caller-owned qualified PureEd25519 adapter without private material."""

    @property
    @abstractmethod
    def public_key(self) -> bytes:
        """Return the immutable raw32 public key matched to the pinned delegation."""
        ...

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Sign the entire requested prefixed statement without algorithm fallback.

        Parameters
        ----------
        message : bytes
            Exact complete original group or root-control message, never a bare digest.

        Returns
        -------
        bytes
            Raw64 PureEd25519 signature, independently verified by EMT before publication.
        """
        ...
