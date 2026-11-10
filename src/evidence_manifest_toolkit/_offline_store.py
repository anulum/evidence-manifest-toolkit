# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit bounded offline digest store

"""Read flat digest-named regular files through a pinned directory descriptor."""

import os
import stat
from pathlib import Path
from types import TracebackType

from ._caller_config import validate_reference_argument
from ._codecs import DIGEST_PATTERN
from ._errors import InputRefused, ReferenceUnavailable, StorageError
from ._reference_paths import configuration_refusal
from ._values import BlobRef, Digest, Reason


def _storage_refusal() -> StorageError:
    """Return the fixed store-I/O refusal without revealing a path or OS exception.

    Returns
    -------
    StorageError
        Original storage_error code with no fabricated artifact location.
    """
    return StorageError(
        Reason("storage_error", None, None, None, "The requested local storage operation failed.")
    )


class OfflineStore:
    """Implement the existing Resolver using one caller-selected local directory.

    Parameters
    ----------
    directory : Path
        Existing flat store containing files named by the 64 lowercase digest hex digits.
        Artifact labels and URLs never become paths; symlinks and special files are refused.

    Notes
    -----
    Use as a context manager to close the pinned directory descriptor. Returned original
    bytes are independently checked by the owning EMT operation, under their declared basis.
    """

    def __init__(self, directory: Path) -> None:
        """Pin the existing root without creating or enumerating store objects.

        Parameters
        ----------
        directory : Path
            Explicit local directory; received content does not select it.

        Raises
        ------
        StorageError
            The directory cannot be opened as a real nonsymlink directory.
        """
        try:
            self._directory_fd = os.open(
                directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
        except OSError:
            raise _storage_refusal() from None

    def __enter__(self) -> "OfflineStore":
        """Return the existing pinned resolver for a bounded operation.

        Returns
        -------
        OfflineStore
            This resolver, without opening another root or resetting acquisition quotas.
        """
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the root descriptor without suppressing an operation failure.

        Parameters
        ----------
        exception_type : type or None
            Existing operation failure type, if any.
        exception : BaseException or None
            Existing failure; never interpreted as a successful resolver result.
        traceback : TracebackType or None
            Context-manager traceback, never included in a caller diagnostic.

        Raises
        ------
        StorageError
            The descriptor cannot be closed.
        """
        self.close()

    def close(self) -> None:
        """Close the pinned root once; repeated closure changes no store file.

        Raises
        ------
        StorageError
            Closing the owned descriptor fails.
        """
        descriptor = self._directory_fd
        if descriptor >= 0:
            self._directory_fd = -1
            try:
                os.close(descriptor)
            except OSError:
                raise _storage_refusal() from None

    def resolve(self, reference: BlobRef, *, max_bytes: int) -> bytes:
        """Read the exact full-reference target without changing its argument or basis.

        Parameters
        ----------
        reference : BlobRef
            Complete original declaration, including optional schema/media metadata.
        max_bytes : int
            Explicit positive byte cap checked before allocation and after bounded reads.

        Returns
        -------
        bytes
            Original file bytes; no canonicalization or identity acceptance is performed.

        Raises
        ------
        ReferenceUnavailable
            The named file is absent; .reference preserves this exact complete argument.
        ConfigurationError
            The supplied declaration or read cap is invalid.
        InputRefused
            The actual file exceeds the explicit cap.
        StorageError
            The resolver is closed or the target is unsafe/unreadable.
        """
        validate_reference_argument(reference, pointer="/resolver/reference")
        return self._read(reference.digest, reference, max_bytes)

    def resolve_digest(self, digest: Digest, *, max_bytes: int) -> bytes:
        """Read only the supplied digest target, preserving unavailable digest-only form.

        Parameters
        ----------
        digest : str
            Exact lowercase sha256 identity; its algorithm prefix is validated before use.
        max_bytes : int
            Explicit positive byte cap before reading any bytes.

        Returns
        -------
        bytes
            Original file bytes; the operation holds the expected native type and basis.

        Raises
        ------
        ReferenceUnavailable
            No file exists; .reference is the original digest, never a guessed BlobRef.
        ConfigurationError
            The digest or bound is invalid.
        InputRefused
            The bounded target exceeds the caller's cap.
        StorageError
            The resolver is closed or the target is unsafe/unreadable.
        """
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            raise configuration_refusal("/resolver/digest")
        return self._read(digest, digest, max_bytes)

    def _read(self, digest: Digest, original: BlobRef | Digest, maximum: int) -> bytes:
        """Open one confined regular file and acquire at most the explicit cap plus one byte.

        Parameters
        ----------
        digest : str
            Already validated immutable filename identity.
        original : BlobRef or str
            Exact original method argument retained for an unavailable lookup.
        maximum : int
            Caller-selected positive cap; no unbounded read is used.

        Returns
        -------
        bytes
            Entire actual original file only when within the explicit cap.

        Raises
        ------
        ReferenceUnavailable
            The exact target file is absent.
        ConfigurationError
            The cap is not a positive integer.
        InputRefused
            File size or growth exceeds the cap.
        StorageError
            A symlink, special file, closed resolver or local I/O failure is encountered.
        """
        if type(maximum) is not int or maximum <= 0:
            raise configuration_refusal("/resolver/max_bytes")
        if self._directory_fd < 0:
            raise _storage_refusal()
        try:
            descriptor = os.open(
                digest[7:],
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=self._directory_fd,
            )
        except FileNotFoundError:
            raise ReferenceUnavailable(original) from None
        except OSError:
            raise _storage_refusal() from None
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise _storage_refusal()
            if metadata.st_size > maximum:
                raise InputRefused(
                    Reason(
                        "limit_exceeded",
                        digest,
                        None,
                        None,
                        "Reference acquisition bound exceeded.",
                    )
                )
            chunks: list[bytes] = []
            acquired = 0
            while True:
                chunk = os.read(descriptor, min(65536, maximum - acquired + 1))
                if not chunk:
                    return b"".join(chunks)
                acquired += len(chunk)
                if acquired > maximum:
                    raise InputRefused(
                        Reason(
                            "limit_exceeded",
                            digest,
                            None,
                            None,
                            "Reference acquisition bound exceeded.",
                        )
                    )
                chunks.append(chunk)
        except OSError:
            raise _storage_refusal() from None
        finally:
            try:
                os.close(descriptor)
            except OSError:
                raise _storage_refusal() from None
