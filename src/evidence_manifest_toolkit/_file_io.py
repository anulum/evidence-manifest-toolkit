# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit local input file acquisition

"""Read selected regular inputs before parsing without leaking filesystem diagnostics."""

import os
import stat
from contextlib import ExitStack
from pathlib import Path

from ._configuration_wire import decode_limits
from ._errors import InputRefused, StorageError
from ._json import acquire_document
from ._reference_paths import configuration_refusal
from ._values import Limits, Reason


def _read_open_file(descriptor: int, metadata: os.stat_result, maximum: int) -> bytes:
    """Read the same inspected regular handle within its finite acquisition boundary.

    Parameters
    ----------
    descriptor : int
        Actual already opened caller input descriptor, never a later pathname lookup.
    metadata : os.stat_result
        Regular-file size measured on that same descriptor before acquisition.
    maximum : int
        Original positive bound or the limits bootstrap file's actual measured size.

    Returns
    -------
    bytes
        Entire captured source bytes without repair or loss of original integer tokens.

    Raises
    ------
    StorageError
        The selected input is not an actual regular file.
    InputRefused
        Measured size or subsequent captured growth exceeds the finite boundary.
    OSError
        Actual descriptor reading fails; the caller maps it to the fixed I/O reason.
    """
    if not stat.S_ISREG(metadata.st_mode):
        raise StorageError(Reason("storage_error", None, None, None, "Input could not be read."))
    if metadata.st_size > maximum:
        raise InputRefused(Reason("limit_exceeded", None, None, None, "JSON input refused."))
    chunks: list[bytes] = []
    acquired = 0
    while True:
        chunk = os.read(descriptor, min(65536, maximum - acquired + 1))
        if not chunk:
            return b"".join(chunks)
        acquired += len(chunk)
        if acquired > maximum:
            raise InputRefused(Reason("limit_exceeded", None, None, None, "JSON input refused."))
        chunks.append(chunk)


def read_file(path: Path, *, max_bytes: int) -> bytes:
    """Read one complete explicitly selected regular file within the known byte cap.

    Parameters
    ----------
    path : Path
        Local caller-selected file, never a received artifact URL or executable.
    max_bytes : int
        Already validated positive acquisition cap before reading or allocating bytes.

    Returns
    -------
    bytes
        Exact original bytes; no canonicalization, filename-based type or trust is inferred.

    Raises
    ------
    StorageError
        The actual selected file cannot be read as a regular local file.
    InputRefused
        The source exceeds the same explicit JSON size bound used by the public operation.
    """
    try:
        with ExitStack() as cleanup:
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            cleanup.callback(os.close, descriptor)
            metadata = os.fstat(descriptor)
            return _read_open_file(descriptor, metadata, max_bytes)
    except OSError:
        raise StorageError(
            Reason("storage_error", None, None, None, "Input could not be read.")
        ) from None


def read_limits(path: Path) -> Limits:
    """Acquire the whole closed local limits configuration before any content read.

    Parameters
    ----------
    path : Path
        Explicit caller file containing all six positive integer bounds.

    Returns
    -------
    Limits
        Exact original integer lexemes, without binary64 rounding or supplied defaults.

    Raises
    ------
    StorageError
        The configuration file cannot be inspected or read.
    ConfigurationError
        Strict configuration JSON or the closed six-field token population is invalid.

    Notes
    -----
    Initial configuration acquisition is bounded by its actual inspected file size, before
    its own operation limits can be known. This adds no hidden operation limit or mode.
    Container depth cannot exceed that finite source size. Later content uses the decoded
    caller limits independently; growing configuration files are refused during acquisition.
    """
    try:
        with ExitStack() as cleanup:
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            cleanup.callback(os.close, descriptor)
            metadata = os.fstat(descriptor)
            size = max(1, metadata.st_size)
            data = _read_open_file(descriptor, metadata, size)
        bootstrap = Limits(size, size, size, 1, 1, size)
        document = acquire_document(data, limits=bootstrap)
    except InputRefused:
        raise configuration_refusal("/limits") from None
    except OSError:
        raise StorageError(
            Reason("storage_error", None, None, None, "Input could not be read.")
        ) from None
    return decode_limits(document)
