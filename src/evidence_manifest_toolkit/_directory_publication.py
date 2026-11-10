# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — anchored exclusive directory transactions

"""Publish whole seal outputs with native no-replacement directory visibility."""

import ctypes
import errno
import os
import sys
import uuid
from collections.abc import Mapping
from pathlib import Path

from ._errors import ConfigurationError
from ._publication import storage_refusal
from ._values import Reason


def _unsupported() -> ConfigurationError:
    """Refuse a host unable to provide the required native publication primitive."""
    return ConfigurationError(
        Reason("configuration_error", None, None, None, "Native publication is unavailable.")
    )


def _rename(parent: int, source: str, target: str) -> None:
    """Move an anchored directory exclusively through Linux renameat2, without fallback."""
    if sys.platform != "linux":
        raise _unsupported()
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        raise _unsupported() from None
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if function(parent, os.fsencode(source), parent, os.fsencode(target), 1) != 0:
        number = ctypes.get_errno()
        if number in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
            raise _unsupported()
        raise OSError(number, "Native directory publication failed.")


def _identity(parent: int, name: str) -> tuple[int, int]:
    """Inspect the immediate anchored entry identity without following symlinks."""
    metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    return metadata.st_dev, metadata.st_ino


def _remove_directory(parent: int, name: str, identity: tuple[int, int]) -> None:
    """Remove only an unchanged transaction-owned empty immediate directory."""
    if _identity(parent, name) != identity:
        raise OSError(errno.ESTALE, "Owned staging identity changed.")
    os.rmdir(name, dir_fd=parent)


def _probe(parent: int) -> None:
    """Exercise actual absent-target and occupied-target native exclusion before payload staging."""
    prefix = ".emt-probe-" + uuid.uuid4().hex
    source, target, competitor = prefix + "-source", prefix + "-target", prefix + "-occupied"
    owned: dict[str, tuple[int, int]] = {}
    try:
        for name in (source, competitor):
            os.mkdir(name, 0o700, dir_fd=parent)
            owned[name] = _identity(parent, name)
        original = owned[source]
        _rename(parent, source, target)
        del owned[source]
        owned[target] = original
        if _identity(parent, target) != original:
            raise _unsupported()
        try:
            _rename(parent, target, competitor)
        except OSError as error:
            if error.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                raise
        else:
            del owned[target]
            owned[competitor] = original
            raise _unsupported()
        if (
            _identity(parent, target) != original
            or _identity(parent, competitor) != owned[competitor]
        ):
            raise _unsupported()
    finally:
        for name, identity in owned.items():
            _remove_directory(parent, name, identity)


def _write(directory: int, name: str, data: bytes, owned: dict[str, tuple[int, int]]) -> None:
    """Store the entire already encoded file exclusively and sync its pinned descriptor."""
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    try:
        metadata = os.fstat(descriptor)
        owned[name] = metadata.st_dev, metadata.st_ino
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written == 0:
                raise OSError(errno.EIO, "Output write made no progress.")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_directory(destination: Path, files: Mapping[str, bytes]) -> None:
    """Publish a complete seal directory atomically without replacing any destination.

    Parameters
    ----------
    destination : Path
        Explicit fresh directory name within an existing caller-selected parent.
    files : Mapping of str to bytes
        Entire previously encoded content.json, refs.json and optional envelope.json.

    Raises
    ------
    ConfigurationError
        Native no-replacement capability is unsupported or fails admission.
    StorageError
        Actual staging, write, exclusion, cleanup or durability fails. A complete published
        directory stays immutable on subsequent failure; cleanup never deletes the final name.
    """
    parent = -1
    directory = -1
    stage = ".emt-seal-" + uuid.uuid4().hex
    identity: tuple[int, int] | None = None
    published = False
    owned: dict[str, tuple[int, int]] = {}
    try:
        try:
            parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            _probe(parent)
            os.mkdir(stage, 0o700, dir_fd=parent)
            identity = _identity(parent, stage)
            directory = os.open(
                stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
            )
            for name, data in files.items():
                _write(directory, name, data, owned)
            os.fsync(directory)
            if _identity(parent, stage) != identity:
                raise OSError(errno.ESTALE, "Owned staging identity changed.")
            _rename(parent, stage, destination.name)
            published = True
            os.fsync(parent)
        finally:
            try:
                if identity is not None and not published:
                    if _identity(parent, stage) != identity:
                        raise OSError(errno.ESTALE, "Owned staging identity changed.")
                    if directory >= 0:
                        for name, file_identity in owned.items():
                            if _identity(directory, name) != file_identity:
                                raise OSError(errno.ESTALE, "Owned file identity changed.")
                            os.unlink(name, dir_fd=directory)
                    _remove_directory(parent, stage, identity)
            finally:
                try:
                    if directory >= 0:
                        os.close(directory)
                finally:
                    if parent >= 0:
                        os.close(parent)
    except OSError:
        raise storage_refusal() from None
