# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exclusive complete report publication

"""Publish a complete staged report with an atomic no-overwrite filesystem operation."""

import os
import uuid
from contextlib import ExitStack
from pathlib import Path

from ._errors import StorageError
from ._values import Reason


def storage_refusal() -> StorageError:
    """Construct the complete original output-storage refusal without exposing an OS error.

    Returns
    -------
    StorageError
        Exact source-selected all-null storage_error reason and fixed detail.
    """
    return StorageError(Reason("storage_error", None, None, None, "Output could not be stored."))


def publish_report(destination: Path, data: bytes) -> None:
    """Create one fresh report atomically and preserve every preexisting destination.

    Parameters
    ----------
    destination : Path
        Caller-selected fresh file within an existing local parent directory.
    data : bytes
        Entire already serialized canonical result; no content is changed during publication.

    Raises
    ------
    StorageError
        Parent/stage/write/sync/publication fails or any file, directory or symlink already
        occupies the destination. Only this operation's exact private stage is removed.
    """
    stage = ".emt-report-" + uuid.uuid4().hex
    try:
        with ExitStack() as cleanup:
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            cleanup.callback(os.close, directory)
            descriptor = os.open(
                stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=directory
            )
            cleanup.callback(os.unlink, stage, dir_fd=directory)
            cleanup.callback(os.close, descriptor)
            remaining = memoryview(data)
            while remaining:
                remaining = remaining[os.write(descriptor, remaining) :]
            os.fsync(descriptor)
            os.link(
                stage,
                destination.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            os.fsync(directory)
    except OSError:
        raise storage_refusal() from None
