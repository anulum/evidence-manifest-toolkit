# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — one fixed, bounded capture of timesyncd's last NTP exchange

"""Capture timesyncd's NTPMessage with one fixed ``busctl`` call and a real output bound.

This is the toolkit's only child process. The argument vector is a constant with an absolute
executable path; no shell runs, standard input is ``/dev/null``, and the environment holds only
``LC_ALL=C``. At most ``max_bytes + 1`` bytes are ever read from the reply, so a larger reply is
refused without being held. Any byte on standard error, a non-zero exit, a timeout or a reply
over the bound makes the capture unavailable; the child is then killed and reaped.
"""

import os
import selectors
import subprocess
import time
from collections.abc import Sequence
from typing import IO, cast

from ._errors import StorageError
from ._values import Reason

NTP_MESSAGE_ARGV = (
    "/usr/bin/busctl",
    "--system",
    "get-property",
    "org.freedesktop.timesync1",
    "/org/freedesktop/timesync1",
    "org.freedesktop.timesync1.Manager",
    "NTPMessage",
)
"""The fixed command that prints timesyncd's last NTP exchange."""

NTP_MESSAGE_MAX_BYTES = 4096
"""The largest reply accepted; one byte more is refused."""

NTP_MESSAGE_TIMEOUT_SECONDS = 10.0
"""The wall-clock bound of one capture."""


def _unavailable() -> StorageError:
    """Return the refusal of a capture that did not complete within its bounds."""
    return StorageError(
        Reason(
            "storage_error",
            None,
            None,
            "/clock/ntp_capture",
            "The timesyncd NTP capture is unavailable.",
        )
    )


def bounded_output(argv: Sequence[str], *, timeout: float, max_bytes: int) -> bytes:
    """Run one fixed command and return its whole standard output within both bounds.

    Parameters
    ----------
    argv : Sequence of str
        The complete argument vector, starting with an absolute executable path.
    timeout : float
        Positive wall-clock bound in seconds for the whole capture, exit included.
    max_bytes : int
        The largest standard output accepted.

    Returns
    -------
    bytes
        The whole standard output of a command that exited 0 with nothing on standard error.

    Raises
    ------
    StorageError
        The command could not start, wrote to standard error, exited non-zero, produced more
        than ``max_bytes`` bytes or did not finish within ``timeout``.
    """
    try:
        child = subprocess.Popen(
            tuple(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C"},
            close_fds=True,
        )
    except OSError:
        raise _unavailable() from None
    deadline = time.monotonic() + timeout
    output = bytearray()
    failed = False
    with child, selectors.DefaultSelector() as selector:
        for stream in (child.stdout, child.stderr):
            selector.register(cast(IO[bytes], stream), selectors.EVENT_READ)
        while selector.get_map() and not failed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failed = True
                break
            for key, _ in selector.select(remaining):
                errors = key.fileobj is child.stderr
                chunk = os.read(key.fd, 1 if errors else max_bytes + 1 - len(output))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if errors:
                    failed = True
                    break
                output += chunk
                if len(output) > max_bytes:
                    failed = True
                    break
        if not failed:
            try:
                failed = child.wait(timeout=max(deadline - time.monotonic(), 0.001)) != 0
            except subprocess.TimeoutExpired:
                failed = True
        if failed:
            child.kill()
            child.wait()
    if failed:
        raise _unavailable()
    return bytes(output)


def capture_ntp_message() -> bytes:
    """Return timesyncd's whole NTPMessage reply as ``busctl`` prints it.

    Returns
    -------
    bytes
        The complete reply, terminal newline included, of at most 4096 bytes.

    Raises
    ------
    StorageError
        The fixed capture is unavailable (see :func:`bounded_output`).
    """
    return bounded_output(
        NTP_MESSAGE_ARGV, timeout=NTP_MESSAGE_TIMEOUT_SECONDS, max_bytes=NTP_MESSAGE_MAX_BYTES
    )
