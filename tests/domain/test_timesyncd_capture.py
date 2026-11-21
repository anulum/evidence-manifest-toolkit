# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the fixed NTP capture keeps every bound with a real child

"""Check the bounded capture with real child processes: output, input, environment and limits."""

import json
import sys
import time
from pathlib import Path

import pytest

from evidence_manifest_toolkit import StorageError
from evidence_manifest_toolkit._timesyncd_capture import (
    NTP_MESSAGE_ARGV,
    NTP_MESSAGE_MAX_BYTES,
    NTP_MESSAGE_TIMEOUT_SECONDS,
    bounded_output,
    capture_ntp_message,
)


def _python(code: str) -> tuple[str, ...]:
    """Return a child command that runs ``code`` in this interpreter, isolated."""
    return (sys.executable, "-I", "-c", code)


def _refused(argv: tuple[str, ...], *, timeout: float = 10.0) -> None:
    """Assert that one capture is refused as unavailable at the capture's pointer."""
    with pytest.raises(StorageError) as caught:
        bounded_output(argv, timeout=timeout, max_bytes=NTP_MESSAGE_MAX_BYTES)
    assert (caught.value.reason.code, caught.value.reason.pointer) == (
        "storage_error",
        "/clock/ntp_capture",
    )


def test_the_capture_is_one_fixed_command_with_fixed_bounds() -> None:
    """The argument vector, its absolute executable and both bounds are constants."""
    assert NTP_MESSAGE_ARGV == (
        "/usr/bin/busctl",
        "--system",
        "get-property",
        "org.freedesktop.timesync1",
        "/org/freedesktop/timesync1",
        "org.freedesktop.timesync1.Manager",
        "NTPMessage",
    )
    assert (NTP_MESSAGE_MAX_BYTES, NTP_MESSAGE_TIMEOUT_SECONDS) == (4096, 10.0)


def test_output_of_exactly_the_bound_is_returned_whole() -> None:
    """A reply of 4096 bytes is accepted byte for byte."""
    output = bounded_output(
        _python("import sys; sys.stdout.write('x' * 4095 + '\\n')"),
        timeout=10.0,
        max_bytes=NTP_MESSAGE_MAX_BYTES,
    )
    assert output == b"x" * 4095 + b"\n"


def test_one_byte_over_the_bound_is_refused() -> None:
    """A reply of 4097 bytes is refused without being returned."""
    _refused(_python("import sys; sys.stdout.write('x' * 4097)"))


def test_a_large_reply_is_refused_and_the_child_is_stopped() -> None:
    """A child that keeps writing is killed once the bound is passed, long before it ends."""
    started = time.monotonic()
    _refused(
        _python("import sys, time\nwhile True: sys.stdout.write('x' * 65536); sys.stdout.flush()")
    )
    assert time.monotonic() - started < 5.0


def test_the_child_reads_dev_null_and_sees_only_lc_all() -> None:
    """Standard input is empty and the environment holds LC_ALL=C alone."""
    output = bounded_output(
        _python("import json, os, sys; print(json.dumps([sys.stdin.read(), dict(os.environ)]))"),
        timeout=10.0,
        max_bytes=NTP_MESSAGE_MAX_BYTES,
    )
    assert json.loads(output) == ["", {"LC_ALL": "C"}]


def test_any_byte_on_standard_error_is_refused() -> None:
    """A warning on standard error refuses the capture even when the exit status is 0."""
    _refused(_python("import sys; sys.stderr.write('w'); print('ok')"))


def test_a_non_zero_exit_is_refused() -> None:
    """A failing command refuses the capture."""
    _refused(_python("import sys; print('partial'); sys.exit(3)"))


def test_a_command_that_cannot_start_is_refused(tmp_path: Path) -> None:
    """A missing executable refuses the capture."""
    _refused((str(tmp_path / "absent-busctl"), "--system"))


def test_a_command_past_its_timeout_is_refused_and_reaped() -> None:
    """A child still running at the deadline is killed and the capture refused at once."""
    started = time.monotonic()
    _refused(_python("import time; time.sleep(30)"), timeout=0.5)
    assert time.monotonic() - started < 5.0


def test_a_child_that_closes_its_output_and_lingers_is_refused() -> None:
    """The deadline covers the exit too, not only the output."""
    started = time.monotonic()
    _refused(_python("import os, time; os.close(1); os.close(2); time.sleep(30)"), timeout=0.5)
    assert time.monotonic() - started < 5.0


def test_the_live_capture_returns_one_whole_ntp_message() -> None:
    """The live timesyncd answers with the fixed 20-token NTPMessage form."""
    tokens = capture_ntp_message().decode("ascii").split()
    assert len(tokens) == 20 and tokens[0] == "(uuuuittayttttbtt)"
