# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original command and filesystem source correspondence

"""Exercise complete diagnostic commands with actual files and independent byte oracles."""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Literal, TypedDict

import pytest


class _Case(TypedDict):
    """Retain the entire original invocation, input bytes and source-selected output."""

    case_id: str
    command: str
    argv: list[str]
    files_hex: dict[str, str]
    initial: Literal["existing", "unwritable", "fresh"]
    sentinel_hex: str
    expected_exit: int
    expected_error: dict[str, object] | None
    expected_success_hex: str


_CASES: list[_Case] = json.loads(
    (Path(__file__).parent / "fixtures/cli-diagnostic-storage-sources.json").read_bytes()
)["cases"]


def _run(argv: list[str], directory: Path) -> subprocess.CompletedProcess[bytes]:
    """Run the actual module command in an owned filesystem without replacing product I/O.

    Parameters
    ----------
    argv : list of str
        Complete original command arguments, including explicit source and output paths.
    directory : Path
        Owned working directory for this actual child and its temporary/cache outputs.

    Returns
    -------
    CompletedProcess
        Actual exit status and complete stdout/stderr bytes of the real entrypoint.
    """
    environment = os.environ.copy()
    environment.update(
        PYTHONPATH=str(Path(__file__).resolve().parents[2] / "src"),
        PYTHONDONTWRITEBYTECODE="1",
        TMPDIR=str(directory),
        TMP=str(directory),
        TEMP=str(directory),
    )
    return subprocess.run(
        [sys.executable, "-m", "evidence_manifest_toolkit", *argv],
        cwd=directory,
        env=environment,
        capture_output=True,
        timeout=15,
        check=False,
    )


@pytest.mark.parametrize("case", _CASES, ids=[case["case_id"] for case in _CASES])
def test_original_diagnostic_storage_and_distinct_recovery(case: _Case, tmp_path: Path) -> None:
    """Compare whole original results, storage refusals and fresh recovery through real CLI.

    Parameters
    ----------
    case : dict
        Complete independently selected original source case prepared before command calls.
    tmp_path : Path
        Owned Samsung test directory for unchanged sources and actual output state.
    """
    assert os.geteuid() != 0
    for name, encoded in case["files_hex"].items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes.fromhex(encoded))
    argv = case["argv"].copy()
    destination = tmp_path / argv[argv.index("--report") + 1]
    destination.parent.mkdir(mode=0o755)
    sentinel = bytes.fromhex(case["sentinel_hex"])
    if case["initial"] == "existing":
        destination.write_bytes(sentinel)
        destination.chmod(0o644)
    elif case["initial"] == "unwritable":
        destination.parent.chmod(0o555)
    try:
        actual = _run(argv, tmp_path)
    finally:
        destination.parent.chmod(0o755)
    assert actual.returncode == case["expected_exit"]
    assert actual.stderr == b""
    if case["initial"] == "fresh":
        expected = bytes.fromhex(case["expected_success_hex"])
        assert actual.stdout == expected
        assert destination.read_bytes() == expected
    else:
        assert actual.stdout == json.dumps(
            case["expected_error"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if case["initial"] == "existing":
            assert destination.read_bytes() == sentinel
            assert destination.stat().st_mode & 0o777 == 0o644
        else:
            assert not destination.exists()
        recovery = destination.with_name("distinct-recovery.json")
        argv[argv.index("--report") + 1] = str(recovery)
        repaired = _run(argv, tmp_path)
        expected = bytes.fromhex(case["expected_success_hex"])
        assert (repaired.returncode, repaired.stdout, repaired.stderr) == (0, expected, b"")
        assert recovery.read_bytes() == expected
        if case["initial"] == "existing":
            assert destination.read_bytes() == sentinel
    assert not tuple(destination.parent.glob(".emt-report-*"))
    for name, encoded in case["files_hex"].items():
        assert (tmp_path / name).read_bytes() == bytes.fromhex(encoded)
