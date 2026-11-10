# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — real finite caller-file acquisition

"""Exercise actual limits bootstrap and nonregular-file refusals through public processes."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _limits() -> bytes:
    """Declare all six explicit bounds with a one-byte subsequent JSON allowance."""
    return json.dumps(
        {
            "max_json_bytes": 1,
            "max_blob_bytes": 1,
            "max_total_reference_bytes": 1,
            "max_reference_count": 1,
            "max_graph_depth": 1,
            "max_json_depth": 1,
        }
    ).encode("ascii")


def _invoke(limits: Path, content: Path, output: Path) -> subprocess.CompletedProcess[bytes]:
    """Run the real module command in its ordinary source directory without overlays."""
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1",
        TMPDIR=str(output.parent),
        TMP=str(output.parent),
        TEMP=str(output.parent),
    )
    return subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "evidence_manifest_toolkit",
            "inspect",
            "--content",
            str(content),
            "--limits",
            str(limits),
            "--report",
            str(output),
        ],
        cwd=Path(__file__).resolve().parents[2] / "src",
        env=environment,
        capture_output=True,
        timeout=15,
        check=False,
    )


def _expected() -> bytes:
    """Retain the whole independent six-field diagnostic oracle for the original scalar byte."""
    return json.dumps(
        {
            "schema_id": None,
            "content_ref": {
                "digest": "sha256:" + hashlib.sha256(b"1").hexdigest(),
                "byte_length": "1",
                "media_type": "application/json",
                "digest_basis": "jcs_content",
            },
            "declared_claims": [],
            "declared_references": [],
            "acceptance": "not_evaluated",
            "reasons": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def test_limits_bootstrap_uses_its_measured_file_not_future_json_bound(tmp_path: Path) -> None:
    """Admit the whole limits file then enforce its one-byte bound on actual later content.

    Parameters
    ----------
    tmp_path : Path
        Owned immutable inputs and fresh result files for real process calls.
    """
    limits = tmp_path / "limits.json"
    content = tmp_path / "one.json"
    oversize = tmp_path / "two.json"
    limits.write_bytes(_limits())
    content.write_bytes(b"1")
    oversize.write_bytes(b"12")
    before = {path.name: path.read_bytes() for path in (limits, content, oversize)}
    report = tmp_path / "original-report.json"
    actual = _invoke(limits, content, report)
    assert (actual.returncode, actual.stdout, actual.stderr) == (0, _expected(), b"")
    assert report.read_bytes() == _expected()
    refused_report = tmp_path / "refused-report.json"
    refused = _invoke(limits, oversize, refused_report)
    expected_error = json.dumps(
        {
            "operation": "inspect",
            "reasons": [
                {
                    "code": "limit_exceeded",
                    "subject_digest": None,
                    "claim_id": None,
                    "pointer": None,
                    "detail": "JSON input refused.",
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    assert (refused.returncode, refused.stdout, refused.stderr) == (2, expected_error, b"")
    assert not refused_report.exists()
    recovery = tmp_path / "recovery-report.json"
    repaired = _invoke(limits, content, recovery)
    assert (repaired.returncode, repaired.stdout, repaired.stderr) == (0, _expected(), b"")
    assert recovery.read_bytes() == report.read_bytes()
    assert before == {path.name: path.read_bytes() for path in (limits, content, oversize)}


@pytest.mark.parametrize("kind", ("directory", "fifo"))
def test_nonregular_limits_input_is_preserved_and_distinct_recovery_succeeds(
    kind: str, tmp_path: Path
) -> None:
    """Refuse actual directories and FIFOs before reading while preserving source identities.

    Parameters
    ----------
    kind : str
        Actual native nonregular source kind; no mocked descriptor or filesystem result.
    tmp_path : Path
        Owned original special entry and separate complete regular recovery inputs.
    """
    bad = tmp_path / "nonregular"
    if kind == "directory":
        bad.mkdir()
    else:
        assert kind == "fifo"
        os.mkfifo(bad, 0o600)
    identity = bad.lstat()
    limits = tmp_path / "valid-limits.json"
    content = tmp_path / "content.json"
    limits.write_bytes(_limits())
    content.write_bytes(b"1")
    report = tmp_path / "refused-report.json"
    actual = _invoke(bad, content, report)
    error = json.dumps(
        {
            "operation": "inspect",
            "reasons": [
                {
                    "code": "storage_error",
                    "subject_digest": None,
                    "claim_id": None,
                    "pointer": None,
                    "detail": "Input could not be read.",
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    assert (actual.returncode, actual.stdout, actual.stderr) == (3, error, b"")
    assert not report.exists()
    recovery = tmp_path / "recovery-report.json"
    repaired = _invoke(limits, content, recovery)
    assert (repaired.returncode, repaired.stdout, repaired.stderr) == (0, _expected(), b"")
    assert recovery.read_bytes() == _expected()
    retained = bad.lstat()
    assert (retained.st_dev, retained.st_ino, retained.st_mode) == (
        identity.st_dev,
        identity.st_ino,
        identity.st_mode,
    )
    assert limits.read_bytes() == _limits() and content.read_bytes() == b"1"
