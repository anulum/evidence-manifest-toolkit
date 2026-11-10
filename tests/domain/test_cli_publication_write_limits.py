# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — native publication write failure and recovery

"""Exercise real process file-size limits against complete original CLI transports."""

import json
import os
import resource
import signal
import subprocess
import sys
from pathlib import Path

import pytest
from tests.domain.test_cli_evidence_sources import (
    _bytes,
    _collision,
    _hashes,
    _inputs,
    _object,
    _run,
    _source,
    _transport,
)

_FIXTURES = Path(__file__).parent / "fixtures"
_REPOSITORY = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("command", ("seal", "verify"))
def test_native_unwritable_parent_preserves_source_and_full_recovery(
    command: str, tmp_path: Path
) -> None:
    """Refuse an actual unwritable parent and restore full original publication.

    Parameters
    ----------
    command : str
        Original unsigned seal or current verification with a complete fixed byte oracle.
    tmp_path : Path
        Owned unchanged caller/store files, permission-controlled parent and fresh destinations.

    Notes
    -----
    Only the owned output parent's native permission bits change. An actual
    unprivileged file creation confirms the kernel denial before calling the
    unmodified public module CLI. This is permission-boundary evidence, not
    the whole fourteen-case storage or native platform qualification.
    """
    assert os.geteuid() != 0
    case = "seal-unsigned-whole-fixture" if command == "seal" else "verify-current-whole-fixture"
    source = _source(case)
    arguments = _inputs(source, tmp_path)
    parent = tmp_path / "publication-parent"
    parent.mkdir(mode=0o755)
    metadata = parent.stat()
    original_mode = metadata.st_mode & 0o777
    destination = parent / "refused-output"
    recovery = parent / "distinct-recovery"
    flag = "--output" if command == "seal" else "--report"
    if command == "seal":
        expected = _object(source["expected_entire_SealResult"])
        expected_files = {
            "content.json": _bytes(expected["canonical_content"]),
            "refs.json": (_FIXTURES / "evidence-command-sources/unsigned-refs.json").read_bytes(),
        }
        success = _transport(
            {
                "canonical_content": {
                    "content_ref": expected["content_ref"],
                    "output_file": str(recovery / "content.json"),
                },
                "content_ref": expected["content_ref"],
                "envelope_json": None,
            }
        )
    else:
        success = _transport(source["expected_entire_VerificationReport"])
        expected_files = {"distinct-recovery": success}
    before = _hashes(tmp_path)
    entries = {str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")}
    parent.chmod(0o555)
    try:
        with pytest.raises(PermissionError):
            (parent / "native-permission-probe").open("xb")
        failed = _run(arguments + [flag, str(destination)], tmp_path)
        assert (failed.returncode, failed.stdout, failed.stderr) == (
            3,
            _collision(command),
            b"",
        )
        assert not destination.exists() and not list(parent.iterdir())
        assert _hashes(tmp_path) == before
        assert {str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")} == entries
        assert parent.stat().st_mode & 0o777 == 0o555
    finally:
        parent.chmod(original_mode)
    retained = parent.stat()
    assert (retained.st_dev, retained.st_ino) == (metadata.st_dev, metadata.st_ino)
    assert retained.st_mode & 0o777 == original_mode
    repaired = _run(arguments + [flag, str(recovery)], tmp_path)
    assert (repaired.returncode, repaired.stdout, repaired.stderr) == (0, success, b"")
    if command == "seal":
        assert {path.name for path in recovery.iterdir()} == set(expected_files)
        assert all((recovery / name).read_bytes() == raw for name, raw in expected_files.items())
    else:
        assert recovery.read_bytes() == success
    after = _hashes(tmp_path)
    assert {key: after[key] for key in before} == before
    assert not destination.exists()
    assert {path.name for path in parent.iterdir()} == {"distinct-recovery"}
    observed = {
        "command": command,
        "original_case": case,
        "native_parent_mode_during_failure": "0555",
        "actual_kernel_creation_denied": True,
        "parent_device_inode_preserved": [metadata.st_dev, metadata.st_ino],
        "original_parent_mode_restored": original_mode,
        "failure": {
            "exit": failed.returncode,
            "entire_stdout_hex": failed.stdout.hex(),
            "entire_ErrorResult": json.loads(failed.stdout),
            "stderr_hex": failed.stderr.hex(),
            "requested_output_absent": True,
            "parent_has_no_stage_or_partial_output": True,
        },
        "recovery": {
            "exit": repaired.returncode,
            "entire_stdout_hex": repaired.stdout.hex(),
            "entire_result": json.loads(repaired.stdout),
            "stderr_hex": repaired.stderr.hex(),
            "complete_output_files_hex": {name: raw.hex() for name, raw in expected_files.items()},
        },
        "all_original_caller_and_store_sha256_before_after_equal": before,
        "whole_original_fourteen_storage_cases_or_platform_qualified": False,
    }
    (tmp_path / "actual-native-parent-permission-observations.json").write_text(
        json.dumps(observed, indent=2) + "\n"
    )


@pytest.mark.parametrize("command", ("inspect", "diff", "seal", "verify"))
@pytest.mark.parametrize("write_limit", (0, 64), ids=("zero-write", "partial-write"))
def test_native_write_limit_removes_stage_and_preserves_whole_recovery(
    command: str, write_limit: int, tmp_path: Path
) -> None:
    """Refuse real output writes without publishing partial bytes or losing caller inputs.

    Parameters
    ----------
    command : str
        One of the four original commands, with its independently prepared full oracle.
    write_limit : int
        Actual per-file operating-system bound: zero bytes or an incomplete prefix.
    tmp_path : Path
        Owned caller files, untouched source store and fresh output destinations.

    Notes
    -----
    Only the child process resource limit and SIGXFSZ disposition change. Product
    imports, filesystem calls, serializers and exception handlers remain unmodified.
    """
    destination = tmp_path / "output"
    flag = "--output" if command == "seal" else "--report"
    if command in {"seal", "verify"}:
        case = (
            "seal-unsigned-whole-fixture" if command == "seal" else "verify-current-whole-fixture"
        )
        source = _source(case)
        arguments = _inputs(source, tmp_path)
        if command == "seal":
            expected = _object(source["expected_entire_SealResult"])
            expected_files = {
                "content.json": _bytes(expected["canonical_content"]),
                "refs.json": (
                    _FIXTURES / "evidence-command-sources/unsigned-refs.json"
                ).read_bytes(),
            }
            success = _transport(
                {
                    "canonical_content": {
                        "content_ref": expected["content_ref"],
                        "output_file": str(destination / "content.json"),
                    },
                    "content_ref": expected["content_ref"],
                    "envelope_json": None,
                }
            )
        else:
            success = _transport(source["expected_entire_VerificationReport"])
            expected_files = {"output": success}
    else:
        cases = _object(
            json.loads((_FIXTURES / "cli-diagnostic-storage-sources.json").read_bytes())
        )["cases"]
        assert isinstance(cases, list)
        source = next(
            _object(case)
            for case in cases
            if _object(case)["case_id"] == command + "/full-distinct-output-recovery"
        )
        files = _object(source["files_hex"])
        for name, token in files.items():
            assert isinstance(token, str)
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bytes.fromhex(token))
        argv = source["argv"]
        assert isinstance(argv, list) and all(isinstance(value, str) for value in argv)
        arguments = []
        for value in argv[: argv.index("--report")]:
            assert isinstance(value, str)
            arguments.append(str(tmp_path / value) if value in files else value)
        oracle = source["expected_success_hex"]
        assert isinstance(oracle, str)
        success = bytes.fromhex(oracle)
        expected_files = {"output": success}
    assert all(len(value) > write_limit for value in expected_files.values())
    arguments += [flag, str(destination)]
    before = _hashes(tmp_path)
    original_entries = {str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")}
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(tmp_path), TMP=str(tmp_path), TEMP=str(tmp_path)
    )

    def restrict_child_writes() -> None:
        """Apply a genuine child-only native bound and retain catchable OS write errors."""
        resource.setrlimit(resource.RLIMIT_FSIZE, (write_limit, write_limit))
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)

    failed = subprocess.run(
        [sys.executable, "-B", "-m", "evidence_manifest_toolkit", *arguments],
        cwd=_REPOSITORY / "src",
        env=environment,
        capture_output=True,
        preexec_fn=restrict_child_writes,
        timeout=30,
        check=False,
    )
    assert (failed.returncode, failed.stdout, failed.stderr) == (3, _collision(command), b"")
    assert not destination.exists()
    assert _hashes(tmp_path) == before
    assert {str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")} == original_entries
    repaired = _run(arguments, tmp_path)
    assert (repaired.returncode, repaired.stdout, repaired.stderr) == (0, success, b"")
    if command == "seal":
        assert {path.name for path in destination.iterdir()} == set(expected_files)
        for name, data in expected_files.items():
            assert (destination / name).read_bytes() == data
    else:
        assert destination.read_bytes() == success
    committed = _hashes(tmp_path)
    collision = _run(arguments, tmp_path)
    assert (collision.returncode, collision.stdout, collision.stderr) == (
        3,
        _collision(command),
        b"",
    )
    assert _hashes(tmp_path) == committed
    assert {key: committed[key] for key in before} == before
    assert not list(tmp_path.glob(".emt-*"))
