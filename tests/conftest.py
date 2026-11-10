# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Independent finite repository fixtures and actual public-command invocation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
from coverage import Coverage

from local_scaffold.inputs import Json

SOURCE = Path(__file__).resolve().parents[1]


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Retain actual per-case timings even when the complete native leaf times out."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "controller")
    directory = SOURCE / ".tool-cache/test-event-times"
    assert not directory.is_symlink()
    directory.mkdir(exist_ok=True)
    path = directory / (worker + "-" + str(os.getpid()) + ".jsonl")
    assert not path.is_symlink()
    value = {
        "nodeid": report.nodeid,
        "phase": report.when,
        "duration_seconds": report.duration,
        "outcome": report.outcome,
        "worker": worker,
        "native_pid": os.getpid(),
    }
    with path.open("a") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


def source_python(*arguments: str, executable: str | None = None) -> list[str]:
    """Trace every owned Python child; retain raw unrelated control processes."""
    python = executable or sys.executable
    if Coverage.current() is None:
        return [python, *arguments]
    flags: list[str] = []
    remaining = list(arguments)
    while remaining[0] in ("-I", "-S", "-B"):
        flags.append(remaining.pop(0))
    if remaining[0] == "-c":
        program = remaining[1].encode()
        directory = SOURCE / ".tool-cache/test-source-programs"
        directory.mkdir(exist_ok=True)
        script = directory / (hashlib.sha256(program).hexdigest() + ".py")
        try:
            with script.open("xb") as stream:
                stream.write(program)
        except FileExistsError:
            assert script.read_bytes() == program
        remaining = [str(script), *remaining[2:]]
    launcher = """import pathlib,runpy,sys
from coverage import Coverage
configuration=sys.argv[1]
arguments=sys.argv[2:]
coverage=Coverage(config_file=configuration,data_suffix=True)
coverage.start()
try:
    if arguments[0]=='-m':
        sys.argv=[arguments[1],*arguments[2:]]
        runpy.run_module(arguments[1],run_name='__main__',alter_sys=True)
    else:
        script=pathlib.Path(arguments[0]).resolve()
        sys.path.insert(0,str(script.parent))
        sys.argv=[str(script),*arguments[1:]]
        runpy.run_path(script,run_name='__main__')
finally:
    coverage.stop()
    coverage.save()
"""
    return [python, *flags, "-c", launcher, str(SOURCE / "pyproject.toml"), *remaining]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """Copy actual owned inputs and initialise a genuine isolated local Git tree."""
    target = tmp_path / "repository"
    shutil.copytree(
        SOURCE,
        target,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            ".tool-cache",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
        ),
    )
    cache = target / ".tool-cache/security"
    cache.mkdir(parents=True)
    shutil.copyfile(SOURCE / ".tool-cache/security/pip-audit.json", cache / "pip-audit.json")
    subprocess.run(["git", "init", "--quiet", "-b", "main", str(target)], check=True)
    return target


def run_guard(gate: str, root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    """Invoke the actual fixed public script with real native process semantics."""
    filename = "preflight.py" if gate == "preflight" else "check_" + gate + ".py"
    return subprocess.run(
        source_python(
            str(SOURCE / "tools" / filename),
            "--root",
            str(root),
            "--json",
            *arguments,
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )


def payload(result: subprocess.CompletedProcess[bytes], expected: int) -> dict[str, Json]:
    """Assert complete native/report agreement and safe deterministic wire shape."""
    assert result.returncode == expected, (result.stdout, result.stderr)
    assert not result.stderr, result.stderr
    value = cast(dict[str, Json], json.loads(result.stdout))
    assert set(value) == {
        "report_schema",
        "gate",
        "scope",
        "status",
        "exit_code",
        "reasons",
        "checks",
    }
    assert value["exit_code"] == expected
    assert value["status"] == {0: "passed", 2: "refused", 3: "unavailable", 4: "invalid"}[expected]
    assert value["report_schema"] == "emt.local-scaffold-guard-report.v1"
    assert result.stdout.endswith(b"\n")
    assert len(result.stdout) <= 524288
    return value


def change(root: Path, name: str, path: tuple[str, ...], replacement: Json) -> None:
    """Change one independently chosen actual JSON input, preserving valid encoding."""
    filename = root / name
    value = cast(dict[str, Json], json.loads(filename.read_bytes()))
    current = value
    for key in path[:-1]:
        child = current[key]
        assert isinstance(child, dict)
        current = child
    current[path[-1]] = replacement
    filename.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n")


def snapshots(root: Path) -> dict[str, bytes]:
    """Retain every original owned file's actual bytes for read-only assertions."""
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
        and not any(
            part in (".git", ".tool-cache", "__pycache__") for part in path.relative_to(root).parts
        )
    }


def closed_stdout(gate: str, root: Path) -> int:
    """Close an actual pipe consumer before the real guard attempts report output."""
    filename = "preflight.py" if gate == "preflight" else "check_" + gate + ".py"
    reader, writer = os.pipe()
    os.close(reader)
    try:
        result = subprocess.run(
            source_python(
                str(SOURCE / "tools" / filename),
                "--root",
                str(root),
                "--json",
                "--unknown-private-sentinel",
            ),
            cwd=SOURCE,
            stdout=writer,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    finally:
        os.close(writer)
    assert b"private-sentinel" not in result.stderr
    return result.returncode


@pytest.fixture
def audited_clone(root: Path) -> Path:
    """Copy genuine original local admission objects into a distinct owned installation."""
    source = SOURCE / ".tool-cache/security-admissions"
    target = root / ".tool-cache/security-admissions"
    target.mkdir()
    shutil.copytree(source / "objects", target / "objects")
    shutil.copyfile(source / "HEAD.json", target / "HEAD.json")
    shutil.copyfile(source / "admission.lock", target / "admission.lock")
    return root


def clone_dependency(root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    """Exercise the cloned real implementation so its actual installation owns its store."""
    return subprocess.run(
        source_python(
            str(root / "tools/check_dependency_alignment.py"),
            "--root",
            str(root),
            "--json",
            *arguments,
        ),
        cwd=root,
        capture_output=True,
        timeout=120,
    )


def adverse_audit_receipt(root: Path, changes: dict[str, Json]) -> None:
    """Publish only an explicitly adverse owned fixture, never a synthetic passing receipt."""
    store = root / ".tool-cache/security-admissions"
    head = cast(dict[str, Json], json.loads((store / "HEAD.json").read_bytes()))
    selector = head["receipt_sha256"]
    assert isinstance(selector, str)
    receipt = cast(
        dict[str, Json], json.loads((store / "objects" / (selector + ".json")).read_bytes())
    )
    assert changes and any(
        type(receipt.get(key)) is not type(value) or receipt.get(key) != value
        for key, value in changes.items()
    )
    receipt["installation_sha256"] = hashlib.sha256(
        b"emt.trusted-installation.v1\0" + str(root.resolve()).encode()
    ).hexdigest()
    receipt.update(changes)
    data = (json.dumps(receipt, sort_keys=True) + "\n").encode()
    new_selector = hashlib.sha256(data).hexdigest()
    (store / "objects" / (new_selector + ".json")).write_bytes(data)
    head["receipt_sha256"] = new_selector
    (store / "HEAD.json").write_text(json.dumps(head) + "\n")


@pytest.fixture(scope="module")
def actual_strace() -> Path:
    """Require the genuine pinned Ubuntu fixture; absence never simulates success."""
    base = SOURCE / ".tool-cache/native-fixtures/strace-6.8-0ubuntu2"
    executable = base / "extracted/usr/bin/strace"
    if not executable.is_file():
        pytest.exit("Required native strace fixture is unavailable.", returncode=3)
    assert not any(path.is_symlink() for path in (executable, *executable.parents[:-1]))
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == (
        "28f957c227012de0b18d1bd7fff2d396cb693ea60ed8013be68de071e84b5001"
    )
    copyright_file = base / "extracted/usr/share/doc/strace/copyright"
    assert hashlib.sha256(copyright_file.read_bytes()).hexdigest() == (
        "40e4ca01654c733c06fabee65168da4c177117b1bd084f3a752bc8a989736e04"
    )
    version = subprocess.run(
        [str(executable), "--version"], capture_output=True, timeout=10, check=True
    )
    assert b"strace -- version 6.8" in version.stdout
    return executable
