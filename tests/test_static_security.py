# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Exercise original static findings, exact reviewed attribution and real source scans."""

from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from check_static_security import main
from local_scaffold.reports import Fault, Report
from local_scaffold.static_security import inspect_findings, verify
from tests.conftest import SOURCE, payload, run_guard, snapshots, source_python
from tests.conftest import actual_strace as actual_strace

_SIGNATURE = "src/evidence_manifest_toolkit/_native_signature.py"
_CAPTURE = "src/evidence_manifest_toolkit/_timesyncd_capture.py"


@pytest.fixture(scope="module")
def native_report() -> bytes:
    """Produce one genuine complete current native report and retain its original bytes."""
    store = SOURCE / ".tool-cache/security-admissions"
    before = (store / "HEAD.json").read_bytes()
    payload(run_guard("static_security", SOURCE), 0)
    assert (store / "HEAD.json").read_bytes() == before
    entries = []
    for path in (store / "objects").iterdir():
        try:
            value = json.loads(path.read_bytes())
        except (UnicodeDecodeError, ValueError):
            continue
        if isinstance(value, dict) and value.get("producer") == "bandit":
            entries.append((path.stat().st_mtime_ns, value))
    assert entries
    entry = max(entries, key=lambda row: row[0])[1]
    assert entry["native_exit"] == 1 and entry["version"] == "1.9.4"
    selector = entry["report_sha256"]
    assert isinstance(selector, str)
    data = (store / "objects" / (selector + ".json")).read_bytes()
    assert hashlib.sha256(data).hexdigest() == entry["report_sha256"]
    actual = json.loads(data)
    assert actual["errors"] == []
    assert {(row["filename"], row["line_number"], row["test_id"]) for row in actual["results"]} == {
        (_SIGNATURE, 14, "B413"),
        (_SIGNATURE, 15, "B413"),
        (_CAPTURE, 20, "B404"),
        (_CAPTURE, 83, "B603"),
    }
    return data


def test_genuine_result_reader_and_unchanged_public_scan(native_report: bytes, root: Path) -> None:
    """Accept the exact reviewed attribution and preserve every original received source."""
    report = Report("static_security")
    inspect_findings(
        native_report,
        1,
        (SOURCE / _SIGNATURE).read_bytes(),
        importlib.metadata.version("pycryptodome"),
        report,
        (SOURCE / _CAPTURE).read_bytes(),
    )
    assert report.exit_code == 0
    before = snapshots(root)
    payload(run_guard("static_security", root), 0)
    assert snapshots(root) == before


@pytest.mark.parametrize(
    "case",
    (
        "json",
        "top-level",
        "results",
        "finding",
        "errors",
        "native-other",
        "native-clean-with-findings",
        "native-false",
        "missing-source",
        "changed-source",
        "provider",
        "rule",
        "path",
        "line",
        "boolean-line",
        "duplicate",
        "capture-missing",
        "capture-changed",
        "capture-rule",
        "capture-line",
        "capture-path",
        "capture-duplicate",
    ),
)
def test_actual_report_and_source_disagreements_refuse(native_report: bytes, case: str) -> None:
    """Mutate one original producer or source fact; no synthetic accepting result exists."""
    value = copy.deepcopy(json.loads(native_report))
    signature: bytes | None = (SOURCE / _SIGNATURE).read_bytes()
    capture: bytes | None = (SOURCE / _CAPTURE).read_bytes()
    capture_index = next(
        index for index, row in enumerate(value["results"]) if row["filename"] == _CAPTURE
    )
    provider = importlib.metadata.version("pycryptodome")
    status = 1
    expected = 2
    if case == "json":
        data = native_report[:1]
        expected = 2
    else:
        if case == "top-level":
            value = []
            expected = 4
        elif case == "results":
            value["results"] = {}
            expected = 4
        elif case == "finding":
            value["results"][0] = "invalid original finding"
            expected = 4
        elif case == "errors":
            value["errors"] = [{"filename": _SIGNATURE, "reason": "source unavailable"}]
        elif case == "native-other":
            status = 2
        elif case == "native-clean-with-findings":
            status = 0
        elif case == "native-false":
            status = False
            expected = 4
        elif case == "missing-source":
            signature = None
        elif case == "changed-source":
            assert signature is not None
            signature += b"\n"
        elif case == "provider":
            provider = "0"
        elif case == "rule":
            value["results"][0]["test_id"] = "B602"
        elif case == "path":
            value["results"][0]["filename"] = "tools/local_scaffold/static_security.py"
        elif case == "line":
            value["results"][0]["line_number"] = 13
        elif case == "boolean-line":
            value["results"][0]["line_number"] = True
        elif case == "capture-missing":
            capture = None
        elif case == "capture-changed":
            assert capture is not None
            capture += b"\n"
        elif case == "capture-rule":
            value["results"][capture_index]["test_id"] = "B602"
        elif case == "capture-line":
            value["results"][capture_index]["line_number"] = 84
        elif case == "capture-path":
            value["results"][capture_index]["filename"] = (
                "src/evidence_manifest_toolkit/_self_bound_launch.py"
            )
        elif case == "capture-duplicate":
            value["results"].append(copy.deepcopy(value["results"][capture_index]))
        else:
            assert case == "duplicate"
            value["results"].append(copy.deepcopy(value["results"][0]))
        data = (json.dumps(value) + "\n").encode()
    report = Report("static_security")
    if case in {"json", "top-level", "results", "finding", "native-false"}:
        with pytest.raises(Fault) as error:
            inspect_findings(data, status, signature, provider, report, capture)
        assert error.value.exit_code == expected
    else:
        inspect_findings(data, status, signature, provider, report, capture)
        assert report.exit_code == expected


@pytest.mark.parametrize(
    "case",
    (
        "unsafe-python",
        "syntax-error",
        "changed-reviewed-source",
        "changed-reviewed-capture",
        "wrong-lock",
    ),
)
def test_real_public_scan_refuses_new_source_and_inputs(root: Path, case: str) -> None:
    """Exercise actual additional findings and native parse failures without executing input."""
    marker = root / "must-not-execute"
    if case == "unsafe-python":
        source = root / "src/evidence_manifest_toolkit/source_tripwire.py"
        source.write_text(
            "import subprocess\nsubprocess.run('touch must-not-execute', shell=True)\n"
        )
    elif case == "syntax-error":
        (root / "src/evidence_manifest_toolkit/source_tripwire.py").write_text("def invalid(:\n")
    elif case == "changed-reviewed-source":
        source = root / _SIGNATURE
        source.write_bytes(source.read_bytes() + b"\n")
    elif case == "changed-reviewed-capture":
        source = root / _CAPTURE
        source.write_bytes(source.read_bytes() + b"\n")
    else:
        source = root / "requirements-dev.txt"
        source.write_bytes(source.read_bytes() + b"\n")
    before = snapshots(root)
    payload(run_guard("static_security", root), 2)
    assert not marker.exists() and snapshots(root) == before


@pytest.mark.parametrize("budget", (False, 0.0, -1.0, float("inf"), 121.0))
def test_actual_invalid_budget_refuses_before_scanning(root: Path, budget: float) -> None:
    """Reject unsupported caller ceilings without any scanner or source mutation."""
    before = snapshots(root)
    with pytest.raises(Fault) as error:
        verify(root, Report("static_security"), timeout=budget)
    assert error.value.exit_code == 4 and snapshots(root) == before


def test_actual_source_budget_exhaustion_precedes_native_exec(root: Path) -> None:
    """A real very small inherited ceiling expires during complete source acquisition."""
    before = snapshots(root)
    with pytest.raises(Fault) as error:
        verify(root, Report("static_security"), timeout=0.000001)
    assert error.value.code == "tool_timeout" and error.value.exit_code == 3
    assert snapshots(root) == before


def test_no_python_source_refuses_as_unavailable(root: Path) -> None:
    """Source absence cannot become a clean scan of an empty fabricated population."""
    for directory in ("src", "tools"):
        for path in (root / directory).rglob("*.py"):
            path.unlink()
    before = snapshots(root)
    payload(run_guard("static_security", root), 3)
    assert snapshots(root) == before


def test_public_callable_rejects_invalid_options() -> None:
    """The importable command entrypoint enforces the same closed CLI grammar."""
    assert main(["--unrecognized-option"]) == 4


@pytest.mark.parametrize("case", ("source-during-native", "publication-deadline"))
def test_native_scan_retains_source_and_publication_boundaries(
    root: Path, tmp_path: Path, actual_strace: Path, case: str
) -> None:
    """Use genuine native execution and syscall delays; no clock or producer is substituted."""
    program = """
import json,sys
sys.path.insert(0,sys.argv[1])
from pathlib import Path
from local_scaffold.static_security import verify
from local_scaffold.reports import Fault,Report
report=Report("static_security")
try:
    verify(Path(sys.argv[2]),report,timeout=10 if sys.argv[3]=="publication-deadline" else 120)
except Fault as error:
    print(json.dumps({"code":error.code,"exit_code":error.exit_code}))
    raise SystemExit(error.exit_code)
raise SystemExit(report.exit_code)
"""
    trace = tmp_path / "static-native.trace"
    injection = (
        "inject=fsync:delay_enter=15s:when=1"
        if case == "publication-deadline"
        else "inject=exit_group:delay_enter=1s"
    )
    command = [
        str(actual_strace),
        "-f",
        "-qq",
        "--kill-on-exit",
        "-s",
        "4096",
        "-o",
        str(trace),
        "-e",
        "trace=execve,fsync,exit_group",
        "-e",
        injection,
        *source_python("-B", "-c", program, str(SOURCE / "tools"), str(root), case),
    ]
    acted = False
    started = time.monotonic()
    with subprocess.Popen(
        command, cwd=SOURCE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    ) as child:
        try:
            while child.poll() is None:
                assert time.monotonic() - started < 50
                if case == "source-during-native" and not acted and trace.exists():
                    native = [
                        line
                        for line in trace.read_bytes().splitlines()
                        if b"execve(" in line and b'"bandit"' in line and b"= 0" in line
                    ]
                    if native:
                        target = root / _SIGNATURE
                        target.write_bytes(target.read_bytes() + b"\n")
                        acted = True
                time.sleep(0.01)
            stdout, stderr = child.communicate(timeout=5)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    expected = "tool_timeout" if case == "publication-deadline" else "source_identity_mismatch"
    assert json.loads(stdout)["code"] == expected, (stdout, stderr)
    assert child.returncode == (3 if case == "publication-deadline" else 2)
    assert acted == (case == "source-during-native")
