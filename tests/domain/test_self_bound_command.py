# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the self-bound launch as the command a launcher starts as its child

"""Run ``emt verify-self-bound`` as a real child process and check its outputs and exits."""

import json
import os
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

from coverage import Coverage
from tests.domain.self_bound_inputs import SelfBoundInputs, self_bound_inputs

from evidence_manifest_toolkit._clock_verdict import CHECK_IDS

QUALIFIED = Fraction(15, 1_000_000)
_REPOSITORY = Path(__file__).resolve().parents[2]


def _run(arguments: list[str], directory: Path) -> subprocess.CompletedProcess[bytes]:
    """Start the command as a child that a measured session also measures.

    The child runs in ``src/``, where coverage finds no configuration, so it is given the
    repository's configuration and an absolute data file: the active session's, otherwise one
    under ``directory``. Nothing is written into ``src/``.

    Parameters
    ----------
    arguments : list of str
        The command line after ``python -m evidence_manifest_toolkit``.
    directory : Path
        The test's own temporary directory, also the child's temporary directory.

    Returns
    -------
    subprocess.CompletedProcess of bytes
        The child's exit status, standard output and standard error.
    """
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    active = Coverage.current()
    environment.update(
        PYTHONDONTWRITEBYTECODE="1",
        TMPDIR=str(directory),
        TMP=str(directory),
        TEMP=str(directory),
        COVERAGE_FILE=(
            os.path.abspath(active.config.data_file)
            if active is not None
            else str(directory / "child-coverage")
        ),
    )
    src_entries = sorted(entry.name for entry in (_REPOSITORY / "src").iterdir())
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "coverage",
            "run",
            "--branch",
            "--parallel-mode",
            "--rcfile=" + str(_REPOSITORY / "pyproject.toml"),
            "--source=evidence_manifest_toolkit._cli,evidence_manifest_toolkit._cli_operations",
            "-m",
            "evidence_manifest_toolkit",
            *arguments,
        ],
        cwd=_REPOSITORY / "src",
        env=environment,
        capture_output=True,
        timeout=300,
        check=False,
    )
    assert sorted(entry.name for entry in (_REPOSITORY / "src").iterdir()) == src_entries
    return result


def _arguments(case: SelfBoundInputs, report: Path) -> list[str]:
    """Return the whole command line of one launch."""
    return [
        "verify-self-bound",
        "--declaration",
        str(case.declaration_path),
        "--content",
        str(case.content),
        "--schema-id",
        case.schema_id,
        "--registry",
        str(case.registry),
        "--objects",
        str(case.objects),
        "--limits",
        str(case.limits),
        "--request",
        str(case.request),
        "--report",
        str(report),
    ]


def _listing(directory: Path) -> dict[str, bytes]:
    """Return every file under ``directory`` with its bytes."""
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def test_a_child_started_as_the_command_verifies_its_own_request_and_exits_0(
    tmp_path: Path,
) -> None:
    """The child builds and verifies its request; stdout and the report file are the same bytes."""
    case = self_bound_inputs(
        tmp_path, rate=QUALIFIED, declared_checks=dict.fromkeys(CHECK_IDS, "pass")
    )
    report = tmp_path / "report.json"
    result = _run(_arguments(case, report), tmp_path)
    assert (result.returncode, result.stderr) == (0, b"")
    assert report.read_bytes() == result.stdout
    published = json.loads(result.stdout)
    assert (published["authenticity"], published["common_eligibility"]) == ("unsigned", "eligible")
    assert published["reasons"][0]["code"] == "time_consistency_only"
    assert sorted(path.name for path in case.request.iterdir()) == [
        "policy.json",
        "request.json",
        "trust.json",
    ]
    policy = json.loads((case.request / "policy.json").read_bytes())
    assert published["policy_ref"] == policy["policy_ref"]


def test_a_taken_report_name_is_refused_before_anything_is_captured(tmp_path: Path) -> None:
    """An existing report file refuses with exit 4 at /report; no request or record is written."""
    case = self_bound_inputs(tmp_path, rate=QUALIFIED)
    report = tmp_path / "report.json"
    report.write_bytes(b"earlier")
    before = _listing(case.objects)
    result = _run(_arguments(case, report), tmp_path)
    error = json.loads(result.stdout)
    assert (result.returncode, error["operation"]) == (4, "verify-self-bound")
    assert [reason["pointer"] for reason in error["reasons"]] == ["/report"]
    assert report.read_bytes() == b"earlier"
    assert not case.request.exists()
    assert _listing(case.objects) == before


def test_a_contradicted_declaration_exits_2_and_writes_nothing(tmp_path: Path) -> None:
    """A budget declared to hold at too low a rate is refused; no report, request or record."""
    case = self_bound_inputs(
        tmp_path, rate=Fraction(1, 1_000_000), declared_checks=dict.fromkeys(CHECK_IDS, "pass")
    )
    report = tmp_path / "report.json"
    before = _listing(case.objects)
    result = _run(_arguments(case, report), tmp_path)
    error = json.loads(result.stdout)
    assert (result.returncode, error["operation"]) == (2, "verify-self-bound")
    assert [(reason["code"], reason["pointer"]) for reason in error["reasons"]] == [
        ("policy_unavailable", f"/checks/{CHECK_IDS.index('proven_uncertainty_budget')}/result")
    ]
    assert not report.exists()
    assert not case.request.exists()
    assert _listing(case.objects) == before


def test_an_incomplete_invocation_is_refused_under_the_command_name(tmp_path: Path) -> None:
    """A missing --request is an invalid invocation of verify-self-bound, exit 4."""
    case = self_bound_inputs(tmp_path, rate=QUALIFIED)
    arguments = _arguments(case, tmp_path / "report.json")
    index = arguments.index("--request")
    del arguments[index : index + 2]
    result = _run(arguments, tmp_path)
    error = json.loads(result.stdout)
    assert (result.returncode, error["operation"]) == (4, "verify-self-bound")
    assert not case.request.exists()
