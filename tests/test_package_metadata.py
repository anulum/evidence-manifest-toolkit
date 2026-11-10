# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete development package guard correspondence

"""Exercise package declaration changes through the real complete dependency command."""

import shutil
from pathlib import Path

import pytest

from tests.conftest import SOURCE, payload, run_guard, snapshots

_CHANGES = (
    ("name", 'name = "evidence-manifest-toolkit"', 'name = "other-package"'),
    ("version", 'version = "0.0.0.dev0"', 'version = "1.0.0"'),
    ("missing-version", 'version = "0.0.0.dev0"\n', ""),
    ("python", 'requires-python = ">=3.13.18,<3.14"', 'requires-python = ">=3.9"'),
    ("builder", 'requires = ["poetry-core==2.5.0"]', 'requires = ["poetry-core"]'),
    ("backend", 'build-backend = "poetry.core.masonry.api"', 'build-backend = "other.api"'),
    (
        "console",
        'emt = "evidence_manifest_toolkit._cli:main"',
        'emt = "evidence_manifest_toolkit._inspection:inspect"',
    ),
    ("runtime", '"rfc8785==0.1.4+emt.1"', '"rfc8785==0.1.4"'),
    ("package", 'from = "src"', 'from = "tools"'),
    ("licenses", 'license-files = ["LICENSE", "LICENSES/*.txt"]', 'license-files = ["LICENSE"]'),
    ("typed-marker", 'path = "src/evidence_manifest_toolkit/py.typed"', 'path = "missing"'),
)
_REFUSAL = {
    "code": "dependency_alignment.runtime-dep",
    "location": "pyproject.toml",
    "detail": "Required local infrastructure condition failed: dependency_alignment.runtime-dep.",
}


@pytest.fixture
def package_root(tmp_path: Path) -> Path:
    """Copy every real input read by dependency alignment without synthesizing producers.

    Parameters
    ----------
    tmp_path : Path
        Owned Samsung caller directory for the public command's unchanged input copies.

    Returns
    -------
    Path
        Actual source inputs and the retained original audit, bound to genuine current trusted admission.
    """
    for name in (
        "requirements-dev.txt",
        "requirements-dev.in",
        "requirements-runtime.txt",
        "requirements-runtime.in",
        "dependency-provenance.json",
        "pyproject.toml",
        ".pre-commit-config.yaml",
        ".tool-cache/security/pip-audit.json",
        "vendor/rfc8785/rfc8785-0.1.4+emt.1-py3-none-any.whl",
        "vendor/rfc8785/source-provenance.json",
        "vendor/rfc8785/upstream-typing.patch",
        "tools/vendor_rfc8785.py",
        "LICENSES/Apache-2.0.txt",
    ):
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / name, destination)
    return tmp_path


@pytest.mark.parametrize("case, original, replacement", _CHANGES, ids=[row[0] for row in _CHANGES])
def test_complete_package_declaration_refusal_and_whole_recovery(
    package_root: Path, case: str, original: str, replacement: str
) -> None:
    """Retain every existing graph/audit refusal and add the exact malformed-package reason.

    Parameters
    ----------
    package_root : Path
        Entire genuine dependency input population, without patched environment or producers.
    case : str
        One complete project, backend, console, dependency or resource declaration change.
    original, replacement : str
        Exact valid TOML source fragment and its independently chosen disagreement.

    Notes
    -----
    The baseline consumes genuine current native registry admission. Each altered
    declaration must independently refuse and recover byte exactly; no audit
    response or accepting receipt is synthesized.
    """
    assert case
    before = snapshots(package_root)
    baseline_process = run_guard("dependency_alignment", package_root)
    assert baseline_process.returncode == 0
    baseline = payload(baseline_process, baseline_process.returncode)
    assert isinstance(baseline["reasons"], list)
    assert _REFUSAL not in baseline["reasons"]
    path = package_root / "pyproject.toml"
    text = path.read_text()
    assert text.count(original) == 1
    path.write_text(text.replace(original, replacement))
    changed = snapshots(package_root)
    actual_process = run_guard("dependency_alignment", package_root)
    actual = payload(actual_process, 2)
    reasons = actual["reasons"]
    assert isinstance(reasons, list) and sum(reason == _REFUSAL for reason in reasons) == 1
    assert {
        **actual,
        "reasons": [reason for reason in reasons if reason != _REFUSAL],
        "exit_code": baseline["exit_code"],
        "status": baseline["status"],
    } == baseline
    assert snapshots(package_root) == changed
    path.write_text(text)
    recovery_process = run_guard("dependency_alignment", package_root)
    assert (recovery_process.returncode, recovery_process.stdout, recovery_process.stderr) == (
        baseline_process.returncode,
        baseline_process.stdout,
        baseline_process.stderr,
    )
    assert snapshots(package_root) == before


def test_original_scaffold_and_complete_package_keep_independent_gates(package_root: Path) -> None:
    """Preserve the original scaffold path without interpreting package absence as qualification.

    Parameters
    ----------
    package_root : Path
        Genuine complete dependency input copies retaining independent source/audit refusals.
    """
    before = snapshots(package_root)
    path = package_root / "pyproject.toml"
    original = path.read_text()
    baseline_process = run_guard("dependency_alignment", package_root)
    assert baseline_process.returncode == 0
    baseline = payload(baseline_process, baseline_process.returncode)
    assert isinstance(baseline["reasons"], list) and _REFUSAL not in baseline["reasons"]
    start, end = original.index("[build-system]"), original.index("[tool.ruff]")
    path.write_text(original[:start] + original[end:])
    scaffold_process = run_guard("dependency_alignment", package_root)
    assert payload(scaffold_process, baseline_process.returncode) == baseline
    path.write_text(original)
    recovered = run_guard("dependency_alignment", package_root)
    assert (recovered.returncode, recovered.stdout, recovered.stderr) == (
        baseline_process.returncode,
        baseline_process.stdout,
        baseline_process.stderr,
    )
    assert snapshots(package_root) == before


@pytest.mark.parametrize(
    "case, name, replacement",
    (
        ("unknown-include", "requirements-dev.in", "-r other.in\n"),
        ("duplicate-include", "requirements-dev.in", "-r requirements-runtime.in\n"),
        ("unpinned", "requirements-dev.in", "other-package>=1\n"),
        ("duplicate-runtime", "requirements-runtime.in", "jsonschema==4.26.0\n"),
        ("unknown-option", "requirements-runtime.in", "--find-links other-directory\n"),
        ("invalid-name", "requirements-dev.in", "-package==1.0\n"),
        ("invalid-version", "requirements-dev.in", "other-package==invalid-version\n"),
    ),
    ids=(
        "unknown-include",
        "duplicate-include",
        "unpinned",
        "duplicate-runtime",
        "unknown-option",
        "invalid-name",
        "invalid-version",
    ),
)
def test_complete_local_direct_inputs_refuse_unknown_or_duplicate_pins(
    package_root: Path, case: str, name: str, replacement: str
) -> None:
    """Refuse malformed direct sources through the complete public guard and recover unchanged bytes.

    Parameters
    ----------
    package_root : Path
        Every actual source read by the guard, including the real local runtime input.
    case : str
        Exact independently chosen source-line disagreement.
    name : str
        Original development or runtime input path; it selects no executable.
    replacement : str
        Complete malformed line appended to the original unchanged source population.
    """
    assert case
    before = snapshots(package_root)
    baseline = run_guard("dependency_alignment", package_root)
    assert baseline.returncode == 0
    baseline_value = payload(baseline, baseline.returncode)
    assert isinstance(baseline_value["reasons"], list)
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "configuration_invalid"
        for reason in baseline_value["reasons"]
    )
    path = package_root / name
    original = path.read_bytes()
    path.write_bytes(original + replacement.encode("ascii"))
    changed = snapshots(package_root)
    value = payload(run_guard("dependency_alignment", package_root), 4)
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    assert {
        "code": "configuration_invalid",
        "location": name,
        "detail": "Required local infrastructure condition failed: configuration_invalid.",
    } in reasons
    assert snapshots(package_root) == changed
    path.write_bytes(original)
    recovered = run_guard("dependency_alignment", package_root)
    assert (recovered.returncode, recovered.stdout, recovered.stderr) == (
        baseline.returncode,
        baseline.stdout,
        baseline.stderr,
    )
    assert snapshots(package_root) == before
