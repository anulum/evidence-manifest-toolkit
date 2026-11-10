# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole source quality hook refusal and recovery

"""Exercise real full dependency reports when required source quality hooks drift."""

from pathlib import Path

import pytest
import yaml

from tests.conftest import payload, run_guard, snapshots
from tests.test_package_metadata import package_root as package_root

_CASES = (
    "lint-src",
    "format-src",
    "typing-src",
    "missing-hook",
    "duplicate-hook",
    "language",
    "entry",
    "pass-filenames",
    "always-run",
    "numeric-false",
    "numeric-true",
    "hook-extra",
    "configuration-extra",
)


def _object(value: object) -> dict[str, object]:
    """Retain the entire known source mapping at the fixture decoder boundary.

    Parameters
    ----------
    value : object
        Original locally decoded YAML mapping.

    Returns
    -------
    dict of str to object
        Every original member after requiring string keys, without source projection.
    """
    assert isinstance(value, dict)
    result: dict[str, object] = {}
    for key, member in value.items():
        assert isinstance(key, str)
        result[key] = member
    return result


@pytest.mark.parametrize("case", _CASES)
def test_whole_quality_hook_drift_and_immutable_source_recovery(
    package_root: Path, case: str
) -> None:
    """Refuse removed or changed quality controls and recover every original report field.

    Parameters
    ----------
    package_root : Path
        Genuine whole dependency inputs and maintained source bytes, with the original audit.
    case : str
        Independently chosen omission, changed command or native control-field disagreement.

    Notes
    -----
    The real public dependency command starts from genuine current native admission.
    Each changed hook must independently refuse and recover the complete original
    result; no source or successful receipt is fabricated.
    """
    before = snapshots(package_root)
    baseline = run_guard("dependency_alignment", package_root)
    value = payload(baseline, 0)
    assert value["reasons"] == []
    path = package_root / ".pre-commit-config.yaml"
    original = path.read_bytes()
    configuration = _object(yaml.safe_load(original))
    repositories = configuration["repos"]
    assert isinstance(repositories, list)
    repository = _object(repositories[0])
    repositories[0] = repository
    hooks = repository["hooks"]
    assert isinstance(hooks, list)
    index = {"lint-src": 0, "format-src": 1, "typing-src": 2}.get(case, 0)
    hook = _object(hooks[index])
    hooks[index] = hook
    if case.endswith("-src"):
        entry = hook["entry"]
        assert isinstance(entry, str) and entry.count("src ") == 1
        hook["entry"] = entry.replace("src ", "")
    elif case == "missing-hook":
        hooks.pop()
    elif case == "duplicate-hook":
        hooks.append(dict(hook))
    elif case == "language":
        hook["language"] = "python"
    elif case == "entry":
        hook["entry"] = ".venv/bin/python -c pass"
    elif case == "pass-filenames":
        hook["pass_filenames"] = True
    elif case == "always-run":
        hook["always_run"] = False
    elif case == "numeric-false":
        hook["pass_filenames"] = 0
    elif case == "numeric-true":
        hook["always_run"] = 1
    elif case == "hook-extra":
        hook["additional_dependencies"] = ["other-package"]
    else:
        assert case == "configuration-extra"
        configuration["default_stages"] = ["pre-push"]
    path.write_text(yaml.safe_dump(configuration, sort_keys=False))
    changed = snapshots(package_root)
    actual = payload(run_guard("dependency_alignment", package_root), 2)
    reasons = actual["reasons"]
    assert isinstance(reasons, list)
    refusal = {
        "code": "dependency_alignment.hook-drift",
        "location": ".pre-commit-config.yaml",
        "detail": "Required local infrastructure condition failed: dependency_alignment.hook-drift.",
    }
    assert refusal in reasons
    assert {
        **actual,
        "reasons": [reason for reason in reasons if reason != refusal],
        "exit_code": value["exit_code"],
        "status": value["status"],
    } == value
    assert snapshots(package_root) == changed
    path.write_bytes(original)
    recovered = run_guard("dependency_alignment", package_root)
    assert (recovered.returncode, recovered.stdout, recovered.stderr) == (
        baseline.returncode,
        baseline.stdout,
        baseline.stderr,
    )
    assert snapshots(package_root) == before
