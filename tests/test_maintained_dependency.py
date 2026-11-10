# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — maintained dependency full public guard checks

"""Exercise real maintained artifact/source disagreements without changing audit qualification."""

import json
from pathlib import Path

import pytest

from tests.conftest import payload, run_guard, snapshots
from tests.test_package_metadata import package_root as package_root

_FILES = (
    "vendor/rfc8785/rfc8785-0.1.4+emt.1-py3-none-any.whl",
    "vendor/rfc8785/source-provenance.json",
    "vendor/rfc8785/upstream-typing.patch",
    "tools/vendor_rfc8785.py",
    "LICENSES/Apache-2.0.txt",
)


@pytest.mark.parametrize("name", _FILES, ids=("wheel", "provenance", "patch", "builder", "license"))
def test_complete_maintained_source_refusal_and_byte_recovery(
    package_root: Path, name: str
) -> None:
    """Refuse each changed actual source and restore the complete unchanged public report.

    Parameters
    ----------
    package_root : Path
        Every original source read by the full guard, including the fixed maintained files.
    name : str
        One exact local derivation source; its contents are read and never executed.
    """
    before = snapshots(package_root)
    baseline = run_guard("dependency_alignment", package_root)
    value = payload(baseline, 0)
    assert value["reasons"] == []
    path = package_root / name
    original = path.read_bytes()
    path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    changed = snapshots(package_root)
    actual = payload(run_guard("dependency_alignment", package_root), 2)
    reasons = actual["reasons"]
    assert isinstance(reasons, list)
    refusal = {
        "code": "dependency_alignment.wrong-producer",
        "location": name,
        "detail": "Required local infrastructure condition failed: dependency_alignment.wrong-producer.",
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


@pytest.mark.parametrize("case", ("kind", "path", "url", "sha256", "provenance"))
def test_complete_maintained_artifact_descriptor_refusal_and_recovery(
    package_root: Path, case: str
) -> None:
    """Refuse changed producer descriptors while preserving original source and audit boundaries.

    Parameters
    ----------
    package_root : Path
        Genuine full dependency input copies, without synthesized producer or audit values.
    case : str
        Exact original artifact field changed independently of the product checks.
    """
    before = snapshots(package_root)
    baseline = run_guard("dependency_alignment", package_root)
    value = payload(baseline, 0)
    path = package_root / "dependency-provenance.json"
    original = path.read_bytes()
    records = json.loads(original)
    row = next(row for row in records["packages"] if row["name"] == "rfc8785")
    artifact = row["source_artifact"]
    if case == "kind":
        artifact["kind"] = "bdist_wheel"
    elif case == "path":
        artifact["path"] = "other-wheel.whl"
    elif case == "url":
        artifact["url"] = "https://files.pythonhosted.org/packages/local-build.whl"
    elif case == "sha256":
        artifact["sha256"] = "0" * 64
    else:
        assert case == "provenance"
        artifact["provenance"]["sha256"] = "0" * 64
    path.write_text(json.dumps(records, sort_keys=True, indent=2) + "\n")
    changed = snapshots(package_root)
    actual = payload(run_guard("dependency_alignment", package_root), 2)
    reasons = actual["reasons"]
    assert isinstance(reasons, list)
    expected = [
        {
            "code": "dependency_alignment.licence-drift",
            "location": "dependency-provenance.json",
            "detail": "Required local infrastructure condition failed: dependency_alignment.licence-drift.",
        },
        {
            "code": "dependency_alignment.wrong-producer",
            "location": "dependency-provenance.json",
            "detail": "Required local infrastructure condition failed: dependency_alignment.wrong-producer.",
        },
    ]
    assert all(reason in reasons for reason in expected)
    assert {
        **actual,
        "reasons": [reason for reason in reasons if reason not in expected],
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
