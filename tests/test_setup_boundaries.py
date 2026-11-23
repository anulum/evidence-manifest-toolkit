# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Exercise actual setup Make targets against owned external symlink sentinels.

The audit producer owns its store and opens it without following links, so
``produce-audit`` has no Make guard of its own; ``tests/test_audit_store.py``
exercises that boundary.
"""

import subprocess
from pathlib import Path

import pytest

from tests.conftest import SOURCE

QUOTED = {("environment", ".venv")}
"""Guards over an overridable Make variable, which the recipe quotes."""


@pytest.mark.parametrize(
    ("target", "relative"),
    [
        ("environment", name)
        for name in (".venv", ".tool-cache", ".tool-cache/bootstrap-builders.lock")
    ]
    + [
        ("prepare-native", name)
        for name in (
            ".tool-cache",
            ".tool-cache/native",
            ".tool-cache/native-artifacts",
            ".tool-cache/native/actionlint",
            ".tool-cache/native/gitleaks",
            ".tool-cache/native/actionlint/actionlint",
            ".tool-cache/native/gitleaks/gitleaks",
            ".tool-cache/native-artifacts/actionlint.tar.gz",
            ".tool-cache/native-artifacts/gitleaks.tar.gz",
        )
    ]
    + [
        ("prepare-codeql", name)
        for name in (
            ".tool-cache",
            ".tool-cache/native-artifacts",
            ".tool-cache/native-artifacts/codeql-bundle-python-linux64.tar.zst",
        )
    ]
    + [
        ("prepare-test-fixtures", name)
        for name in (
            ".tool-cache",
            ".tool-cache/native-fixtures",
            ".tool-cache/native-fixtures/strace-6.8-0ubuntu2",
            ".tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb",
            ".tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted",
            ".tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr",
            ".tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/bin",
            ".tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/bin/strace",
            ".tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share",
            ".tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc",
            ".tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc/strace",
            ".tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc/strace/copyright",
        )
    ]
    + [
        ("prepare-test-wheels", name)
        for name in (
            ".tool-cache",
            ".tool-cache/wheelhouse",
            ".tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl",
            ".tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl",
        )
    ]
    + [
        ("prepare-interpreter-fixture", name)
        for name in (
            ".tool-cache",
            ".tool-cache/native-fixtures",
            ".tool-cache/native-fixtures/cpython-3.13.15",
            ".tool-cache/native-fixtures/cpython-3.13.15/cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
            ".tool-cache/native-fixtures/cpython-3.13.15/extracted",
            ".tool-cache/native-fixtures/cpython-3.13.15/extracted/python",
            ".tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin",
            ".tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin/python3.13",
            ".tool-cache/native-fixtures/cpython-3.13.15/guard-environment",
            ".tool-cache/native-fixtures/cpython-3.13.15/guard-environment/bin",
            ".tool-cache/native-fixtures/cpython-3.13.15/guard-environment/bin/python",
            ".tool-cache/native-fixtures/cpython-3.13.15/installer-cache",
        )
    ]
    + [
        ("prepare-major-interpreter-fixture", name)
        for name in (
            ".tool-cache",
            ".tool-cache/native-fixtures",
            ".tool-cache/native-fixtures/cpython-3.14.7",
            ".tool-cache/native-fixtures/cpython-3.14.7/cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
            ".tool-cache/native-fixtures/cpython-3.14.7/extracted",
            ".tool-cache/native-fixtures/cpython-3.14.7/extracted/python",
            ".tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin",
            ".tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin/python3.14",
            ".tool-cache/native-fixtures/cpython-3.14.7/guard-environment",
            ".tool-cache/native-fixtures/cpython-3.14.7/guard-environment/bin",
            ".tool-cache/native-fixtures/cpython-3.14.7/guard-environment/bin/python",
            ".tool-cache/native-fixtures/cpython-3.14.7/installer-cache",
            ".tool-cache/wheelhouse",
            ".tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl",
        )
    ],
)
def test_native_setup_refuses_external_symlinks(tmp_path: Path, target: str, relative: str) -> None:
    """A genuine Make invocation refuses before download, extraction or external write."""
    root = tmp_path / "owned-setup-repository"
    root.mkdir()
    (root / "Makefile").write_bytes((SOURCE / "Makefile").read_bytes())
    outside = tmp_path / "owned-unrelated-directory"
    outside.mkdir()
    sentinel = outside / "preserved"
    sentinel.write_bytes(b"actual existing external bytes")
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.symlink_to(outside, target_is_directory=True)
    before = sentinel.read_bytes()
    result = subprocess.run(
        ["make", "--no-print-directory", target], cwd=root, capture_output=True, timeout=10
    )
    assert result.returncode == 2
    guarded = f'"{relative}"' if (target, relative) in QUOTED else relative
    assert result.stdout.splitlines()[-1] == b"test ! -L " + guarded.encode()
    assert b"curl " not in result.stdout and b"pip_audit" not in result.stdout
    assert sentinel.read_bytes() == before
    assert list(outside.iterdir()) == [sentinel]
    assert destination.is_symlink()
