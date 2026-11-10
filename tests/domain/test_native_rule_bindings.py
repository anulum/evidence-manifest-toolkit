# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete public native rule-binding source workflow

"""Exercise whole native rule data through the original public verification and CLI workflow."""

import hashlib
import os
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

import pytest
from coverage import Coverage
from tests.domain.native_method_inputs import NATIVE_METHOD_CASES
from tests.domain.native_rule_binding_inputs import NATIVE_BINDING_CASES
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow

import evidence_manifest_toolkit
from evidence_manifest_toolkit import BlobRef


@pytest.mark.parametrize(
    "condition", tuple(case for case in NATIVE_BINDING_CASES if case not in NATIVE_METHOD_CASES)
)
def test_native_rule_bindings_through_complete_public_workflow(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Keep all original source fields and exact API/CLI diagnostics under actual faults.

    Parameters
    ----------
    condition : str
        Whole binding shape/metadata/source/resource failure or matching declaration.
    tmp_path : Path
        Owned real source and isolated installed-package source-copy directory.
    capfd : pytest.CaptureFixture
        Actual same-process module CLI output, never mocked I/O or native sampling.

    Notes
    -----
    A matching declaration remains unqualified and reaches the original final V2
    configuration boundary. Resource faults change real isolated package bytes;
    neither canonical source nor another test process is mutated.
    """
    if condition == "native_binding_remaining_total":
        baseline = tmp_path / "quota-baseline"
        baseline.mkdir()
        observed: list[tuple[BlobRef | str, int]] = []
        total = 10_000_000
        assert_whole_clock_source_workflow(
            "native_binding_matching",
            baseline,
            capfd,
            limits_override={"max_blob_bytes": total, "max_total_reference_bytes": total},
            resolver_calls=observed,
        )
        implementation = (
            files("evidence_manifest_toolkit")
            .joinpath("_native_launch_implementation.json")
            .read_bytes()
        )
        digest = "sha256:" + hashlib.sha256(implementation).hexdigest()
        maximum = next(
            bound
            for reference, bound in observed
            if isinstance(reference, BlobRef)
            and reference.digest == digest
            and reference.media_type == "application/json"
        )
        grammar_size = len(
            files("evidence_manifest_toolkit")
            .joinpath("_schemas", "native_method_data.json")
            .read_bytes()
        )
        prefix = total - maximum - grammar_size
        assert prefix > 0 and grammar_size > 0
        target_total = prefix + grammar_size // 2
        target = tmp_path / "quota-target"
        target.mkdir()
        target_calls: list[tuple[BlobRef | str, int]] = []
        assert_whole_clock_source_workflow(
            condition,
            target,
            capfd,
            limits_override={"max_blob_bytes": total, "max_total_reference_bytes": target_total},
            resolver_calls=target_calls,
        )
        assert not any(
            isinstance(reference, BlobRef) and reference.digest == digest
            for reference, _ in target_calls
        )
        return
    if condition in {
        "native_binding_resource_missing",
        "native_binding_resource_changed",
        "native_binding_resource_truncated",
    } and (os.environ.get("EMT_NATIVE_BINDING_ISOLATED_CHILD") != "1"):
        isolated = tmp_path / "successor-package-native-method-source"
        package = isolated / "evidence_manifest_toolkit"
        assert evidence_manifest_toolkit.__file__ is not None
        shutil.copytree(
            Path(evidence_manifest_toolkit.__file__).parent,
            package,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        resource = package / "_schemas" / "native_method_data.json"
        if condition == "native_binding_resource_missing":
            resource.unlink()
        elif condition == "native_binding_resource_truncated":
            resource.write_bytes(resource.read_bytes()[:-1])
        else:
            raw = resource.read_bytes()
            resource.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        root = Path(__file__).parents[2]
        command = [sys.executable, "-B"]
        active = Coverage.current()
        if active is not None:
            command += [
                "-m",
                "coverage",
                "run",
                "--parallel-mode",
                "--rcfile=" + str(root / "pyproject.toml"),
            ]
            if active.config.source:
                command += ["--source=" + ",".join(active.config.source)]
        command += [
            "-m",
            "pytest",
            "-q",
            "--tb=short",
            "-p",
            "no:cacheprovider",
            "-o",
            "pythonpath=" + str(isolated) + " tools",
            "--basetemp=" + str(tmp_path / "child-tests"),
            str(Path(__file__).relative_to(root))
            + "::test_native_rule_bindings_through_complete_public_workflow["
            + condition
            + "]",
        ]
        environment = dict(os.environ, EMT_NATIVE_BINDING_ISOLATED_CHILD="1")
        environment["PYTHONPATH"] = str(isolated) + os.pathsep + str(root)
        if active is not None:
            environment["COVERAGE_FILE"] = active.config.data_file
        result = subprocess.run(
            command, cwd=root, env=environment, capture_output=True, text=True, timeout=90
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "1 passed" in result.stdout and result.stderr == ""
        return
    if os.environ.get("EMT_NATIVE_BINDING_ISOLATED_CHILD") == "1":
        assert evidence_manifest_toolkit.__file__ is not None
        assert (
            "successor-package-native-method-source"
            in Path(evidence_manifest_toolkit.__file__).parts
        )
    assert_whole_clock_source_workflow(condition, tmp_path, capfd)
