# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual isolated installed source behavior through public verification

"""Exercise real installed package faults without mutating canonical source or replacing providers."""

import json
import os
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

import pytest
from coverage import Coverage
from tests.domain.native_installation_inputs import NATIVE_INSTALLATION_CASES
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow
from tests.domain.test_verification_report_sources import _array, _object, _text

import evidence_manifest_toolkit


@pytest.mark.parametrize("condition", NATIVE_INSTALLATION_CASES)
def test_actual_native_installation_through_public_verification(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Apply an entire actual filesystem fault before the original complete public operation.

    Parameters
    ----------
    condition : str
        Known selected descriptor, code, layout or original bound contradiction.
    tmp_path : Path
        Owned isolated package and whole independent source inputs, not canonical files.
    capfd : pytest.CaptureFixture
        Actual public output, without a replaced native sampler or I/O provider.

    Notes
    -----
    The child imports the isolated actual product before changing loaded code permissions.
    The complete selected descriptor input is frozen separately from physical installation.
    Every child executes the public verifier; no private product method is invoked directly.
    """
    if os.environ.get("EMT_INSTALLATION_ISOLATED_CHILD") != "1":
        isolated = tmp_path / "successor-package-native-implementation"
        package = isolated / "evidence_manifest_toolkit"
        assert evidence_manifest_toolkit.__file__ is not None
        shutil.copytree(
            Path(evidence_manifest_toolkit.__file__).parent,
            package,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        original = isolated / "independent-descriptor-input.raw"
        original.write_bytes(
            files("evidence_manifest_toolkit")
            .joinpath("_native_launch_implementation.json")
            .read_bytes()
        )
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
            + "::test_actual_native_installation_through_public_verification["
            + condition
            + "]",
        ]
        environment = dict(
            os.environ,
            EMT_INSTALLATION_ISOLATED_CHILD="1",
            EMT_INSTALLATION_DESCRIPTOR_INPUT=str(original),
            PYTHONPATH=str(isolated) + os.pathsep + str(root),
        )
        if active is not None:
            environment["COVERAGE_FILE"] = active.config.data_file
        result = subprocess.run(
            command, cwd=root, env=environment, capture_output=True, text=True, timeout=90
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "1 passed" in result.stdout and result.stderr == ""
        return
    assert evidence_manifest_toolkit.__file__ is not None
    package = Path(evidence_manifest_toolkit.__file__).parent
    assert "successor-package-native-implementation" in package.parts
    assert "evidence_manifest_toolkit._native_installation" in sys.modules
    selected = Path(os.environ["EMT_INSTALLATION_DESCRIPTOR_INPUT"]).read_bytes()
    descriptor = package / "_native_launch_implementation.json"
    code = package / "_native_installation.py"
    case = condition.removeprefix("native_binding_installation_")
    restore: list[tuple[Path, int]] = []
    try:
        if case == "descriptor_missing":
            descriptor.unlink()
        elif case == "descriptor_changed":
            descriptor.write_bytes(b"[" + descriptor.read_bytes()[1:])
        elif case == "descriptor_truncated":
            descriptor.write_bytes(descriptor.read_bytes()[:-1])
        elif case.startswith("selected_"):
            value = _object(json.loads(selected))
            if case == "selected_invalid_json":
                selected = b"{"
            elif case == "selected_invalid_utf8":
                selected = b"\xff"
            elif case == "selected_depth_limit":
                selected = b"[" * 65 + b"]" * 65
            else:
                population = [_object(row) for row in _array(value["implementation_files"])]
                value["implementation_files"] = population
                if case == "selected_extra":
                    value["unexpected"] = True
                elif case == "selected_version":
                    value["method_version"] = "2"
                elif case == "selected_omitted":
                    population.pop()
                elif case == "selected_added":
                    population.append({**population[0], "filename": "../../outside-source"})
                elif case == "selected_reordered":
                    population.reverse()
                elif case == "selected_pin_length":
                    population[0]["byte_length"] = str(int(_text(population[0]["byte_length"])) + 1)
                elif case == "selected_pin_hash":
                    population[0]["sha256"] = "0" * 64
                elif case == "selected_remaining_bound":
                    population[0]["byte_length"] = "2000000"
                else:
                    assert case == "selected_pin_oversized"
                    population[0]["byte_length"] = str(2**64)
                selected = json.dumps(value).encode()
            descriptor.write_bytes(selected)
        elif case == "source_missing":
            code.unlink()
        elif case == "source_changed":
            code.write_bytes(code.read_bytes() + b"\n")
        elif case == "source_truncated":
            code.write_bytes(code.read_bytes()[:-1])
        elif case in {"source_unreadable", "listing_unreadable"}:
            target = code if case == "source_unreadable" else package
            restore.append((target, target.stat().st_mode & 0o777))
            target.chmod(0 if case == "source_unreadable" else 0o111)
        elif case == "unexpected_directory":
            (package / "unknown_native_owner").mkdir()
        elif case == "extension_layout":
            (package / "unknown_native_owner.so").write_bytes(
                b"unloaded unsupported installed extension layout"
            )
        elif case == "schema_python":
            (package / "_schemas/unknown_native_owner.py").write_bytes(
                b"unloaded unsupported schema source layout"
            )
        elif case == "ignored_noncode":
            (package / "__pycache__").mkdir()
            (package / "_schemas/__pycache__").mkdir()
            (package / "metadata.txt").write_bytes(b"ordinary nonexecutable package metadata")
        else:
            assert case == "blob_bound"
        assert_whole_clock_source_workflow(
            condition,
            tmp_path,
            capfd,
            launcher_implementation_bytes=selected,
            limits_override={"max_blob_bytes": 43000}
            if case == "blob_bound"
            else {"max_blob_bytes": 10000000, "max_total_reference_bytes": 2000000}
            if case == "selected_remaining_bound"
            else None,
        )
    finally:
        for target, mode in reversed(restore):
            target.chmod(mode)
