# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original empty signer installation transport

"""Exercise real default-install signer absence without creating a fake qualified signer."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def _object(value: object) -> dict[str, object]:
    """Retain the entire independently fixed source mapping."""
    assert isinstance(value, dict) and all(isinstance(key, str) for key in value)
    return dict(value)


def _text(value: object) -> str:
    """Retain an original source string without coercion."""
    assert isinstance(value, str)
    return value


def test_original_signed_cli_empty_installation_before_sign_and_publication(tmp_path: Path) -> None:
    """Compare the complete selected pre-sign error through the real public signed command.

    Parameters
    ----------
    tmp_path : Path
        Owned original six input files and entire real offline store, preserved after refusal.

    Notes
    -----
    The default installation is empty. No qualified association, signer call, signature,
    positive signed recovery or operational root is supplied or inferred by this test.
    """
    source = _object(
        json.loads(
            (
                Path(__file__).parent / "fixtures/cli-signer-empty-installation-source.json"
            ).read_bytes()
        )
    )
    population = _object(source["exact_original_files_hex"])
    for name, token in population.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes.fromhex(_text(token)))
    (tmp_path / "out").mkdir()
    before = {
        name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() for name in population
    }
    argv = source["argv"]
    assert isinstance(argv, list)
    arguments = [_text(value) for value in argv]
    for index, token in enumerate(arguments):
        if token in {
            "--content",
            "--registry",
            "--objects",
            "--limits",
            "--output",
            "--signing-request",
            "--signer-config",
            "--trust",
        }:
            arguments[index + 1] = str(tmp_path / arguments[index + 1])
    expected = _object(source["source_selected_empty_installation"])
    expected_bytes = bytes.fromhex(_text(expected["exact_expected_stdout_hex"]))
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(tmp_path), TMP=str(tmp_path), TEMP=str(tmp_path)
    )
    actual = subprocess.run(
        [sys.executable, "-B", "-m", "evidence_manifest_toolkit", *arguments],
        cwd=Path(__file__).resolve().parents[2] / "src",
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert (actual.returncode, actual.stdout, actual.stderr) == (
        expected["expected_exit"],
        expected_bytes,
        b"",
    )
    assert not (tmp_path / "out/sealed").exists()
    assert not list((tmp_path / "out").iterdir())
    assert before == {
        name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() for name in population
    }
    assert {
        str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*") if path.is_file()
    } == population.keys()
