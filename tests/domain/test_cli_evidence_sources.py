# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original complete evidence process transport

"""Exercise real evidence commands against portable unchanged whole-source byte oracles."""

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_REPOSITORY = Path(__file__).resolve().parents[2]
_VERIFICATION_CASES = (
    "verify-current-whole-fixture",
    "verify-historical-whole-fixture",
    "verify-required-signature-absent",
    "verify-narrow-claim-scope",
    "verify-required-evaluation-time-qualification-absent",
    "verify-required-environment-unavailable",
    "verify-required-environment-mismatch",
    "verify-current-expiry-endpoint",
    "verify-current-floor-rollback",
)


@pytest.mark.parametrize("command", ("seal", "verify"))
def test_broken_stdout_retains_complete_publication_and_distinct_recovery(
    command: str, tmp_path: Path
) -> None:
    """Retain committed output after a real pipe failure without reporting process success.

    Parameters
    ----------
    command : str
        Original unsigned seal or full current verification, using unchanged source oracles.
    tmp_path : Path
        Owned caller inputs, a readerless native pipe and fresh output destinations.
    """
    case = "seal-unsigned-whole-fixture" if command == "seal" else "verify-current-whole-fixture"
    source = _source(case)
    arguments = _inputs(source, tmp_path)
    before = _hashes(tmp_path)
    destination = tmp_path / "committed-output"
    recovery = tmp_path / "distinct-recovery"
    flag = "--output" if command == "seal" else "--report"
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(tmp_path), TMP=str(tmp_path), TEMP=str(tmp_path)
    )
    reader, writer = os.pipe()
    os.close(reader)
    try:
        failed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "evidence_manifest_toolkit",
                *arguments,
                flag,
                str(destination),
            ],
            cwd=_REPOSITORY / "src",
            env=environment,
            stdout=writer,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    finally:
        os.close(writer)
    assert (failed.returncode, failed.stderr) == (3, b"")
    identity = destination.stat()
    if command == "seal":
        expected = _object(source["expected_entire_SealResult"])
        canonical = _bytes(expected["canonical_content"])
        refs = (_FIXTURES / "unsigned-refs.json").read_bytes()
        assert {path.name for path in destination.iterdir()} == {"content.json", "refs.json"}
        assert (destination / "content.json").read_bytes() == canonical
        assert (destination / "refs.json").read_bytes() == refs
        success = _transport(
            {
                "canonical_content": {
                    "content_ref": expected["content_ref"],
                    "output_file": str(recovery / "content.json"),
                },
                "content_ref": expected["content_ref"],
                "envelope_json": None,
            }
        )
    else:
        success = _transport(source["expected_entire_VerificationReport"])
        assert destination.read_bytes() == success
    committed = _hashes(tmp_path)
    collision = _run(arguments + [flag, str(destination)], tmp_path)
    assert (collision.returncode, collision.stdout, collision.stderr) == (
        3,
        _collision(command),
        b"",
    )
    assert _hashes(tmp_path) == committed
    repaired = _run(arguments + [flag, str(recovery)], tmp_path)
    assert (repaired.returncode, repaired.stdout, repaired.stderr) == (0, success, b"")
    if command == "seal":
        assert {path.name for path in recovery.iterdir()} == {"content.json", "refs.json"}
        for name in ("content.json", "refs.json"):
            assert (recovery / name).read_bytes() == (destination / name).read_bytes()
    else:
        assert recovery.read_bytes() == destination.read_bytes() == success
    after = _hashes(tmp_path)
    assert {key: after[key] for key in committed} == committed
    assert {key: after[key] for key in before} == before
    retained = destination.stat()
    assert (retained.st_dev, retained.st_ino) == (identity.st_dev, identity.st_ino)
    assert not list(tmp_path.glob(".emt-*"))


def _object(value: object) -> dict[str, object]:
    """Retain complete fixture fields without implementing any product predicate."""
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return dict(value)


def _text(value: object) -> str:
    """Retain exact fixture strings without coercion."""
    assert isinstance(value, str)
    return value


def _bytes(value: object) -> bytes:
    """Decode only the fixture's independently prepared original Base64URL bytes."""
    token = _text(value)
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))


def _transport(value: object) -> bytes:
    """Encode the known ASCII-only original oracle without using the product formatter."""
    token = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert token.isascii()
    return token.encode("ascii")


def _source(case: str) -> dict[str, object]:
    """Check entire original source bytes against their independently recorded provenance."""
    data = (_FIXTURES / (case + ".json")).read_bytes()
    pins = _object(json.loads((_FIXTURES / "source-pins.json").read_bytes()))
    members = pins["original_cases"]
    assert isinstance(members, list)
    selected = next(_object(member) for member in members if _object(member)["case_id"] == case)
    assert hashlib.sha256(data).hexdigest() == selected["source_sha256"]
    return _object(json.loads(data))


def _inputs(source: dict[str, object], directory: Path) -> list[str]:
    """Materialise full caller configurations and actual flat-store original bytes."""
    inputs = _object(source["complete_library_inputs"])
    objects = directory / "objects"
    objects.mkdir()
    captured: dict[str, bytes] = {}
    for key, member in _object(inputs["resolver_input_population"]).items():
        digest, basis = key.split("|")
        assert basis in {"raw_bytes", "jcs_content"}
        record = _object(member)
        data = (_FIXTURES / "objects" / _text(record["sha256"])).read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        assert len(data) == record["byte_length"]
        if digest in captured:
            assert captured[digest] == data
        captured[digest] = data
    for key, value in _object(inputs.get("resolver_overrides", {})).items():
        digest, _basis = key.split("|")
        override = _object(value)
        if override["mode"] == "missing":
            captured.pop(digest)
        else:
            assert override["mode"] == "exact_wrong_bytes"
            captured[digest] = _bytes(override["returned_bytes_base64url"])
    for digest, data in captured.items():
        (objects / digest.removeprefix("sha256:")).write_bytes(data)
    (directory / "content.json").write_bytes(_bytes(inputs["content_json"]))
    arguments = [
        _text(source["operation"]),
        "--content",
        str(directory / "content.json"),
        "--schema-id",
        _text(inputs["schema_id"]),
        "--objects",
        str(objects),
    ]
    for name in ("registry", "limits", "policy", "trust"):
        if name in inputs and inputs[name] is not None:
            path = directory / (name + ".json")
            path.write_bytes(_transport(inputs[name]))
            arguments.extend(["--" + name, str(path)])
    envelopes = inputs.get("envelopes", [])
    assert isinstance(envelopes, list)
    for index, token in enumerate(envelopes):
        path = directory / f"signature-{index}.json"
        path.write_bytes(_bytes(token))
        arguments.extend(["--signature", str(path)])
    return arguments


def _run(arguments: list[str], directory: Path) -> subprocess.CompletedProcess[bytes]:
    """Invoke genuine source-module processes without Python or typing overlays."""
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(directory), TMP=str(directory), TEMP=str(directory)
    )
    return subprocess.run(
        [sys.executable, "-B", "-m", "evidence_manifest_toolkit", *arguments],
        cwd=_REPOSITORY / "src",
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )


def _hashes(directory: Path) -> dict[str, str]:
    """Observe all original files and output bytes through the real filesystem."""
    return {
        str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.rglob("*")
        if path.is_file()
    }


def _collision(command: str) -> bytes:
    """Retain the full independent original collision refusal, without a successful field."""
    return _transport(
        {
            "operation": command,
            "reasons": [
                {
                    "code": "storage_error",
                    "subject_digest": None,
                    "claim_id": None,
                    "pointer": None,
                    "detail": "Output could not be stored.",
                }
            ],
        }
    )


@pytest.mark.parametrize("case", _VERIFICATION_CASES)
def test_original_whole_verify_process_report_collision_and_distinct_recovery(
    case: str, tmp_path: Path
) -> None:
    """Compare every original report field, exit and immutable input through real verify CLI.

    Parameters
    ----------
    case : str
        One complete original source and independent fifteen-field report oracle.
    tmp_path : Path
        Owned test directory containing source copies, real store and fresh output files.
    """
    source = _source(case)
    expected = _transport(source["expected_entire_VerificationReport"])
    expected_exit = source["expected_CLI_exit"]
    arguments = _inputs(source, tmp_path)
    before = _hashes(tmp_path)
    destination = tmp_path / "original-report.json"
    recovery = tmp_path / "recovery-report.json"
    actual = _run(arguments + ["--report", str(destination)], tmp_path)
    assert (actual.returncode, actual.stdout, actual.stderr) == (expected_exit, expected, b"")
    assert destination.read_bytes() == expected
    collision = _run(arguments + ["--report", str(destination)], tmp_path)
    assert (collision.returncode, collision.stdout, collision.stderr) == (
        3,
        _collision("verify"),
        b"",
    )
    assert destination.read_bytes() == expected
    repaired = _run(arguments + ["--report", str(recovery)], tmp_path)
    assert (repaired.returncode, repaired.stdout, repaired.stderr) == (expected_exit, expected, b"")
    assert recovery.read_bytes() == destination.read_bytes() == expected
    after = _hashes(tmp_path)
    assert {key: after[key] for key in before} == before
    assert after.keys() == before.keys() | {destination.name, recovery.name}


def test_original_whole_unsigned_seal_process_directory_collision_and_recovery(
    tmp_path: Path,
) -> None:
    """Compare full unsigned publication, exclusive refusal and fresh recovery against original bytes.

    Parameters
    ----------
    tmp_path : Path
        Owned directory retaining exact source/store bytes and complete atomic output sets.
    """
    source = _source("seal-unsigned-whole-fixture")
    expected = _object(source["expected_entire_SealResult"])
    reference = expected["content_ref"]
    canonical = _bytes(expected["canonical_content"])
    refs = (_FIXTURES / "unsigned-refs.json").read_bytes()
    assert refs == _transport({"content_ref": reference})
    arguments = _inputs(source, tmp_path)
    before = _hashes(tmp_path)
    for name, status in (("original", 0), ("original", 3), ("recovery", 0)):
        destination = tmp_path / name
        stdout = (
            _collision("seal")
            if status == 3
            else _transport(
                {
                    "canonical_content": {
                        "content_ref": reference,
                        "output_file": str(destination / "content.json"),
                    },
                    "content_ref": reference,
                    "envelope_json": None,
                }
            )
        )
        actual = _run(arguments + ["--output", str(destination)], tmp_path)
        assert (actual.returncode, actual.stdout, actual.stderr) == (status, stdout, b"")
        assert {path.name for path in destination.iterdir()} == {"content.json", "refs.json"}
        assert (destination / "content.json").read_bytes() == canonical
        assert (destination / "refs.json").read_bytes() == refs
    after = _hashes(tmp_path)
    assert {key: after[key] for key in before} == before
    assert after.keys() == before.keys() | {
        "original/content.json",
        "original/refs.json",
        "recovery/content.json",
        "recovery/refs.json",
    }
    assert not list(tmp_path.glob(".emt-*"))


def test_current_native_context_with_omitted_optional_reference_schema(tmp_path: Path) -> None:
    """Retain the full current report when only optional caller reference metadata is omitted.

    Parameters
    ----------
    tmp_path : Path
        Owned copied caller inputs; original snapshot, signatures, corpus and store remain
        unchanged. Known current context independently retains its native schema binding.
    """
    source = _source("verify-current-whole-fixture")
    expected = _transport(source["expected_entire_VerificationReport"])
    arguments = _inputs(source, tmp_path)
    trust_path = tmp_path / "trust.json"
    trust = _object(json.loads(trust_path.read_bytes()))
    reference = _object(trust["current_snapshot_ref"])
    assert reference.pop("schema_id") == "evidence_manifest_toolkit.trust_snapshot.v1"
    trust["current_snapshot_ref"] = reference
    trust_path.write_bytes(_transport(trust))
    before = _hashes(tmp_path)
    report = tmp_path / "full-context-report.json"
    actual = _run(arguments + ["--report", str(report)], tmp_path)
    assert (actual.returncode, actual.stdout, actual.stderr) == (0, expected, b"")
    assert report.read_bytes() == expected
    after = _hashes(tmp_path)
    assert {key: after[key] for key in before} == before
    assert after.keys() == before.keys() | {report.name}


def test_unsigned_seal_two_real_writers_preserve_the_complete_winner(tmp_path: Path) -> None:
    """Race actual public command processes and retain exactly one complete immutable output.

    Parameters
    ----------
    tmp_path : Path
        Owned original source/store and the single destination shared by two real writers.
    """
    source = _source("seal-unsigned-whole-fixture")
    expected = _object(source["expected_entire_SealResult"])
    reference = expected["content_ref"]
    canonical = _bytes(expected["canonical_content"])
    refs = (_FIXTURES / "unsigned-refs.json").read_bytes()
    arguments = _inputs(source, tmp_path)
    before = _hashes(tmp_path)
    destination = tmp_path / "shared-output"
    success = _transport(
        {
            "canonical_content": {
                "content_ref": reference,
                "output_file": str(destination / "content.json"),
            },
            "content_ref": reference,
            "envelope_json": None,
        }
    )
    failure = _collision("seal")
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(tmp_path), TMP=str(tmp_path), TEMP=str(tmp_path)
    )
    processes: list[subprocess.Popen[bytes]] = []
    results: list[tuple[int | None, bytes, bytes]] = []
    try:
        for _ in range(2):
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-B",
                        "-m",
                        "evidence_manifest_toolkit",
                        *arguments,
                        "--output",
                        str(destination),
                    ],
                    cwd=_REPOSITORY / "src",
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            )
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            results.append((process.returncode, stdout, stderr))
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait()
    assert sorted(result[0] for result in results if result[0] is not None) == [0, 3]
    for status, stdout, stderr in results:
        assert stderr == b""
        assert stdout == (success if status == 0 else failure)
    assert {path.name for path in destination.iterdir()} == {"content.json", "refs.json"}
    assert (destination / "content.json").read_bytes() == canonical
    assert (destination / "refs.json").read_bytes() == refs
    after = _hashes(tmp_path)
    assert {key: after[key] for key in before} == before
    assert after.keys() == before.keys() | {"shared-output/content.json", "shared-output/refs.json"}
    assert not list(tmp_path.glob(".emt-*"))
