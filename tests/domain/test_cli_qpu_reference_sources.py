# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole QPU source process and exclusive seal publication

"""Exercise complete QPU source closure across the actual offline process/file boundary."""

import base64
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from coverage import Coverage
from tests.domain.test_cli_evidence_sources import _collision, _hashes
from tests.domain.test_qpu_reference_closure_sources import (
    _canonical,
    _reference,
    _whole_report_sources,
)
from tests.domain.test_qpu_registry_sources import _construction_sources
from tests.domain.test_verification_report_sources import _array, _mapping, _object

_REPOSITORY = Path(__file__).resolve().parents[2]
_SCHEMA = "qpu_result_pack.verification.v1"


def _run_seal(arguments: list[str], directory: Path) -> subprocess.CompletedProcess[bytes]:
    """Invoke the genuine module in a traced child and retain its complete process result.

    Parameters
    ----------
    arguments : list of str
        Entire explicit original seal command and caller source/publication paths.
    directory : Path
        Owned process temp and immutable command-result journal. The child's trace joins
        the active coverage run, or without one a sibling directory outside this one.

    Returns
    -------
    subprocess.CompletedProcess
        Actual native exit/stdout/stderr after the child has terminated.
    """
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    active = Coverage.current()
    fallback = directory.with_name(directory.name + "-child-coverage")
    if active is None:
        fallback.mkdir(exist_ok=True)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1",
        TMPDIR=str(directory),
        TMP=str(directory),
        TEMP=str(directory),
        COVERAGE_FILE=(
            os.path.abspath(active.config.data_file)
            if active is not None
            else str(fallback / "native-process-coverage")
        ),
    )
    argv = [
        sys.executable,
        "-B",
        "-m",
        "coverage",
        "run",
        "--branch",
        "--parallel-mode",
        "--rcfile",
        str(_REPOSITORY / "pyproject.toml"),
        "--source=evidence_manifest_toolkit._closure,evidence_manifest_toolkit._cli,"
        "evidence_manifest_toolkit._cli_operations,evidence_manifest_toolkit._directory_publication",
        "-m",
        "evidence_manifest_toolkit",
        *arguments,
    ]
    actual = subprocess.run(
        argv,
        cwd=_REPOSITORY / "src",
        env=environment,
        capture_output=True,
        timeout=300,
        check=False,
    )
    with (directory / "native-command-observations.jsonl").open("a") as journal:
        journal.write(
            json.dumps(
                {
                    "argv": argv,
                    "returncode": actual.returncode,
                    "stdout_base64url": base64.urlsafe_b64encode(actual.stdout).decode("ascii"),
                    "stderr_base64url": base64.urlsafe_b64encode(actual.stderr).decode("ascii"),
                },
                sort_keys=True,
            )
            + "\n"
        )
    return actual


def _assert_complete_publication(
    actual: subprocess.CompletedProcess[bytes], content: bytes, destination: Path
) -> None:
    """Compare every transport field and every complete atomically published output byte."""
    reference = dict(_reference(content, _SCHEMA).to_mapping())
    assert (actual.returncode, actual.stdout, actual.stderr) == (
        0,
        _canonical(
            {
                "canonical_content": {
                    "content_ref": reference,
                    "output_file": str(destination / "content.json"),
                },
                "content_ref": reference,
                "envelope_json": None,
            }
        ),
        b"",
    )
    assert {path.name for path in destination.iterdir()} == {"content.json", "refs.json"}
    assert (destination / "content.json").read_bytes() == content
    assert (destination / "refs.json").read_bytes() == _canonical({"content_ref": reference})


def _materialize_store(population: dict[str, Path], directory: Path) -> None:
    """Preserve full physical source bytes while collapsing only actual equal digest aliases."""
    directory.mkdir()
    selected: dict[str, bytes] = {}
    for key, path in population.items():
        digest, basis = key.split("|", 1)
        assert basis in {"raw_bytes", "jcs_content"}
        raw = path.read_bytes()
        if digest in selected:
            assert selected[digest] == raw
        selected[digest] = raw
    for digest, raw in selected.items():
        (directory / digest.removeprefix("sha256:")).write_bytes(raw)


@pytest.mark.parametrize(
    "condition",
    (
        "unavailable",
        "wrong_bytes",
        "invalid_subject",
        "unknown_schema",
        "metadata_conflict",
        "matching",
    ),
)
def test_whole_qpu_optional_sources_real_seal_process_and_required_output_refusals(
    condition: str, tmp_path: Path
) -> None:
    """Preserve full constructor results, exact refusals, exclusive publication and fresh recovery.

    Parameters
    ----------
    condition : str
        Entire unavailable/wrong/invalid/unknown/conflicting/matching diagnostic source.
    tmp_path : Path
        Actual original source files, two immutable flat stores, complete caller
        configuration and fresh exclusive output destinations.

    Notes
    -----
    All seventeen report fields and all77caller entries stay explicit. These are
    unadmitted source declarations; no QPU/domain-valid report, quantum execution,
    signer, Clock, operational trust or scientific qualification is asserted.
    """
    sources = tmp_path / "source-inputs"
    sources.mkdir()
    registry, limits, _ = _construction_sources()
    registry_value = _mapping(registry)
    report, population, snapshot, manifest_ref = _whole_report_sources(sources)
    original = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in population.values()}
    snapshot_body = _object(json.loads(population[snapshot.digest + "|jcs_content"].read_bytes()))
    supplied = dict(population)
    selected = snapshot
    if condition == "unavailable":
        supplied = {
            key: path for key, path in supplied.items() if key.split("|", 1)[0] != snapshot.digest
        }
    elif condition == "wrong_bytes":
        wrong = sources / "actual-wrong-snapshot"
        wrong.write_bytes(b"{}")
        supplied = {
            key: wrong if key.split("|", 1)[0] == snapshot.digest else path
            for key, path in supplied.items()
        }
    elif condition == "invalid_subject":
        raw = _canonical(dict(snapshot_body, sequence="not-a-decimal"))
        selected = _reference(raw, snapshot.schema_id)
        path = sources / "complete-invalid-snapshot"
        path.write_bytes(raw)
        supplied[selected.digest + "|jcs_content"] = path
    elif condition == "unknown_schema":
        selected = replace(snapshot, schema_id="unregistered.control.source")
    elif condition == "metadata_conflict":
        selected = replace(manifest_ref, schema_id="evidence_manifest_toolkit.trust_snapshot.v1")
    else:
        assert condition == "matching"
    reason = _object(_array(report["reasons"])[0])
    report["reasons"] = [dict(reason, subject_ref=dict(selected.to_mapping()))]
    optional = _canonical(report)
    required = _canonical(dict(report, evaluation_inputs_ref=dict(selected.to_mapping())))
    recovery = _canonical(
        dict(report, reasons=[dict(reason, subject_ref=dict(snapshot.to_mapping()))])
    )
    objects = tmp_path / "fault-source-store"
    recovery_objects = tmp_path / "complete-recovery-store"
    _materialize_store(supplied, objects)
    _materialize_store(population, recovery_objects)
    inputs = {"optional": optional, "required": required, "recovery": recovery}
    for name, raw in inputs.items():
        (tmp_path / (name + ".json")).write_bytes(raw)
    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(_canonical(registry_value))
    limits_path = tmp_path / "limits.json"
    limits_path.write_bytes(_canonical(asdict(limits)))

    def arguments(name: str, store: Path, output: Path) -> list[str]:
        """Select only complete original explicit caller files for the actual seal command."""
        return [
            "seal",
            "--content",
            str(tmp_path / (name + ".json")),
            "--schema-id",
            _SCHEMA,
            "--registry",
            str(registry_path),
            "--limits",
            str(limits_path),
            "--objects",
            str(store),
            "--output",
            str(output),
        ]

    before = _hashes(tmp_path)
    destination = tmp_path / "optional-output"
    first = _run_seal(arguments("optional", objects, destination), tmp_path)
    _assert_complete_publication(first, optional, destination)
    identity = destination.stat()
    collision = _run_seal(arguments("optional", objects, destination), tmp_path)
    assert (collision.returncode, collision.stdout, collision.stderr) == (
        3,
        _collision("seal"),
        b"",
    )
    assert (destination / "content.json").read_bytes() == optional
    reference = dict(_reference(optional, _SCHEMA).to_mapping())
    assert (destination / "refs.json").read_bytes() == _canonical({"content_ref": reference})
    retained = destination.stat()
    assert (retained.st_dev, retained.st_ino) == (identity.st_dev, identity.st_ino)
    required_output = tmp_path / "required-output"
    actual = _run_seal(arguments("required", objects, required_output), tmp_path)
    if condition == "matching":
        _assert_complete_publication(actual, required, required_output)
    else:
        if condition == "unavailable":
            expected_reason: dict[str, object] = {
                "code": "reference_unavailable",
                "subject_digest": None,
                "claim_id": None,
                "pointer": None,
                "detail": "Required reference unavailable.",
            }
        elif condition == "invalid_subject":
            expected_reason = {
                "code": "invalid_schema",
                "subject_digest": selected.digest,
                "claim_id": None,
                "pointer": "/sequence",
                "detail": "Input violates its selected schema.",
            }
        else:
            code, detail = {
                "wrong_bytes": ("reference_mismatch", "Reference byte identity does not match."),
                "unknown_schema": ("unknown_schema", "Selected schema is not known."),
                "metadata_conflict": ("invalid_schema", "Reference metadata conflicts."),
            }[condition]
            expected_reason = {
                "code": code,
                "subject_digest": _reference(required, _SCHEMA).digest,
                "claim_id": None,
                "pointer": "/evaluation_inputs_ref",
                "detail": detail,
            }
        assert (actual.returncode, actual.stdout, actual.stderr) == (
            3 if condition == "unavailable" else 2,
            _canonical({"operation": "seal", "reasons": [expected_reason]}),
            b"",
        )
        assert not required_output.exists()
    recovered = tmp_path / "recovery-output"
    _assert_complete_publication(
        _run_seal(arguments("recovery", recovery_objects, recovered), tmp_path), recovery, recovered
    )
    after = _hashes(tmp_path)
    assert {key: after[key] for key in before} == before
    outputs = {"optional-output", "recovery-output"}
    if condition == "matching":
        outputs.add("required-output")
    assert set(after) == set(before) | {"native-command-observations.jsonl"} | {
        directory + "/" + name for directory in outputs for name in ("content.json", "refs.json")
    }
    observations = (tmp_path / "native-command-observations.jsonl").read_text().splitlines()
    assert len(observations) == 4
    assert not list(tmp_path.glob(".emt-*"))
    assert all(
        hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in original.items()
    )
    assert _mapping(registry) == registry_value
