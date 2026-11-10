# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole policy selection before authority acquisition

"""Exercise policy shape, caller pairing and shared budgets through public verification."""

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest
from tests.domain.test_cli_evidence_sources import _inputs, _run, _source, _transport
from tests.domain.test_verification_report_sources import (
    _array,
    _bytes,
    _FileResolver,
    _mapping,
    _object,
    _optional_reference,
    _registry,
    _text,
)

from evidence_manifest_toolkit import (
    BlobRef,
    ConfigurationError,
    InputRefused,
    Limits,
    TrustContext,
    Utc,
    VerificationPolicy,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_POLICY_ID = "evidence_manifest_toolkit.authority_policy.v2"
_FORMAT_SHA256 = "649b5c03400bc362811467300e6acc05158e48eb4297e85449cb0c187d1f31e1"


def _successor_policy(reference: BlobRef) -> dict[str, object]:
    """Retain complete declaration shape without claiming native source qualification.

    Parameters
    ----------
    reference : BlobRef
        Actual original policy source, reused only as a declared reference. Its bytes
        are not asserted to be identity, validation, conditions or signature-rule sources.

    Returns
    -------
    dict
        All fourteen fields of a shape-valid unsigned policy. Wrong v1 caller pairing
        must refuse before any declared subordinate source can be acquired or accepted.
    """
    return {
        "schema_id": _POLICY_ID,
        "namespace": "EMT_AUTHORITY_SUCCESSOR_POLICY_V2",
        "profile_class": "unsigned_declared",
        "whole_legacy_artifact_policy_ref": dict(reference.to_mapping()),
        "authority_rule_ref": None,
        "root_grant_ref": None,
        "identity_rule_ref": dict(reference.to_mapping()),
        "validation_rule_ref": dict(reference.to_mapping()),
        "foreign_rule_ref": None,
        "independent_foreign_trust_ref": None,
        "minimum_identity_class": "declared_by_launcher_under_the_seat_account",
        "allowed_nonuse_classes": ["procedural_nonuse"],
        "whole_conditions_and_limitations_ref": dict(reference.to_mapping()),
        "signature_obligation_rule_ref": dict(reference.to_mapping()),
    }


@pytest.mark.parametrize("condition", ("class", "shape", "budget", "reference", "metadata"))
def test_whole_policy_pairing_refuses_before_authority_and_preserves_full_recovery(
    condition: str, tmp_path: Path
) -> None:
    """Refuse real whole source conflicts before any bootstrap or snapshot lookup.

    Parameters
    ----------
    condition : str
        Whole class, shape, exact reference, metadata or cumulative-byte conflict.
    tmp_path : Path
        Owned actual source file. The entire original corpus remains unchanged.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    bounds = _object(inputs["limits"])
    assert all(type(value) is int for value in bounds.values())
    limits = Limits(**cast(dict[str, int], bounds))
    local = _object(inputs["trust"])
    trust = TrustContext(
        BlobRef.from_mapping(_object(local["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(local["current_snapshot_ref"])),
        _text(local["accepted_sequence_floor"]),
        "current",
        Utc(local["evaluation_time"]),
        tuple(_bytes(member) for member in _array(local["control_envelopes"])),
        _optional_reference(local.get("archived_snapshot_ref")),
    )
    declared = _object(inputs["policy"])
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(declared["policy_ref"])),
        tuple(_text(member) for member in _array(declared["required_claim_ids"])),
        ("evidence",),
    )
    population: dict[str, Path] = {}
    originals: dict[Path, bytes] = {}
    for key, member in _object(inputs["resolver_input_population"]).items():
        row = _object(member)
        path = _FIXTURES / "objects" / _text(row["sha256"])
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
        assert len(raw) == row["byte_length"]
        population[key] = path
        originals[path] = raw
    for path in (_FIXTURES / "verify-current-whole-fixture.json", _FIXTURES / "source-pins.json"):
        originals[path] = path.read_bytes()
    content = _bytes(inputs["content_json"])
    envelopes = tuple(_bytes(member) for member in _array(inputs["envelopes"]))
    schema = _text(inputs["schema_id"])
    baseline = verify(
        content,
        schema_id=schema,
        envelopes=envelopes,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
        policy=policy,
        trust=trust,
    )
    assert _mapping(baseline) == source["expected_entire_VerificationReport"]
    value = _successor_policy(policy.policy_ref)
    if condition == "shape":
        value["allowed_nonuse_classes"] = ["made_up_nonuse_class"]
    if condition == "reference":
        value["identity_rule_ref"] = {
            **dict(policy.policy_ref.to_mapping()),
            "byte_length": policy.policy_ref.byte_length + "\n",
        }
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    path = tmp_path / "whole-declared-successor-policy.json"
    path.write_bytes(raw)
    reference = BlobRef(
        "sha256:" + hashlib.sha256(raw).hexdigest(),
        str(len(raw)),
        "application/json",
        "raw_bytes",
        "evidence_manifest_toolkit.authority_snapshot.v2"
        if condition == "metadata"
        else _POLICY_ID,
    )
    chosen = replace(policy, policy_ref=reference)
    if condition == "budget":
        unique = {entry.schema_ref.digest: entry.schema_bytes for entry in registry.entries}
        limits = replace(
            limits, max_total_reference_bytes=sum(map(len, unique.values())) + len(raw)
        )
    resolver = _FileResolver({reference.digest + "|raw_bytes": path})
    exception = InputRefused if condition == "budget" else ConfigurationError
    with pytest.raises(exception) as caught:
        verify(
            content,
            schema_id=schema,
            envelopes=envelopes,
            registry=registry,
            resolver=resolver,
            limits=limits,
            policy=chosen,
            trust=trust,
        )
    expected = {
        "code": "limit_exceeded" if condition == "budget" else "configuration_error",
        "subject_digest": "sha256:" + _FORMAT_SHA256 if condition == "budget" else reference.digest,
        "claim_id": None,
        "pointer": {
            "budget": "/policy_ref",
            "shape": "/allowed_nonuse_classes/0",
            "reference": "/identity_rule_ref",
            "metadata": "/policy_ref",
            "class": "/trust",
        }[condition],
        "detail": "Reference acquisition bound exceeded."
        if condition == "budget"
        else "Invalid local trust or policy configuration.",
    }
    assert asdict(caught.value.reason) == expected
    assert len(resolver.calls) == 1 and resolver.calls[0][0] == reference
    assert resolver.calls[0][1] >= len(raw)
    assert path.read_bytes() == raw
    recovered = verify(
        content,
        schema_id=schema,
        envelopes=envelopes,
        registry=registry,
        resolver=_FileResolver(population),
        limits=Limits(**cast(dict[str, int], bounds)),
        policy=policy,
        trust=trust,
    )
    assert _mapping(recovered) == source["expected_entire_VerificationReport"]
    assert all(path.read_bytes() == data for path, data in originals.items())


def test_whole_policy_class_refusal_has_native_cli_exit_and_no_report_then_recovers(
    tmp_path: Path,
) -> None:
    """Keep a class mismatch out of report publication and recover the full original transport.

    Parameters
    ----------
    tmp_path : Path
        Owned complete original caller/store copies and two fresh report destinations.
    """
    source = _source("verify-current-whole-fixture")
    arguments = _inputs(source, tmp_path)
    policy_path = tmp_path / "policy.json"
    original = policy_path.read_bytes()
    policy = _object(json.loads(original))
    value = _successor_policy(BlobRef.from_mapping(_object(policy["policy_ref"])))
    raw = _transport(value)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    (tmp_path / "objects" / digest.removeprefix("sha256:")).write_bytes(raw)
    policy["policy_ref"] = {
        "digest": digest,
        "byte_length": str(len(raw)),
        "media_type": "application/json",
        "digest_basis": "raw_bytes",
        "schema_id": _POLICY_ID,
    }
    policy_path.write_bytes(_transport(policy))
    refused_path = tmp_path / "refused-report.json"
    refusal = _run(arguments + ["--report", str(refused_path)], tmp_path)
    assert (refusal.returncode, refusal.stdout, refusal.stderr) == (
        4,
        _transport(
            {
                "operation": "verify",
                "reasons": [
                    {
                        "code": "configuration_error",
                        "subject_digest": digest,
                        "claim_id": None,
                        "pointer": "/trust",
                        "detail": "Invalid local trust or policy configuration.",
                    }
                ],
            }
        ),
        b"",
    )
    assert not refused_path.exists()
    policy_path.write_bytes(original)
    recovery_path = tmp_path / "original-recovery-report.json"
    recovered = _run(arguments + ["--report", str(recovery_path)], tmp_path)
    expected = _transport(source["expected_entire_VerificationReport"])
    assert (recovered.returncode, recovered.stdout, recovered.stderr) == (0, expected, b"")
    assert recovery_path.read_bytes() == expected and policy_path.read_bytes() == original


@pytest.mark.parametrize("field", ("required_claim_ids", "required_purposes"))
def test_original_whole_policy_scope_refusal_and_cli_recovery(field: str, tmp_path: Path) -> None:
    """Retain exact scope equality, native errors and full report recovery after extraction.

    Parameters
    ----------
    field : str
        Existing caller claim order or purpose population that conflicts with its whole source.
    tmp_path : Path
        Owned complete original inputs, real object store and new report destinations.
    """
    source = _source("verify-current-whole-fixture")
    arguments = _inputs(source, tmp_path)
    path = tmp_path / "policy.json"
    original = path.read_bytes()
    value = _object(json.loads(original))
    subject = _object(value["policy_ref"])["digest"]
    value[field] = (
        list(reversed(_array(value[field]))) if field == "required_claim_ids" else ["human_review"]
    )
    path.write_bytes(_transport(value))
    refused = tmp_path / "refused-scope-report.json"
    recovered = tmp_path / "complete-original-report.json"
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    environment.update(PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(tmp_path))
    expected_failure = _transport(
        {
            "operation": "verify",
            "reasons": [
                {
                    "code": "configuration_error",
                    "subject_digest": subject,
                    "claim_id": None,
                    "pointer": "/" + field,
                    "detail": "Invalid local trust or policy configuration.",
                }
            ],
        }
    )
    for report, status, expected in (
        (refused, 4, expected_failure),
        (recovered, 0, _transport(source["expected_entire_VerificationReport"])),
    ):
        if status == 0:
            path.write_bytes(original)
        actual = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "coverage",
                "run",
                "--branch",
                "--parallel-mode",
                "--source=evidence_manifest_toolkit._policy_selection,evidence_manifest_toolkit._verification_inputs,evidence_manifest_toolkit._successor_formats",
                "-m",
                "evidence_manifest_toolkit",
                *arguments,
                "--report",
                str(report),
            ],
            cwd=Path(__file__).resolve().parents[2] / "src",
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert (actual.returncode, actual.stdout, actual.stderr) == (status, expected, b"")
        assert report.read_bytes() == expected if status == 0 else not report.exists()
    assert path.read_bytes() == original
