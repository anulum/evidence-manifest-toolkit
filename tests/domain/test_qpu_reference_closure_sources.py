# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole QPU optional diagnostic source closure

"""Keep optional diagnostic sources separate from required full input closure."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from tests.domain.test_cli_evidence_sources import _source
from tests.domain.test_qpu_registry_sources import _construction_sources
from tests.domain.test_verification_report_sources import (
    _array,
    _bytes,
    _FileResolver,
    _mapping,
    _object,
    _text,
)

from evidence_manifest_toolkit import (
    BlobRef,
    InputRefused,
    Reason,
    ReferenceUnavailable,
    SealResult,
    seal,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_SCHEMA = "qpu_result_pack.verification.v1"


def _canonical(value: object) -> bytes:
    """Encode entire ASCII-only authored source values without a product codec shortcut."""
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    assert all(ord(character) < 128 for character in raw.decode("ascii"))
    return raw


def _reference(raw: bytes, schema_id: str | None = None) -> BlobRef:
    """Independently identify the complete unchanged source bytes and declared metadata."""
    return BlobRef(
        "sha256:" + hashlib.sha256(raw).hexdigest(),
        str(len(raw)),
        "application/json",
        "jcs_content" if schema_id is not None else "raw_bytes",
        schema_id,
    )


def _whole_report_sources(
    tmp_path: Path,
) -> tuple[dict[str, object], dict[str, Path], BlobRef, BlobRef]:
    """Construct every report field with whole original inputs and explicitly unevaluated gates.

    Parameters
    ----------
    tmp_path : Path
        Owned files for entire original input/report/inventory sources.

    Returns
    -------
    tuple
        All seventeen report fields, actual original file population and complete
        original TrustSnapshot and authored source Manifest references. This is unadmitted schema
        source data, not an evaluated QPU report or a scientific observation.
    """
    original = _source("verify-current-whole-fixture")
    inputs = _object(original["complete_library_inputs"])
    manifest_bytes = _bytes(inputs["content_json"])
    manifest = _object(json.loads(manifest_bytes))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }

    def retain(raw: bytes, schema_id: str | None = None) -> BlobRef:
        """Retain an entire source under its independently calculated actual byte identity."""
        reference = _reference(raw, schema_id)
        path = tmp_path / reference.digest[7:]
        path.write_bytes(raw)
        population[reference.digest + "|" + reference.digest_basis] = path
        return reference

    registry_source = (_FIXTURES.parent / "qpu-registry-source.json").read_bytes()
    registry_ref = retain(registry_source)
    declarations = _object(inputs["registry"])
    for member in _array(declarations["entries"]):
        entry = _object(member)
        schema_ref = BlobRef.from_mapping(_object(entry["schema_ref"]))
        raw_schema = _bytes(entry["schema_bytes"])
        assert schema_ref.digest == "sha256:" + hashlib.sha256(raw_schema).hexdigest()
        assert schema_ref.byte_length == str(len(raw_schema))
        path = tmp_path / schema_ref.digest[7:]
        path.write_bytes(raw_schema)
        population[schema_ref.digest + "|" + schema_ref.digest_basis] = path
    snapshot = BlobRef.from_mapping(_object(_object(inputs["trust"])["current_snapshot_ref"]))
    snapshot_bytes = population[snapshot.digest + "|" + snapshot.digest_basis].read_bytes()
    certificate_ref = BlobRef.from_mapping(
        _object(_array(_object(json.loads(snapshot_bytes))["group_certificate_refs"])[0])
    )
    manifest["payload_ref"] = dict(certificate_ref.to_mapping())
    declared_claims: list[dict[str, object]] = []
    for member in _array(manifest["claims"]):
        claim = _object(member)
        claim["scope"] = dict(_object(claim["scope"]), subject_digest=certificate_ref.digest)
        claim["statement"] = (
            "Complete original GroupCertificate source bytes; "
            "no QPU evaluation, runtime acceptance or scientific qualification."
        )
        declared_claims.append(claim)
    manifest["claims"] = declared_claims
    manifest["producer"] = dict(_object(manifest["producer"]), principal="Arcane Sapience")
    manifest_ref = retain(_canonical(manifest), "evidence_manifest_toolkit.manifest.v1")
    source_ref = retain((_FIXTURES / "verify-current-whole-fixture.json").read_bytes())
    report_ref = retain(_canonical(original["expected_entire_VerificationReport"]))
    inventory_ref = registry_ref
    snapshot = BlobRef.from_mapping(_object(_object(inputs["trust"])["current_snapshot_ref"]))
    entry = _object(manifest["producer"])
    producer = dict(entry, principal="Arcane Sapience")
    claims = [_text(_object(value)["claim_id"]) for value in _array(manifest["claims"])]
    report: dict[str, object] = {
        "schema_id": _SCHEMA,
        "subject_ref": manifest["payload_ref"],
        "manifest_ref": dict(manifest_ref.to_mapping()),
        "policy_ref": _object(inputs["policy"])["policy_ref"],
        "evaluation_inputs_ref": dict(source_ref.to_mapping()),
        "common_report_ref": dict(report_ref.to_mapping()),
        "evaluator": {
            "producer": producer,
            "source_ref": manifest["source_ref"],
            "environment_ref": manifest["environment_ref"],
        },
        "evaluation_time": _object(inputs["trust"])["evaluation_time"],
        "evaluation_mode": "historical",
        "evaluated_claim_ids": claims,
        "evaluated_job_ids": ["whole-source-construction-only"],
        "gates": {
            name: "not_evaluated"
            for name in (
                "structure",
                "integrity",
                "common_eligibility",
                "availability",
                "producer_authenticity",
                "provider_attestation",
                "result_custody",
                "derivation",
                "measurement_qualification",
                "calibration",
                "preregistration",
                "domain",
                "current_source",
            )
        },
        "current_eligibility": "not_evaluated",
        "source_observation": {
            "state": "not_evaluated",
            "mapping_ref": None,
            "source_subject_ref": None,
            "expected_digest": None,
            "observed_digest": None,
            "observation_ref": None,
            "boundary": "Whole author-input source construction; no QPU evaluation or admission.",
            "reason_code": None,
        },
        "quantity_results": [],
        "coverage": {
            "inventory_ref": dict(inventory_ref.to_mapping()),
            "case_records_ref": None,
            "required_count": "0",
            "evaluated_count": "0",
            "passed_count": "0",
            "refused_count": "0",
            "unavailable_count": "0",
        },
        "reasons": [
            {
                "code": "domain_not_evaluated",
                "subject_ref": dict(snapshot.to_mapping()),
                "claim_id": None,
                "quantity_id": None,
                "job_id": None,
                "pointer": None,
                "message_id": "whole-source-construction-without-domain-evaluation",
            }
        ],
    }
    assert set(report) == {
        "schema_id",
        "subject_ref",
        "manifest_ref",
        "policy_ref",
        "evaluation_inputs_ref",
        "common_report_ref",
        "evaluator",
        "evaluation_time",
        "evaluation_mode",
        "evaluated_claim_ids",
        "evaluated_job_ids",
        "gates",
        "current_eligibility",
        "source_observation",
        "quantity_results",
        "coverage",
        "reasons",
    }
    return report, population, snapshot, manifest_ref


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
def test_whole_qpu_optional_source_and_required_input_refusals_then_recovery(
    condition: str,
    tmp_path: Path,
) -> None:
    """Compare whole unsigned results and exact failures for the same optional/required source.

    Parameters
    ----------
    condition : str
        Actual missing source, present wrong bytes, whole malformed native source,
        unknown or conflicting metadata, or the entire matching original control.
    tmp_path : Path
        Actual bounded source files, without changing any original fixture.

    Notes
    -----
    All original77 registry entries and every report field are retained. Declared
    source roles and scope identifiers are unadmitted author data; no QPU result,
    domain report, native authority, Clock, signature or current trust is approved.
    """
    registry, limits, _ = _construction_sources()
    original_registry = _mapping(registry)
    report, population, snapshot, manifest_ref = _whole_report_sources(tmp_path)
    before = {path: path.read_bytes() for path in population.values()}
    original_snapshot = population[snapshot.digest + "|" + snapshot.digest_basis].read_bytes()
    snapshot_body = _object(json.loads(original_snapshot))
    descendant = BlobRef.from_mapping(_object(snapshot_body["registry_ref"]))
    selected = snapshot
    supplied = dict(population)
    if condition == "unavailable":
        del supplied[snapshot.digest + "|" + snapshot.digest_basis]
    elif condition == "wrong_bytes":
        path = tmp_path / "wrong-snapshot-source"
        path.write_bytes(b"{}")
        supplied[snapshot.digest + "|" + snapshot.digest_basis] = path
    elif condition == "invalid_subject":
        altered = dict(snapshot_body, sequence="not-a-decimal")
        raw = _canonical(altered)
        selected = _reference(raw, snapshot.schema_id)
        path = tmp_path / "whole-invalid-snapshot"
        path.write_bytes(raw)
        supplied[selected.digest + "|" + selected.digest_basis] = path
    elif condition == "unknown_schema":
        selected = replace(snapshot, schema_id="unregistered.control.source")
    elif condition == "metadata_conflict":
        selected = replace(manifest_ref, schema_id="evidence_manifest_toolkit.trust_snapshot.v1")
    else:
        assert condition == "matching"
    reason = _object(_array(report["reasons"])[0])
    report["reasons"] = [dict(reason, subject_ref=dict(selected.to_mapping()))]
    content = _canonical(report)
    resolver = _FileResolver(supplied)
    expected = SealResult(content, _reference(content, _SCHEMA), None)
    assert (
        seal(content, schema_id=_SCHEMA, registry=registry, resolver=resolver, limits=limits)
        == expected
    )
    assert not any(actual == descendant for actual, _ in resolver.calls)
    assert any(actual == selected for actual, _ in resolver.calls) == (
        condition != "metadata_conflict"
    )
    required = dict(report, evaluation_inputs_ref=dict(selected.to_mapping()))
    required_bytes = _canonical(required)
    required_ref = _reference(required_bytes, _SCHEMA)
    required_resolver = _FileResolver(supplied)
    if condition == "matching":
        assert seal(
            required_bytes,
            schema_id=_SCHEMA,
            registry=registry,
            resolver=required_resolver,
            limits=limits,
        ) == SealResult(required_bytes, required_ref, None)
        assert any(actual == descendant for actual, _ in required_resolver.calls)
    elif condition == "unavailable":
        with pytest.raises(ReferenceUnavailable) as missing:
            seal(
                required_bytes,
                schema_id=_SCHEMA,
                registry=registry,
                resolver=required_resolver,
                limits=limits,
            )
        assert missing.value.reference == selected
    else:
        with pytest.raises(InputRefused) as caught:
            seal(
                required_bytes,
                schema_id=_SCHEMA,
                registry=registry,
                resolver=required_resolver,
                limits=limits,
            )
        if condition == "invalid_subject":
            expected_reason = Reason(
                "invalid_schema",
                selected.digest,
                None,
                "/sequence",
                "Input violates its selected schema.",
            )
        else:
            code, detail = {
                "wrong_bytes": ("reference_mismatch", "Reference byte identity does not match."),
                "unknown_schema": ("unknown_schema", "Selected schema is not known."),
                "metadata_conflict": ("invalid_schema", "Reference metadata conflicts."),
            }[condition]
            expected_reason = Reason(
                code, required_ref.digest, None, "/evaluation_inputs_ref", detail
            )
        assert caught.value.reason == expected_reason
    recovery = dict(report, reasons=[dict(reason, subject_ref=dict(snapshot.to_mapping()))])
    recovered_bytes = _canonical(recovery)
    assert seal(
        recovered_bytes,
        schema_id=_SCHEMA,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
    ) == SealResult(recovered_bytes, _reference(recovered_bytes, _SCHEMA), None)
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert _mapping(registry) == original_registry
