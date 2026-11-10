# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole public reference read budget boundaries

"""Check cumulative read bounds through original whole public verification and real files."""

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest
from tests.domain.test_signature_provider_sources import _original
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
    InputRefused,
    Limits,
    TrustContext,
    Utc,
    VerificationPolicy,
    seal,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"


@pytest.mark.parametrize("remaining", (0, 1, 1251, 1252))
def test_remaining_unique_byte_budget_precedes_actual_policy_read_and_full_recovery(
    remaining: int,
) -> None:
    """Enforce the remaining allowance before reading the original policy source.

    Parameters
    ----------
    remaining : int
        Zero, one byte, one below or exactly the original1252-byte policy source.

    Notes
    -----
    The original complete current input, all14 registry fields and full15-field
    baseline/recovery report are retained. Numeric boundary variants derive from
    actual unique static schema bytes. A real file Resolver records public read
    caps and uses those caps before allocation; no private product helper is called.
    These source comparisons do not independently qualify the fixture or provider.
    """
    case_path = _FIXTURES / "verify-current-whole-fixture.json"
    raw = case_path.read_bytes()
    pins = _array(
        _object(json.loads((_FIXTURES / "source-pins.json").read_bytes()))["original_cases"]
    )
    pin = next(
        _object(row) for row in pins if _object(row)["case_id"] == "verify-current-whole-fixture"
    )
    assert hashlib.sha256(raw).hexdigest() == pin["source_sha256"]
    source = _object(json.loads(raw))
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    population: dict[str, Path] = {}
    for key, value in _object(inputs["resolver_input_population"]).items():
        record = _object(value)
        path = _FIXTURES / "objects" / _text(record["sha256"])
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        assert len(data) == record["byte_length"]
        population[key] = path
    before = {path: path.read_bytes() for path in set(population.values()) | {case_path}}
    bounds = _object(inputs["limits"])
    assert all(type(value) is int for value in bounds.values())
    limits = Limits(**cast(dict[str, int], bounds))
    local = _object(inputs["trust"])
    assert local["evaluation_mode"] == "current"
    trust = TrustContext(
        BlobRef.from_mapping(_object(local["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(local["current_snapshot_ref"])),
        _text(local["accepted_sequence_floor"]),
        "current",
        Utc(local["evaluation_time"]),
        tuple(_bytes(value) for value in _array(local["control_envelopes"])),
        _optional_reference(local.get("archived_snapshot_ref")),
    )
    declaration = _object(inputs["policy"])
    assert declaration["required_purposes"] == ["evidence"]
    assert declaration["required_reference_paths"] == []
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(declaration["policy_ref"])),
        tuple(_text(value) for value in _array(declaration["required_claim_ids"])),
        ("evidence",),
    )
    assert _mapping(registry) == inputs["registry"] and _mapping(policy) == declaration
    envelopes = tuple(_bytes(value) for value in _array(inputs["envelopes"]))
    content = _bytes(inputs["content_json"])
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
    unique_schemas = {
        (
            entry.schema_ref.digest,
            entry.schema_ref.digest_basis,
            entry.schema_ref.byte_length,
        ): entry.schema_bytes
        for entry in registry.entries
    }
    static_bytes = sum(len(data) for data in unique_schemas.values())
    limited = replace(limits, max_total_reference_bytes=static_bytes + remaining)
    resolver = _FileResolver(population)
    with pytest.raises(InputRefused) as caught:
        verify(
            content,
            schema_id=schema,
            envelopes=envelopes,
            registry=registry,
            resolver=resolver,
            limits=limited,
            policy=policy,
            trust=trust,
        )
    if remaining == 0:
        assert resolver.calls == []
        assert asdict(caught.value.reason) == {
            "code": "limit_exceeded",
            "subject_digest": policy.policy_ref.digest,
            "claim_id": None,
            "pointer": "/policy_ref",
            "detail": "Reference acquisition bound exceeded.",
        }
    elif remaining < 1252:
        assert resolver.calls == [(policy.policy_ref, remaining)]
        assert asdict(caught.value.reason) == {
            "code": "limit_exceeded",
            "subject_digest": None,
            "claim_id": None,
            "pointer": None,
            "detail": "Reference acquisition bound exceeded.",
        }
    else:
        assert resolver.calls == [(policy.policy_ref, remaining)]
        assert asdict(caught.value.reason) == {
            "code": "limit_exceeded",
            "subject_digest": trust.bootstrap_policy_ref.digest,
            "claim_id": None,
            "pointer": "/trust/bootstrap_policy_ref",
            "detail": "Reference acquisition bound exceeded.",
        }
    recovered = verify(
        content,
        schema_id=schema,
        envelopes=envelopes,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
        policy=policy,
        trust=trust,
    )
    assert _mapping(recovered) == source["expected_entire_VerificationReport"]
    assert all(path.read_bytes() == original for path, original in before.items())


def test_native_cli_exhaustion_precedes_unreadable_policy_and_whole_recovery(
    tmp_path: Path,
) -> None:
    """Distinguish pre-read exhaustion from actual store I/O failure and restore the whole report.

    Parameters
    ----------
    tmp_path : Path
        Owned copies of complete original caller inputs, store and fresh output destinations.

    Notes
    -----
    Runs require the supported unprivileged POSIX file-permission boundary.
    Original objects remain unchanged. Only the owned limits copy and policy
    copy's permissions vary, then return to their original state. Genuine source
    CLI outcomes are2 for pre-read exhaustion,3 for actual unreadable storage,
    and0 for complete original recovery. No import interception or private
    production helper supplies the I/O observation.
    """
    assert os.geteuid() != 0
    packet = _object(
        json.loads(_original("4d6365dc18f8a55f7b28e25105750d7229f83baf7a8be48c0ed840f8fd7cb0c1"))
    )
    rows = _array(packet["cases"])
    selected = next(
        _object(row) for row in rows if _object(row)["case_id"] == "verify-missing-local-provider"
    )
    method = _object(
        json.loads(_original("6b428b552cbb27a4c17d2bf9429a3996409c91f2f57a4d1c006ce7cb62d81473"))
    )
    bindings = _object(selected["exact_input_file_bindings"])
    stores = _array(selected["complete_offline_object_store_bindings"])
    originals: dict[Path, bytes] = {}
    for name, value in list(bindings.items()) + [
        (_text(_object(row)["future_relative_path"]), _object(row)["exact_existing_source_bytes"])
        for row in stores
    ]:
        record = _object(value)
        raw = _original(_text(record["sha256"]))
        assert len(raw) == record["byte_length"]
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        originals[path] = raw
    (tmp_path / "out").mkdir()
    limits_path = tmp_path / "configs/limits.json"
    original_limits = limits_path.read_bytes()
    registry = _registry(json.loads((tmp_path / "configs/registry.json").read_bytes()))
    unique = {
        (e.schema_ref.digest, e.schema_ref.digest_basis, e.schema_ref.byte_length): e.schema_bytes
        for e in registry.entries
    }
    limits_value = _object(json.loads(original_limits))
    limits_value["max_total_reference_bytes"] = sum(len(data) for data in unique.values())
    limits_path.write_text(json.dumps(limits_value))
    policy = _object(json.loads((tmp_path / "configs/policy.json").read_bytes()))
    reference = BlobRef.from_mapping(_object(policy["policy_ref"]))
    target = tmp_path / "objects" / reference.digest[7:]
    original_mode = target.stat().st_mode & 0o777
    arguments = [_text(value) for value in _array(selected["full_argv"])[1:]]
    for index, token in enumerate(arguments):
        if token in {
            "--content",
            "--registry",
            "--objects",
            "--limits",
            "--policy",
            "--trust",
            "--report",
            "--signature",
        }:
            arguments[index + 1] = str(tmp_path / arguments[index + 1])
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(tmp_path), TMP=str(tmp_path), TEMP=str(tmp_path)
    )
    target.chmod(0)
    try:
        with pytest.raises(PermissionError):
            target.read_bytes()
        exhausted = subprocess.run(
            [sys.executable, "-B", "-m", "evidence_manifest_toolkit", *arguments],
            cwd=Path(__file__).resolve().parents[2] / "src",
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert (exhausted.returncode, exhausted.stderr) == (2, b"")
        assert json.loads(exhausted.stdout) == {
            "operation": "verify",
            "reasons": [
                {
                    "code": "limit_exceeded",
                    "subject_digest": reference.digest,
                    "claim_id": None,
                    "pointer": "/policy_ref",
                    "detail": "Reference acquisition bound exceeded.",
                }
            ],
        }
        assert not list((tmp_path / "out").iterdir())
        limits_path.write_bytes(original_limits)
        unreadable = subprocess.run(
            [sys.executable, "-B", "-m", "evidence_manifest_toolkit", *arguments],
            cwd=Path(__file__).resolve().parents[2] / "src",
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert (unreadable.returncode, unreadable.stderr) == (3, b"")
        assert json.loads(unreadable.stdout) == {
            "operation": "verify",
            "reasons": [
                {
                    "code": "storage_error",
                    "subject_digest": None,
                    "claim_id": None,
                    "pointer": None,
                    "detail": "The requested local storage operation failed.",
                }
            ],
        }
        assert not list((tmp_path / "out").iterdir())
    finally:
        target.chmod(original_mode)
        limits_path.write_bytes(original_limits)
    arguments[arguments.index("--report") + 1] = str(tmp_path / "out/recovered-budget.json")
    recovered = subprocess.run(
        [sys.executable, "-B", "-m", "evidence_manifest_toolkit", *arguments],
        cwd=Path(__file__).resolve().parents[2] / "src",
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert (recovered.returncode, recovered.stderr) == (0, b"")
    assert json.loads(recovered.stdout) == method["expected_entire_recovery_VerificationReport"]
    assert (tmp_path / "out/recovered-budget.json").read_bytes() == recovered.stdout
    assert not (tmp_path / "out/report.json").exists()
    assert target.stat().st_mode & 0o777 == original_mode
    assert all(path.read_bytes() == raw for path, raw in originals.items())


@pytest.mark.parametrize("metadata", ("omitted_schema", "conflicting_media"))
def test_repeated_content_reference_metadata_and_complete_unsigned_recovery(
    metadata: str,
) -> None:
    """Check cached reference metadata through complete unsigned public construction.

    Parameters
    ----------
    metadata : str
        Omit a repeated reference's schema assertion or contradict its media declaration.

    Notes
    -----
    The complete original manifest, registry and real file population remain
    present. Construction does not establish scientific or current acceptance.
    """
    path = _FIXTURES / "seal-unsigned-whole-fixture.json"
    raw = path.read_bytes()
    packet = _object(json.loads(raw))
    inputs = _object(packet["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    schema_id = _text(inputs["schema_id"])
    original = _bytes(inputs["content_json"])
    population: dict[str, Path] = {}
    for key, member in _object(inputs["resolver_input_population"]).items():
        descriptor = _object(member)
        object_path = _FIXTURES / "objects" / _text(descriptor["sha256"])
        object_bytes = object_path.read_bytes()
        assert len(object_bytes) == descriptor["byte_length"]
        assert hashlib.sha256(object_bytes).hexdigest() == descriptor["sha256"]
        population[key] = object_path
    before = {source: source.read_bytes() for source in set(population.values()) | {path}}
    document = _object(json.loads(original))
    claims = _array(document["claims"])
    assert len(claims) == 2
    second = _object(claims[1])
    if metadata == "omitted_schema":
        repeated = dict(_object(document["payload_ref"]))
        assert "schema_id" in repeated
        repeated.pop("schema_id")
    else:
        assert metadata == "conflicting_media"
        repeated = dict(_object(_array(second["source_refs"])[0]))
        assert repeated["media_type"] == "text/plain"
        repeated["media_type"] = "application/octet-stream"
    second["source_refs"] = [repeated]
    document["claims"] = [_object(claims[0]), second]
    content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    resolver = _FileResolver(population)
    if metadata == "conflicting_media":
        with pytest.raises(InputRefused) as caught:
            seal(content, schema_id=schema_id, registry=registry, resolver=resolver, limits=limits)
        assert asdict(caught.value.reason) == {
            "code": "invalid_schema",
            "subject_digest": digest,
            "claim_id": None,
            "pointer": "/claims/1/source_refs/0",
            "detail": "Reference metadata conflicts.",
        }
    else:
        result = seal(
            content, schema_id=schema_id, registry=registry, resolver=resolver, limits=limits
        )
        assert result.canonical_content == content
        assert asdict(result.content_ref) == {
            "digest": digest,
            "byte_length": str(len(content)),
            "media_type": "application/json",
            "digest_basis": "jcs_content",
            "schema_id": schema_id,
        }
        assert result.envelope_json is None
    identities = []
    for reference, _maximum in resolver.calls:
        assert isinstance(reference, BlobRef)
        identities.append((reference.digest, reference.digest_basis, reference.byte_length))
    assert len(identities) == len(set(identities))
    recovered = seal(
        original,
        schema_id=schema_id,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
    )
    assert _mapping(recovered) == packet["expected_entire_SealResult"]
    assert before == {source: source.read_bytes() for source in before}


@pytest.mark.parametrize("bound", ("count", "bytes"))
def test_unsigned_registry_budget_refusal_precedes_resolver_and_complete_recovery(
    bound: str,
) -> None:
    """Refuse an exhausted static registry bound before reading any selected content object.

    Parameters
    ----------
    bound : str
        Select the unique reference count or cumulative actual schema-byte bound.
        The entire original registry and content population remain selected.
    """
    path = _FIXTURES / "seal-unsigned-whole-fixture.json"
    packet = _object(json.loads(path.read_bytes()))
    inputs = _object(packet["complete_library_inputs"])
    assert inputs["signing"] is None and inputs["signer"] is None and inputs["trust"] is None
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    population = {
        key: _FIXTURES / "objects" / _text(_object(value)["sha256"])
        for key, value in _object(inputs["resolver_input_population"]).items()
    }
    before = {source: source.read_bytes() for source in set(population.values()) | {path}}
    original = _bytes(inputs["content_json"])
    schema_id = _text(inputs["schema_id"])
    assert len(registry.entries) > 1
    assert registry.entries[0].schema_ref.digest != registry.entries[1].schema_ref.digest
    if bound == "count":
        limited = replace(limits, max_reference_count=1)
        pointer = "/registry/entries/1/schema_bytes"
        detail = "Reference count bound exceeded."
    else:
        assert bound == "bytes" and len(registry.entries[0].schema_bytes) > 1
        limited = replace(limits, max_total_reference_bytes=1)
        pointer = "/registry/entries/0/schema_bytes"
        detail = "Reference acquisition bound exceeded."
    resolver = _FileResolver(population)
    with pytest.raises(InputRefused) as caught:
        seal(original, schema_id=schema_id, registry=registry, resolver=resolver, limits=limited)
    assert asdict(caught.value.reason) == {
        "code": "limit_exceeded",
        "subject_digest": registry.snapshot_ref.digest,
        "claim_id": None,
        "pointer": pointer,
        "detail": detail,
    }
    assert resolver.calls == []
    recovered = seal(
        original,
        schema_id=schema_id,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
    )
    assert _mapping(recovered) == packet["expected_entire_SealResult"]
    assert before == {source: source.read_bytes() for source in before}


def test_missing_control_exhaustion_precedes_digest_read_and_full_recovery() -> None:
    """Refuse an exhausted digest-only read after the original full-reference source is absent.

    Notes
    -----
    The complete original current fixture, all fourteen registry fields and both
    entire fifteen-field baseline/recovery reports are retained. Actual bounded
    file reads determine the unique acquired source bytes; only the selected
    certificate lookup and cumulative allowance vary. No original file changes,
    Signer, Clock or operational qualification is supplied by this comparison.
    """
    case_path = _FIXTURES / "verify-current-whole-fixture.json"
    raw = case_path.read_bytes()
    pins = _array(
        _object(json.loads((_FIXTURES / "source-pins.json").read_bytes()))["original_cases"]
    )
    pin = next(
        _object(row) for row in pins if _object(row)["case_id"] == "verify-current-whole-fixture"
    )
    assert hashlib.sha256(raw).hexdigest() == pin["source_sha256"]
    source = _object(json.loads(raw))
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    population: dict[str, Path] = {}
    for key, value in _object(inputs["resolver_input_population"]).items():
        record = _object(value)
        path = _FIXTURES / "objects" / _text(record["sha256"])
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        assert len(data) == record["byte_length"]
        population[key] = path
    before = {path: path.read_bytes() for path in set(population.values()) | {case_path}}
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    local = _object(inputs["trust"])
    assert local["evaluation_mode"] == "current"
    trust = TrustContext(
        BlobRef.from_mapping(_object(local["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(local["current_snapshot_ref"])),
        _text(local["accepted_sequence_floor"]),
        "current",
        Utc(local["evaluation_time"]),
        tuple(_bytes(value) for value in _array(local["control_envelopes"])),
        _optional_reference(local.get("archived_snapshot_ref")),
    )
    declaration = _object(inputs["policy"])
    assert declaration["required_reference_paths"] == []
    assert declaration["required_purposes"] == ["evidence"]
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(declaration["policy_ref"])),
        tuple(_text(value) for value in _array(declaration["required_claim_ids"])),
        ("evidence",),
    )
    assert _mapping(registry) == inputs["registry"] and _mapping(policy) == declaration
    content = _bytes(inputs["content_json"])
    envelopes = tuple(_bytes(value) for value in _array(inputs["envelopes"]))
    schema = _text(inputs["schema_id"])
    resolver = _FileResolver(population)
    baseline = verify(
        content,
        schema_id=schema,
        envelopes=envelopes,
        registry=registry,
        resolver=resolver,
        limits=limits,
        policy=policy,
        trust=trust,
    )
    expected = _object(source["expected_entire_VerificationReport"])
    assert _mapping(baseline) == expected
    observation = next(
        _object(row)
        for row in _array(expected["reference_observations"])
        if _object(row)["path_id"] == "typed-control:group_certificate_digest"
    )
    certificate = BlobRef.from_mapping(_object(observation["reference"]))
    charged: dict[tuple[str, str, str], bytes] = {
        (
            entry.schema_ref.digest,
            entry.schema_ref.digest_basis,
            entry.schema_ref.byte_length,
        ): entry.schema_bytes
        for entry in registry.entries
    }
    for reference, maximum in resolver.calls:
        assert isinstance(reference, BlobRef) and maximum > 0
        identity = reference.digest, reference.digest_basis, reference.byte_length
        charged[identity] = population[reference.digest + "|" + reference.digest_basis].read_bytes()
    identity = certificate.digest, certificate.digest_basis, certificate.byte_length
    assert identity in charged
    total = len(content) + sum(len(data) for key, data in charged.items() if key != identity)
    limited = replace(limits, max_total_reference_bytes=total)
    selected = dict(population)
    selected.pop(certificate.digest + "|" + certificate.digest_basis)
    assert len(selected) == len(population) - 1
    missing = _FileResolver(selected)
    with pytest.raises(InputRefused) as caught:
        verify(
            content,
            schema_id=schema,
            envelopes=envelopes,
            registry=registry,
            resolver=missing,
            limits=limited,
            policy=policy,
            trust=trust,
        )
    assert asdict(caught.value.reason) == {
        "code": "limit_exceeded",
        "subject_digest": observation["subject_digest"],
        "claim_id": None,
        "pointer": "/group_certificate_digest",
        "detail": "Reference acquisition bound exceeded.",
    }
    assert all(isinstance(reference, BlobRef) for reference, _ in missing.calls)
    recovered = verify(
        content,
        schema_id=schema,
        envelopes=envelopes,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
        policy=policy,
        trust=trust,
    )
    assert _mapping(recovered) == expected
    assert all(path.read_bytes() == original for path, original in before.items())


def test_conflicting_control_source_bytes_refuse_before_choice_and_full_recovery(
    tmp_path: Path,
) -> None:
    """Refuse ambiguous retained control bytes rather than silently choosing a source.

    Parameters
    ----------
    tmp_path : Path
        Owned real file retaining a whitespace variant of the complete original certificate.

    Notes
    -----
    Both physical sources have the original canonical digest. One complete edge
    deliberately declares the raw length instead of its canonical length. The
    whole manifest retains every original field while adding both references;
    its original receipt is unchanged and is not asserted to match that variant.
    The entire original baseline and recovery reports remain the independent
    fifteen-field oracle. No operational root, Signer or Clock is fabricated.
    """
    case_path = _FIXTURES / "verify-current-whole-fixture.json"
    raw = case_path.read_bytes()
    pins = _array(
        _object(json.loads((_FIXTURES / "source-pins.json").read_bytes()))["original_cases"]
    )
    pin = next(
        _object(row) for row in pins if _object(row)["case_id"] == "verify-current-whole-fixture"
    )
    assert hashlib.sha256(raw).hexdigest() == pin["source_sha256"]
    source = _object(json.loads(raw))
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    population: dict[str, Path] = {}
    for key, value in _object(inputs["resolver_input_population"]).items():
        record = _object(value)
        path = _FIXTURES / "objects" / _text(record["sha256"])
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        assert len(data) == record["byte_length"]
        population[key] = path
    before = {path: path.read_bytes() for path in set(population.values()) | {case_path}}
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    local = _object(inputs["trust"])
    assert local["evaluation_mode"] == "current"
    trust = TrustContext(
        BlobRef.from_mapping(_object(local["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(local["current_snapshot_ref"])),
        _text(local["accepted_sequence_floor"]),
        "current",
        Utc(local["evaluation_time"]),
        tuple(_bytes(value) for value in _array(local["control_envelopes"])),
        _optional_reference(local.get("archived_snapshot_ref")),
    )
    declaration = _object(inputs["policy"])
    assert declaration["required_reference_paths"] == []
    assert declaration["required_purposes"] == ["evidence"]
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(declaration["policy_ref"])),
        tuple(_text(value) for value in _array(declaration["required_claim_ids"])),
        ("evidence",),
    )
    assert _mapping(registry) == inputs["registry"] and _mapping(policy) == declaration
    content = _bytes(inputs["content_json"])
    envelopes = tuple(_bytes(value) for value in _array(inputs["envelopes"]))
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
    expected = _object(source["expected_entire_VerificationReport"])
    assert _mapping(baseline) == expected
    observation = next(
        _object(row)
        for row in _array(expected["reference_observations"])
        if _object(row)["path_id"] == "typed-control:group_certificate_digest"
    )
    certificate = BlobRef.from_mapping(_object(observation["reference"]))
    wrong = replace(certificate, byte_length=str(int(certificate.byte_length) + 1))
    original = population[certificate.digest + "|" + certificate.digest_basis].read_bytes()
    variant_bytes = b" " + original
    assert json.loads(variant_bytes) == json.loads(original)
    variant = tmp_path / "noncanonical-certificate.json"
    variant.write_bytes(variant_bytes)
    value = _object(json.loads(content))
    assert value["derived_from"] == []
    value["derived_from"] = [dict(wrong.to_mapping()), dict(certificate.to_mapping())]
    altered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()

    class SelectedFiles(_FileResolver):
        """Select actual captured files using the complete original reference argument."""

        def resolve(self, reference: BlobRef, *, max_bytes: int) -> bytes:
            """Read the real whitespace variant only for its explicit whole-reference selection.

            Parameters
            ----------
            reference : BlobRef
                Complete original selected declaration, including its distinct length.
            max_bytes : int
                Actual operation allowance passed to the unchanged bounded file reader.

            Returns
            -------
            bytes
                Actual bounded physical file bytes; identity is checked by the public operation.
            """
            if reference == wrong:
                return self._read("selected-whole-reference-variant", reference, max_bytes)
            return super().resolve(reference, max_bytes=max_bytes)

    selected = SelectedFiles({**population, "selected-whole-reference-variant": variant})
    with pytest.raises(InputRefused) as caught:
        verify(
            altered,
            schema_id=schema,
            envelopes=envelopes,
            registry=registry,
            resolver=selected,
            limits=limits,
            policy=policy,
            trust=trust,
        )
    assert asdict(caught.value.reason) == {
        "code": "reference_mismatch",
        "subject_digest": certificate.digest,
        "claim_id": None,
        "pointer": None,
        "detail": "Reference bytes conflict.",
    }
    assert [
        reference
        for reference, _ in selected.calls
        if isinstance(reference, BlobRef) and reference.digest == certificate.digest
    ] == [wrong, certificate]
    assert all(isinstance(reference, BlobRef) for reference, _ in selected.calls)
    recovered = verify(
        content,
        schema_id=schema,
        envelopes=envelopes,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
        policy=policy,
        trust=trust,
    )
    assert _mapping(recovered) == expected
    assert all(path.read_bytes() == original for path, original in before.items())
    assert variant.read_bytes() == variant_bytes


def test_policy_and_content_source_conflict_retains_entire_report_and_recovery(
    tmp_path: Path,
) -> None:
    """Report conflicting physical sources for one canonical identity without choosing either.

    Parameters
    ----------
    tmp_path : Path
        Owned canonical policy and distinct whole content files with identical JSON values.

    Notes
    -----
    The original complete fixture supplies the independent baseline and recovery
    oracle. This deliberately incompatible content selection retains every policy
    field and uses a separately selected canonical reference. All fifteen refusal
    report fields are checked, including unchanged complete current-state edges.
    No new accepted policy, signature, operational Signer or Clock is asserted.
    """
    case_path = _FIXTURES / "verify-current-whole-fixture.json"
    raw = case_path.read_bytes()
    pins = _array(
        _object(json.loads((_FIXTURES / "source-pins.json").read_bytes()))["original_cases"]
    )
    pin = next(
        _object(row) for row in pins if _object(row)["case_id"] == "verify-current-whole-fixture"
    )
    assert hashlib.sha256(raw).hexdigest() == pin["source_sha256"]
    source = _object(json.loads(raw))
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    population: dict[str, Path] = {}
    for key, value in _object(inputs["resolver_input_population"]).items():
        record = _object(value)
        path = _FIXTURES / "objects" / _text(record["sha256"])
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        assert len(data) == record["byte_length"]
        population[key] = path
    before = {path: path.read_bytes() for path in set(population.values()) | {case_path}}
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    local = _object(inputs["trust"])
    assert local["evaluation_mode"] == "current"
    trust = TrustContext(
        BlobRef.from_mapping(_object(local["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(local["current_snapshot_ref"])),
        _text(local["accepted_sequence_floor"]),
        "current",
        Utc(local["evaluation_time"]),
        tuple(_bytes(value) for value in _array(local["control_envelopes"])),
        _optional_reference(local.get("archived_snapshot_ref")),
    )
    declaration = _object(inputs["policy"])
    assert declaration["required_reference_paths"] == []
    assert declaration["required_purposes"] == ["evidence"]
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(declaration["policy_ref"])),
        tuple(_text(value) for value in _array(declaration["required_claim_ids"])),
        ("evidence",),
    )
    assert _mapping(registry) == inputs["registry"] and _mapping(policy) == declaration
    content = _bytes(inputs["content_json"])
    envelopes = tuple(_bytes(value) for value in _array(inputs["envelopes"]))
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
    expected = _object(source["expected_entire_VerificationReport"])
    assert _mapping(baseline) == expected
    policy_record = _object(
        _object(inputs["resolver_input_population"])[
            policy.policy_ref.digest + "|" + policy.policy_ref.digest_basis
        ]
    )
    original_policy = (_FIXTURES / "objects" / _text(policy_record["sha256"])).read_bytes()
    whole_policy = _object(json.loads(original_policy))
    canonical = json.dumps(
        whole_policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    assert canonical.isascii() and b"\\" not in canonical
    policy_file = tmp_path / "canonical-policy.json"
    content_file = tmp_path / "distinct-content.json"
    policy_file.write_bytes(canonical)
    content_file.write_bytes(b" " + canonical)
    assert policy_file.read_bytes() != content_file.read_bytes()
    assert json.loads(content_file.read_bytes()) == json.loads(original_policy)
    canonical_ref = BlobRef(
        "sha256:" + hashlib.sha256(canonical).hexdigest(),
        str(len(canonical)),
        "application/json",
        "jcs_content",
    )
    selected_policy = replace(policy, policy_ref=canonical_ref)
    selected = _FileResolver({**population, canonical_ref.digest + "|jcs_content": policy_file})
    expected_edges = [
        row
        for row in _array(expected["reference_observations"])
        if _object(row)["subject_digest"]
        in (trust.current_snapshot_ref.digest, registry.snapshot_ref.digest)
    ]
    assert len(expected_edges) == 27
    refusal = {
        "content_ref": {**dict(canonical_ref.to_mapping()), "schema_id": schema},
        "policy_ref": dict(canonical_ref.to_mapping()),
        "registry_ref": dict(registry.snapshot_ref.to_mapping()),
        "evaluation_mode": "current",
        "evaluation_time": str(trust.evaluation_time),
        "evaluated_claim_ids": list(policy.required_claim_ids),
        "structure": "valid",
        "integrity": "mismatched",
        "authenticity": "unsigned",
        "availability": "complete",
        "common_eligibility": "refused",
        "domain_verdict": "not_evaluated",
        "current_eligibility": "refused",
        "reference_observations": expected_edges,
        "reasons": [
            {
                "code": "reference_mismatch",
                "subject_digest": canonical_ref.digest,
                "claim_id": None,
                "pointer": "",
                "detail": "Reference bytes conflict.",
            },
            *[
                {
                    "code": "scope_missing",
                    "subject_digest": canonical_ref.digest,
                    "claim_id": identifier,
                    "pointer": "/claims",
                    "detail": "Required claim scope does not resolve in the complete content.",
                }
                for identifier in policy.required_claim_ids
            ],
            {
                "code": "signature_required",
                "subject_digest": canonical_ref.digest,
                "claim_id": None,
                "pointer": None,
                "detail": "The required evidence signature is unavailable.",
            },
            {
                "code": "domain_verifier_required",
                "subject_digest": canonical_ref.digest,
                "claim_id": None,
                "pointer": None,
                "detail": "Domain verification is required.",
            },
        ],
    }
    report = verify(
        content_file.read_bytes(),
        schema_id=schema,
        envelopes=(),
        registry=registry,
        resolver=selected,
        limits=limits,
        policy=selected_policy,
        trust=trust,
    )
    assert _mapping(report) == refusal
    assert [
        reference
        for reference, _ in selected.calls
        if isinstance(reference, BlobRef) and reference.digest == canonical_ref.digest
    ] == [canonical_ref]
    recovered = verify(
        content,
        schema_id=schema,
        envelopes=envelopes,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
        policy=policy,
        trust=trust,
    )
    assert _mapping(recovered) == expected
    assert all(path.read_bytes() == original for path, original in before.items())
    assert policy_file.read_bytes() == canonical
    assert content_file.read_bytes() == b" " + canonical
