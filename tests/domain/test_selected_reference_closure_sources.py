# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — selected reference closure and backend absence

"""Check complete selected-reference absence and schema refusals through public operations."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from tests.domain.test_cli_evidence_sources import _source
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
    Reason,
    ReferenceRequirement,
    ReferenceUnavailable,
    SealResult,
    TrustContext,
    Utc,
    VerificationPolicy,
    seal,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"


class _DigestMissingFiles(_FileResolver):
    """Read real selected files and retain the backend's digest-only absence.

    Parameters
    ----------
    population : dict
        Actual complete source files, with explicitly selected missing entries removed.
    """

    def resolve(self, reference: BlobRef, *, max_bytes: int) -> bytes:
        """Read the actual file while exposing its backend lookup key on absence.

        Parameters
        ----------
        reference : BlobRef
            Original full public lookup selection.
        max_bytes : int
            Actual remaining acquisition allowance.

        Returns
        -------
        bytes
            Complete bounded file bytes when the source exists.

        Raises
        ------
        ReferenceUnavailable
            The real file lookup has no source, naming the backend's digest key.
        """
        try:
            return super().resolve(reference, max_bytes=max_bytes)
        except ReferenceUnavailable as error:
            raise ReferenceUnavailable(reference.digest) from error


def test_backend_digest_absence_retains_complete_reference_report_and_recovery() -> None:
    """Preserve every report field and recover with the untouched actual source population.

    Notes
    -----
    The original source corpus fixes both entire fifteen-field report oracles.
    A real bounded file Resolver supplies the source bytes and actual missing
    lookup. No private production helper, mocked acquisition or claimed Clock,
    operational authority or scientific admission replaces public verification.
    """
    source = _source("verify-required-environment-unavailable")
    recovered_source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    recovered_inputs = _object(recovered_source["complete_library_inputs"])
    assert {key: value for key, value in inputs.items() if key != "resolver_overrides"} == {
        key: value for key, value in recovered_inputs.items() if key != "resolver_overrides"
    }
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    before = {path: path.read_bytes() for path in population.values()}
    local = _object(inputs["trust"])
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
    assert local["evaluation_mode"] == "current"
    assert declaration["required_purposes"] == ["evidence"]
    assert declaration["required_reference_paths"] == []
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(declaration["policy_ref"])),
        tuple(_text(value) for value in _array(declaration["required_claim_ids"])),
        ("evidence",),
    )
    overrides = _object(inputs["resolver_overrides"])
    assert len(overrides) == 1
    missing_key, override_value = next(iter(overrides.items()))
    override = _object(override_value)
    assert override["mode"] == "missing"
    missing_reference = BlobRef.from_mapping(_object(override["declared_reference"]))
    absent_population = {key: value for key, value in population.items() if key != missing_key}
    assert len(absent_population) + 1 == len(population)
    for resolver in (_FileResolver(absent_population), _DigestMissingFiles(absent_population)):
        actual = verify(
            _bytes(inputs["content_json"]),
            schema_id=_text(inputs["schema_id"]),
            envelopes=tuple(_bytes(value) for value in _array(inputs["envelopes"])),
            registry=registry,
            resolver=resolver,
            limits=limits,
            policy=policy,
            trust=trust,
        )
        assert _mapping(actual) == source["expected_entire_VerificationReport"]
        unavailable = tuple(
            edge for edge in actual.reference_observations if edge.outcome == "unavailable"
        )
        expected = _object(source["expected_entire_VerificationReport"])
        expected_missing = tuple(
            row
            for row in _array(expected["reference_observations"])
            if _object(row)["outcome"] == "unavailable"
        )
        assert len(unavailable) == len(expected_missing) == 2
        assert all(edge.reference == missing_reference for edge in unavailable)
        assert any(reference == missing_reference for reference, _ in resolver.calls)
    restored = verify(
        _bytes(inputs["content_json"]),
        schema_id=_text(inputs["schema_id"]),
        envelopes=tuple(_bytes(value) for value in _array(inputs["envelopes"])),
        registry=registry,
        resolver=_DigestMissingFiles(population),
        limits=limits,
        policy=policy,
        trust=trust,
    )
    assert _mapping(restored) == recovered_source["expected_entire_VerificationReport"]
    assert all(path.read_bytes() == raw for path, raw in before.items())


@pytest.mark.parametrize(
    "condition", ("missing_creation", "unknown_reference_schema", "non_json_source")
)
def test_complete_manifest_schema_refusal_and_original_unsigned_recovery(condition: str) -> None:
    """Reject actual root and source declarations while recovering the entire original content.

    Parameters
    ----------
    condition : str
        Missing mandatory root time, unknown whole-reference assertion, or an
        actual plain-text environment incorrectly asserted to be a known JSON schema.

    Notes
    -----
    Uses the complete original nine-field manifest, eight-entry catalogue and
    real source files. Only the named declaration changes. Unsigned construction
    and its recovery establish no current, domain, Clock or authority admission.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    original = _bytes(inputs["content_json"])
    document = _object(json.loads(original))
    assert original.isascii()
    assert original == json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    schema = _text(inputs["schema_id"])
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    before = {path: path.read_bytes() for path in population.values()}
    baseline = SealResult(
        original,
        BlobRef(
            "sha256:" + hashlib.sha256(original).hexdigest(),
            str(len(original)),
            "application/json",
            "jcs_content",
            schema,
        ),
        None,
    )
    assert (
        seal(
            original,
            schema_id=schema,
            registry=registry,
            resolver=_FileResolver(population),
            limits=limits,
        )
        == baseline
    )
    environment = _object(document["environment_ref"])
    if condition == "missing_creation":
        del document["created_at"]
    elif condition == "unknown_reference_schema":
        environment["schema_id"] = "unregistered.environment.schema"
        document["environment_ref"] = environment
    else:
        assert condition == "non_json_source"
        raw = population[_text(environment["digest"]) + "|" + _text(environment["digest_basis"])]
        assert environment["digest_basis"] == "raw_bytes"
        with pytest.raises(json.JSONDecodeError):
            json.loads(raw.read_bytes())
        environment["schema_id"] = schema
        document["environment_ref"] = environment
    changed = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    changed_digest = "sha256:" + hashlib.sha256(changed).hexdigest()
    expected = (
        Reason(
            "invalid_schema",
            changed_digest,
            None,
            "",
            "Input violates its selected schema.",
        )
        if condition == "missing_creation"
        else Reason(
            "unknown_schema",
            changed_digest,
            None,
            "/environment_ref",
            "Selected schema is not known.",
        )
        if condition == "unknown_reference_schema"
        else Reason(
            "invalid_json",
            _text(environment["digest"]),
            None,
            None,
            "Input is not valid strict JSON.",
        )
    )
    with pytest.raises(InputRefused) as refused:
        seal(
            changed,
            schema_id=schema,
            registry=registry,
            resolver=_FileResolver(population),
            limits=limits,
        )
    assert refused.value.reason == expected
    assert (
        seal(
            original,
            schema_id=schema,
            registry=registry,
            resolver=_FileResolver(population),
            limits=limits,
        )
        == baseline
    )
    assert all(path.read_bytes() == raw for path, raw in before.items())


def _whole_shared_dependency_graph(
    inputs: dict[str, object],
    directory: Path,
    population: dict[str, Path],
    *,
    reverse: bool,
    repeated: bool = False,
) -> tuple[bytes, BlobRef, BlobRef]:
    """Build ordered whole manifests around an unchanged original statement source.

    Parameters
    ----------
    inputs : dict
        Entire original manifest, eight-entry registry and bounded source fixture.
    directory : Path
        Owned immutable dependency document, never an original fixture destination.
    population : dict
        Real full-reference file lookup, extended only with this whole dependency.
    reverse : bool
        Keep the indirect dependency before the directly shared statement source.
    repeated : bool
        Preserve two identical complete dependency edges in the original array.

    Returns
    -------
    tuple
        Whole root bytes, the independently hashed dependency Ref and unchanged
        complete statement Ref. No native authority or reproduction is admitted.
    """
    statement_key = (
        "sha256:117be7591b1ff1aea1f54ed0db52fd17405675e22d7e9e13d086cc659f28599d|jcs_content"
    )
    statement = population[statement_key].read_bytes()
    assert hashlib.sha256(statement).hexdigest() == statement_key[7:71]
    assert _object(json.loads(statement))["schema_id"] == (
        "evidence_manifest_toolkit.signed_statement.v1"
    )
    leaf = BlobRef(
        statement_key[:71],
        str(len(statement)),
        "application/json",
        "jcs_content",
        "evidence_manifest_toolkit.signed_statement.v1",
    )
    original = _bytes(inputs["content_json"])
    dependency = _object(json.loads(original))
    assert original == json.dumps(dependency, sort_keys=True, separators=(",", ":")).encode("ascii")
    producer = _object(dependency["producer"])
    producer["principal"] = "Arcane Sapience"
    dependency["producer"] = producer
    dependency["derived_from"] = [dict(leaf.to_mapping())]
    dependency_bytes = json.dumps(dependency, sort_keys=True, separators=(",", ":")).encode("ascii")
    selected = BlobRef(
        "sha256:" + hashlib.sha256(dependency_bytes).hexdigest(),
        str(len(dependency_bytes)),
        "application/json",
        "jcs_content",
        _text(inputs["schema_id"]),
    )
    destination = directory / selected.digest[7:]
    destination.write_bytes(dependency_bytes)
    population[selected.digest + "|jcs_content"] = destination
    root = _object(json.loads(original))
    edges = [dict(leaf.to_mapping()), dict(selected.to_mapping())]
    root["derived_from"] = (
        [dict(selected.to_mapping()), dict(selected.to_mapping())]
        if repeated
        else list(reversed(edges))
        if reverse
        else edges
    )
    return (
        json.dumps(root, sort_keys=True, separators=(",", ":")).encode("ascii"),
        selected,
        leaf,
    )


@pytest.mark.parametrize("maximum", (2, 3))
@pytest.mark.parametrize("reverse", (False, True))
def test_whole_shared_source_depth_preserves_both_orders_and_recovery(
    maximum: int, reverse: bool, tmp_path: Path
) -> None:
    """Check a deeper shared source after its shallower visit through public seal.

    Parameters
    ----------
    maximum : int
        Original graph bound two, or the exact complete indirect-path depth three.
    reverse : bool
        Reverse only the full direct/indirect dependency order.
    tmp_path : Path
        Owned whole dependency source; original corpus objects remain unchanged.

    Notes
    -----
    The full original nine-field manifests, both unclaimed architecture-only
    claims and the complete native registry remain. Cached file bytes must not
    hide a later deeper path. No scientific, Clock or current admission follows.
    """
    inputs = _object(_source("verify-current-whole-fixture")["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    schema = _text(inputs["schema_id"])
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    original = _bytes(inputs["content_json"])
    baseline = SealResult(
        original,
        BlobRef(
            "sha256:" + hashlib.sha256(original).hexdigest(),
            str(len(original)),
            "application/json",
            "jcs_content",
            schema,
        ),
        None,
    )
    assert (
        seal(
            original,
            schema_id=schema,
            registry=registry,
            resolver=_FileResolver(population),
            limits=replace(limits, max_graph_depth=2),
        )
        == baseline
    )
    content, dependency, statement = _whole_shared_dependency_graph(
        inputs, tmp_path, population, reverse=reverse
    )
    expected = SealResult(
        content,
        BlobRef(
            "sha256:" + hashlib.sha256(content).hexdigest(),
            str(len(content)),
            "application/json",
            "jcs_content",
            schema,
        ),
        None,
    )
    before = {path: path.read_bytes() for path in population.values()}
    resolver = _FileResolver(population)
    if maximum == 2:
        environment = _object(_object(json.loads(original))["environment_ref"])
        with pytest.raises(InputRefused) as caught:
            seal(
                content,
                schema_id=schema,
                registry=registry,
                resolver=resolver,
                limits=replace(limits, max_graph_depth=maximum),
            )
        assert caught.value.reason == Reason(
            "limit_exceeded",
            _text(environment["digest"]),
            None,
            None,
            "Reference graph depth bound exceeded.",
        )
    else:
        assert (
            seal(
                content,
                schema_id=schema,
                registry=registry,
                resolver=resolver,
                limits=replace(limits, max_graph_depth=maximum),
            )
            == expected
        )
    restored = _FileResolver(population)
    assert (
        seal(
            content,
            schema_id=schema,
            registry=registry,
            resolver=restored,
            limits=replace(limits, max_graph_depth=3),
        )
        == expected
    )
    for reference in (dependency, statement):
        assert sum(actual == reference for actual, _ in restored.calls) == 1
    assert all(0 < cap <= limits.max_blob_bytes for _, cap in restored.calls)
    assert all(path.read_bytes() == raw for path, raw in before.items())


def test_duplicate_whole_dependencies_preserve_bytes_and_one_bounded_read(tmp_path: Path) -> None:
    """Keep duplicate declared edges while reading their complete source only once.

    Parameters
    ----------
    tmp_path : Path
        Owned complete dependency source, without any original source mutation.
    """
    inputs = _object(_source("verify-current-whole-fixture")["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    content, dependency, statement = _whole_shared_dependency_graph(
        inputs, tmp_path, population, reverse=False, repeated=True
    )
    before = {path: path.read_bytes() for path in population.values()}
    resolver = _FileResolver(population)
    result = seal(
        content,
        schema_id=_text(inputs["schema_id"]),
        registry=registry,
        resolver=resolver,
        limits=replace(limits, max_graph_depth=3),
    )
    assert result == SealResult(
        content,
        BlobRef(
            "sha256:" + hashlib.sha256(content).hexdigest(),
            str(len(content)),
            "application/json",
            "jcs_content",
            _text(inputs["schema_id"]),
        ),
        None,
    )
    assert _object(json.loads(result.canonical_content))["derived_from"] == [
        dict(dependency.to_mapping()),
        dict(dependency.to_mapping()),
    ]
    for reference in (dependency, statement):
        assert sum(actual == reference for actual, _ in resolver.calls) == 1
    assert all(0 < cap <= limits.max_blob_bytes for _, cap in resolver.calls)
    assert all(path.read_bytes() == raw for path, raw in before.items())


@pytest.mark.parametrize("instances", (None, ("/hardware_ref",)))
def test_required_nested_hardware_source_preserves_whole_report_and_recovery(
    instances: tuple[str, ...] | None,
) -> None:
    """Require the existing absent nested source only through explicit public policy.

    Parameters
    ----------
    instances : tuple of str or None
        All hardware selector instances or its exact literal optional field.

    Notes
    -----
    The original target is a simulation with unknown capability declarations.
    No machine, hardware provider, key, Clock or source is acquired or invented.
    Every one of the original fifteen report fields is compared and recovered.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    content = _bytes(inputs["content_json"])
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    before = {path: path.read_bytes() for path in population.values()}
    local = _object(inputs["trust"])
    trust = TrustContext(
        BlobRef.from_mapping(_object(local["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(local["current_snapshot_ref"])),
        _text(local["accepted_sequence_floor"]),
        "current",
        Utc(local["evaluation_time"]),
        tuple(_bytes(value) for value in _array(local["control_envelopes"])),
        _optional_reference(local.get("archived_snapshot_ref")),
    )
    selected = _object(inputs["policy"])
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(selected["policy_ref"])),
        tuple(_text(value) for value in _array(selected["required_claim_ids"])),
        ("evidence",),
    )
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
    assert _mapping(baseline) == source["expected_entire_VerificationReport"]
    target = BlobRef.from_mapping(_object(_object(json.loads(content))["payload_ref"]))
    assert target.schema_id == "evidence_manifest_toolkit.target_descriptor.v1"
    entry = next(item for item in registry.entries if item.schema_id == target.schema_id)
    path = next(
        item
        for item in entry.reference_paths
        if tuple(dict(step) for step in item.steps) == ({"kind": "member", "name": "hardware_ref"},)
    )
    requirement = ReferenceRequirement(target.digest, entry.schema_id, path.path_id, instances)
    actual = verify(
        content,
        schema_id=schema,
        envelopes=envelopes,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
        policy=replace(policy, required_reference_paths=(requirement,)),
        trust=trust,
    )
    reason = {
        "code": "scope_missing",
        "subject_digest": target.digest,
        "claim_id": None,
        "pointer": "/hardware_ref",
        "detail": "Required reference position is invalid or absent.",
    }
    expected = _object(json.loads(json.dumps(source["expected_entire_VerificationReport"])))
    expected["common_eligibility"] = "refused"
    expected["current_eligibility"] = "refused"
    expected["reasons"] = [reason, *_array(expected["reasons"])]
    observations = [_object(row) for row in _array(expected["reference_observations"])]
    matching = [
        row
        for row in observations
        if row["subject_digest"] == target.digest
        and row["path_id"] == path.path_id
        and row["pointer"] == "/hardware_ref"
    ]
    assert len(matching) == 1
    matching[0].update(required=True, outcome="absent", reasons=[reason])
    expected["reference_observations"] = observations
    assert _mapping(actual) == expected
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
    assert all(path.read_bytes() == raw for path, raw in before.items())
