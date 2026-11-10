# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole required content reference scope

"""Keep selected required subjects inside the actual public content closure."""

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from tests.domain.test_cli_evidence_sources import _source, _transport
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
    Limits,
    ReferenceRequirement,
    TrustContext,
    Utc,
    VerificationPolicy,
    canonicalize_json,
    reference_bytes,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"


@pytest.mark.parametrize("scope", ("inside", "outside"))
def test_required_subject_scope_preserves_whole_report_and_recovery(
    scope: str, tmp_path: Path
) -> None:
    """Compare entire actual reports and forbid store discovery from a required selector.

    Parameters
    ----------
    scope : str
        Actual selected root, or a complete valid-shaped manifest present only in the store.
    tmp_path : Path
        Owned real unselected manifest source; published original inputs remain immutable.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    content = _bytes(inputs["content_json"])
    schema = _text(inputs["schema_id"])
    content_ref = reference_bytes(
        content,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=schema,
        limits=limits,
    )
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    original_bytes = {path: path.read_bytes() for path in population.values()}
    declared = _object(inputs["policy"])
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(declared["policy_ref"])),
        tuple(_text(x) for x in _array(declared["required_claim_ids"])),
        ("evidence",),
    )
    local = _object(inputs["trust"])
    trust = TrustContext(
        BlobRef.from_mapping(_object(local["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(local["current_snapshot_ref"])),
        _text(local["accepted_sequence_floor"]),
        "current",
        Utc(local["evaluation_time"]),
        tuple(_bytes(x) for x in _array(local["control_envelopes"])),
        _optional_reference(local.get("archived_snapshot_ref")),
    )
    envelopes = tuple(_bytes(x) for x in _array(inputs["envelopes"]))
    original = _object(json.loads(content))
    unselected = {
        **original,
        "producer": {
            **_object(original["producer"]),
            "principal": "unselected-whole-manifest-principal",
        },
    }
    unselected_bytes = canonicalize_json(_transport(unselected), limits=limits)
    unselected_ref = reference_bytes(
        unselected_bytes,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=schema,
        limits=limits,
    )
    path = tmp_path / unselected_ref.digest[7:]
    path.write_bytes(unselected_bytes)
    population[unselected_ref.digest + "|jcs_content"] = path
    entry = next(item for item in registry.entries if item.schema_id == schema)
    selected_path = next(
        item
        for item in entry.reference_paths
        if len(item.steps) == 1 and item.steps[0].get("name") == "payload_ref"
    )
    subject = content_ref if scope == "inside" else unselected_ref
    requirement = ReferenceRequirement(subject.digest, schema, selected_path.path_id, None)
    resolver = _FileResolver(population)
    actual = verify(
        content,
        schema_id=schema,
        envelopes=envelopes,
        registry=registry,
        resolver=resolver,
        limits=limits,
        policy=replace(policy, required_reference_paths=(requirement,)),
        trust=trust,
    )
    expected = _object(source["expected_entire_VerificationReport"])
    if scope == "outside":
        expected.update(
            common_eligibility="refused",
            current_eligibility="refused",
            reasons=[
                {
                    "code": "scope_missing",
                    "subject_digest": unselected_ref.digest,
                    "claim_id": None,
                    "pointer": None,
                    "detail": "Required selector subject is outside the selected valid closure.",
                },
                *_array(expected["reasons"]),
            ],
        )
    assert _mapping(actual) == expected
    assert unselected_ref not in {reference for reference, _ in resolver.calls}
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
    assert path.read_bytes() == unselected_bytes
    assert all(path.read_bytes() == raw for path, raw in original_bytes.items())


@pytest.mark.parametrize("instances", (None, ("/derived_from/0",)))
def test_required_empty_reference_population_preserves_whole_report_and_recovery(
    instances: tuple[str, ...] | None,
) -> None:
    """Refuse an explicit required empty source population without changing the original subject.

    Parameters
    ----------
    instances : tuple of str or None
        All instances of the existing derived_from selector, or its exact first
        concrete pointer. Both must resolve despite the source's allowed empty array.

    Notes
    -----
    The entire original manifest, receipts, eight-entry registry and actual
    bounded source files are retained. The selected public policy requirement
    alone changes; no private production selector or accepted-state fixture is used.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    content = _bytes(inputs["content_json"])
    assert _object(json.loads(content))["derived_from"] == []
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    schema = _text(inputs["schema_id"])
    content_ref = reference_bytes(
        content,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=schema,
        limits=limits,
    )
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    original_bytes = {path: path.read_bytes() for path in population.values()}
    declared = _object(inputs["policy"])
    assert declared["required_purposes"] == ["evidence"]
    assert declared["required_reference_paths"] == []
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(declared["policy_ref"])),
        tuple(_text(value) for value in _array(declared["required_claim_ids"])),
        ("evidence",),
    )
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
    envelopes = tuple(_bytes(value) for value in _array(inputs["envelopes"]))
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
    entry = next(item for item in registry.entries if item.schema_id == schema)
    selected = next(
        path
        for path in entry.reference_paths
        if tuple(dict(step) for step in path.steps)
        == ({"kind": "member", "name": "derived_from"}, {"kind": "each"})
    )
    requirement = ReferenceRequirement(content_ref.digest, schema, selected.path_id, instances)
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
    pointer = "/derived_from" if instances is None else instances[0]
    reason = {
        "code": "scope_missing",
        "subject_digest": content_ref.digest,
        "claim_id": None,
        "pointer": pointer,
        "detail": "Required reference position is invalid or absent.",
    }
    expected = _object(json.loads(json.dumps(source["expected_entire_VerificationReport"])))
    expected["common_eligibility"] = "refused"
    expected["current_eligibility"] = "refused"
    expected["reasons"] = [reason, *_array(expected["reasons"])]
    observations = [
        *_array(expected["reference_observations"]),
        {
            "subject_digest": content_ref.digest,
            "path_id": selected.path_id,
            "pointer": pointer,
            "required": True,
            "reference": None,
            "outcome": "absent",
            "reasons": [reason],
        },
    ]
    expected["reference_observations"] = sorted(
        observations,
        key=lambda row: tuple(
            _text(_object(row)[name]).encode("utf-16-be")
            for name in ("subject_digest", "path_id", "pointer")
        ),
    )
    assert _mapping(actual) == expected
    restored = verify(
        content,
        schema_id=schema,
        envelopes=envelopes,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
        policy=policy,
        trust=trust,
    )
    assert _mapping(restored) == source["expected_entire_VerificationReport"]
    assert all(path.read_bytes() == raw for path, raw in original_bytes.items())
