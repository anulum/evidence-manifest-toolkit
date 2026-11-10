# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — independent fixture graph depth frontier

"""Derive genuine overdepth source identities from complete declared fixture graphs."""

import json
from pathlib import Path

from tests.domain.test_verification_report_sources import _array, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, reference_bytes


def overdepth_digests(
    root: BlobRef, directory: Path, inputs: dict[str, object], *, limits: Limits
) -> tuple[str, ...]:
    """Find the actual source frontier one edge beyond the unchanged public depth limit.

    Parameters
    ----------
    root : BlobRef
        Complete actual final fixture manifest reference.
    directory : Path
        Owned canonical sources, all constructed before first S0.
    inputs : dict
        Complete original fixture inputs, including its literal source population
        and static catalogue. This fixture oracle is not a runtime source decoder.
    limits : Limits
        Original operation limits, never enlarged for the adverse graph.

    Returns
    -------
    tuple of str
        Sorted unique actual digests reachable at max_graph_depth plus one.
        The public diagnostic may identify any such genuine overdepth source;
        no private traversal order is asserted.
    """
    population = _object(inputs["resolver_input_population"])
    known = {
        "evidence_manifest_toolkit.manifest.v1",
        "evidence_manifest_toolkit.independent_validation_record.v2",
        "evidence_manifest_toolkit.independent_validation_body.v2",
        "evidence_manifest_toolkit.identity_binding.v2",
    } | {
        _text(_object(entry)["schema_id"])
        for entry in _array(_object(inputs["registry"])["entries"])
    }
    cache: dict[BlobRef, tuple[BlobRef, ...]] = {}
    detours: dict[BlobRef, BlobRef] = {}

    def references(value: object) -> tuple[BlobRef, ...]:
        """Retain all actual full references in a whole known fixture-native object."""
        if isinstance(value, list):
            return tuple(child for item in _array(value) for child in references(item))
        if isinstance(value, dict):
            mapping = _object(value)
            if {"digest", "byte_length", "media_type", "digest_basis"} <= mapping.keys():
                return (BlobRef.from_mapping(mapping),)
            return tuple(child for item in mapping.values() for child in references(item))
        return ()

    def children(reference: BlobRef) -> tuple[BlobRef, ...]:
        """Read only an actual owned or explicitly original fixture source argument."""
        if reference in cache:
            return cache[reference]
        if reference.media_type != "application/json":
            cache[reference] = ()
            return ()
        path = directory / reference.digest[7:]
        if not path.is_file():
            declared = _object(population[reference.digest + "|" + reference.digest_basis])
            path = (
                Path(__file__).parent
                / "fixtures/evidence-command-sources/objects"
                / _text(declared["sha256"])
            )
        raw = path.read_bytes()
        assert (
            reference_bytes(
                raw,
                media_type=reference.media_type,
                digest_basis=reference.digest_basis,
                schema_id=reference.schema_id,
                limits=limits,
            )
            == reference
        )
        value = _object(json.loads(raw))
        selected = reference.schema_id in known or value.get("schema_id") in known
        result = references(value) if selected else ()
        if value.get("schema_id") == "evidence_manifest_toolkit.independent_validation_record.v2":
            detours[reference] = BlobRef.from_mapping(_object(value["validation_C0_statement_ref"]))
        cache[reference] = result
        return result

    def frontier_at_bound(*, with_validation: bool) -> set[BlobRef]:
        """Keep every complete graph path or remove only the actual validation detours."""
        frontier = {root}
        for _ in range(limits.max_graph_depth + 1):
            frontier = {
                child
                for parent in frontier
                for child in children(parent)
                if with_validation or child != detours.get(parent)
            }
        return frontier

    assert not frontier_at_bound(with_validation=False)
    frontier = frontier_at_bound(with_validation=True)
    assert frontier
    return tuple(sorted({reference.digest for reference in frontier}))


def history_source_refs(content_json: bytes, directory: Path, *, steps: int) -> tuple[BlobRef, ...]:
    """Retain every whole source argument in the fixture's actual renewal chain.

    Parameters
    ----------
    content_json : bytes
        Entire final manifest actually supplied to public verification.
    directory : Path
        Original owned canonical record/body/validation/subject source store.
    steps : int
        Exact number of declared renewals, independently fixed by the fixture.

    Returns
    -------
    tuple of BlobRef
        Actual complete record, body, validation manifest and earlier subject
        references for each renewal. The caller checks actual public resolver calls.
    """
    subject = _object(json.loads(content_json))
    result: list[BlobRef] = []
    for _ in range(steps):
        claims = [
            _object(value)
            for value in _array(subject["claims"])
            if _object(_object(value)["validation"])["status"] == "independently_reproduced"
        ]
        assert len(claims) == 1
        record_ref = BlobRef.from_mapping(_object(_object(claims[0]["validation"])["record_ref"]))
        record = _object(json.loads((directory / record_ref.digest[7:]).read_bytes()))
        body_ref = BlobRef.from_mapping(_object(record["body_ref"]))
        validation_ref = BlobRef.from_mapping(_object(record["validation_C0_statement_ref"]))
        body = _object(json.loads((directory / body_ref.digest[7:]).read_bytes()))
        earlier_ref = BlobRef.from_mapping(_object(body["subject_ref"]))
        result.extend((record_ref, body_ref, validation_ref, earlier_ref))
        subject = _object(json.loads((directory / earlier_ref.digest[7:]).read_bytes()))
    assert all(
        _object(_object(value)["validation"])["status"] != "independently_reproduced"
        for value in _array(subject["claims"])
    )
    return tuple(result)
