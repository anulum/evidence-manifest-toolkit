# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete native control construction

"""Exercise public unsigned control construction against original whole source bytes."""

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from tests.domain.test_verification_report_sources import _FileResolver, _object, _registry, _text

from evidence_manifest_toolkit import BlobRef, InputRefused, Limits, Reason, seal

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_SCHEMA = "evidence_manifest_toolkit.trust_snapshot.v1"


@pytest.mark.parametrize("schema_assertion", ("present", "omitted", "conflicting"))
def test_native_certificate_reference_metadata_and_immutable_recovery(
    schema_assertion: str,
) -> None:
    """Construct complete snapshots while retaining known native certificate context.

    Parameters
    ----------
    schema_assertion : str
        Original optional reference assertion, its omission, or an explicit wrong assertion.

    Notes
    -----
    This exercises unsigned construction and reference refusal, not root issuance,
    signed authority, external signer qualification or current evidence acceptance.
    """
    source_path = _FIXTURES / "verify-current-whole-fixture.json"
    source_bytes = source_path.read_bytes()
    pins = _object(json.loads((_FIXTURES / "source-pins.json").read_bytes()))["original_cases"]
    assert isinstance(pins, list)
    selected = next(
        _object(member)
        for member in pins
        if _object(member)["case_id"] == "verify-current-whole-fixture"
    )
    assert hashlib.sha256(source_bytes).hexdigest() == selected["source_sha256"]
    source = _object(json.loads(source_bytes))
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    bounds = _object(inputs["limits"])
    assert all(type(value) is int for value in bounds.values())
    limits = Limits(**cast(dict[str, int], bounds))
    population: dict[str, Path] = {}
    for key, member in _object(inputs["resolver_input_population"]).items():
        original = _object(member)
        path = _FIXTURES / "objects" / _text(original["sha256"])
        data = path.read_bytes()
        assert len(data) == original["byte_length"]
        assert hashlib.sha256(data).hexdigest() == original["sha256"]
        population[key] = path
    reference = _object(_object(inputs["trust"])["current_snapshot_ref"])
    original_snapshot = population[_text(reference["digest"]) + "|jcs_content"].read_bytes()
    snapshot = _object(json.loads(original_snapshot))
    assert original_snapshot == json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    certificates = snapshot["group_certificate_refs"]
    assert isinstance(certificates, list) and len(certificates) == 1
    certificate = _object(certificates[0])
    assert certificate["schema_id"] == "evidence_manifest_toolkit.group_certificate.v1"
    if schema_assertion == "omitted":
        certificate.pop("schema_id")
    elif schema_assertion == "conflicting":
        certificate["schema_id"] = _SCHEMA
    else:
        assert schema_assertion == "present"
    snapshot["group_certificate_refs"] = [certificate]
    content = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("ascii")
    paths = set(population.values()) | {source_path}
    before = {path: path.read_bytes() for path in paths}
    resolver = _FileResolver(population)
    if schema_assertion == "conflicting":
        with pytest.raises(InputRefused) as refused:
            seal(content, schema_id=_SCHEMA, registry=registry, resolver=resolver, limits=limits)
        assert refused.value.reason == Reason(
            "invalid_schema",
            "sha256:" + hashlib.sha256(content).hexdigest(),
            None,
            "/group_certificate_refs/0",
            "Declared schema conflicts with its independently selected native context.",
        )
    else:
        result = seal(
            content, schema_id=_SCHEMA, registry=registry, resolver=resolver, limits=limits
        )
        assert result.canonical_content == content
        assert result.content_ref == BlobRef(
            "sha256:" + hashlib.sha256(content).hexdigest(),
            str(len(content)),
            "application/json",
            "jcs_content",
            _SCHEMA,
        )
        assert result.envelope_json is None
    recovery = seal(
        original_snapshot, schema_id=_SCHEMA, registry=registry, resolver=resolver, limits=limits
    )
    assert recovery.canonical_content == original_snapshot
    assert recovery.content_ref == BlobRef.from_mapping(reference)
    assert recovery.envelope_json is None
    assert before == {path: path.read_bytes() for path in paths}
