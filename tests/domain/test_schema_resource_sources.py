# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original protected schema URI metadata binding

"""Resolve original native schema constraints after permitted root URI metadata changes."""

import hashlib
import json
from dataclasses import asdict, replace
from importlib.resources import files
from pathlib import Path
from typing import cast

import pytest
from tests.domain.test_verification_report_sources import _bytes, _FileResolver, _registry

from evidence_manifest_toolkit import ConfigurationError, Limits, reference_bytes, seal


@pytest.mark.parametrize(
    "identifier",
    ("manifest.json", "sub/manifest.json", "https://example.invalid/sub/manifest.json"),
)
def test_original_manifest_root_uri_metadata_and_whole_unsigned_recovery(identifier: str) -> None:
    """Preserve all original constraints and whole content through native URI resolution.

    Parameters
    ----------
    identifier : str
        Controlled existing root metadata value, including a relative directory component.

    Notes
    -----
    Calls only the public reference and unsigned sealing APIs with the original
    complete eight-entry catalogue, real source files and whole manifest. Only
    root$id metadata changes; no new schema, domain verdict or authority is supplied.
    This does not authenticate an altered catalogue or qualify signed construction.
    """
    fixtures = Path(__file__).parent / "fixtures/evidence-command-sources"
    path = fixtures / "verify-current-whole-fixture.json"
    original = path.read_bytes()
    source = json.loads(original)
    inputs = source["complete_library_inputs"]
    registry = _registry(inputs["registry"])
    limits = Limits(**inputs["limits"])
    population = {
        name: fixtures / "objects" / record["sha256"]
        for name, record in inputs["resolver_input_population"].items()
    }
    before = {p: p.read_bytes() for p in set(population.values()) | {path}}
    for record in inputs["resolver_input_population"].values():
        data = (fixtures / "objects" / record["sha256"]).read_bytes()
        assert (
            len(data) == record["byte_length"]
            and hashlib.sha256(data).hexdigest() == record["sha256"]
        )
    content = _bytes(inputs["content_json"])
    schema_id = cast(str, inputs["schema_id"])
    baseline = seal(
        content,
        schema_id=schema_id,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
    )
    selected = next(entry for entry in registry.entries if entry.schema_id == schema_id)
    schema = json.loads(selected.schema_bytes)
    original_identifier = schema["$id"]
    schema["$id"] = identifier
    raw = json.dumps(schema).encode()
    declared = reference_bytes(
        raw,
        media_type=selected.media_type,
        digest_basis=selected.digest_basis,
        schema_id=selected.schema_ref.schema_id,
        limits=limits,
    )
    changed = replace(selected, schema_bytes=raw, schema_ref=declared)
    supplied = replace(
        registry,
        entries=tuple(
            changed if entry.schema_id == schema_id else entry for entry in registry.entries
        ),
    )
    actual = seal(
        content,
        schema_id=schema_id,
        registry=supplied,
        resolver=_FileResolver(population),
        limits=limits,
    )
    assert actual == baseline and actual.envelope_json is None
    assert json.loads(selected.schema_bytes)["$id"] == original_identifier
    recovered = seal(
        content,
        schema_id=schema_id,
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
    )
    assert recovered == baseline
    assert all(p.read_bytes() == raw for p, raw in before.items())


def test_existing_official_core_fragment_binding_uses_root_identifier_once() -> None:
    """Bind original published metaschema fragments after a controlled relative root URI.

    Notes
    -----
    The resource is the complete existing official Draft2020-12 core metaschema,
    not an invented validator or record layout. The original native manifest
    schema is the entire inspected document; the original eight native catalogue
    entries remain. Public unsigned seal supplies no catalogue authentication,
    domain/record qualification or trusted current approval.
    """
    fixtures = Path(__file__).parent / "fixtures/evidence-command-sources"
    source = json.loads((fixtures / "verify-current-whole-fixture.json").read_bytes())
    inputs = source["complete_library_inputs"]
    registry = _registry(inputs["registry"])
    limits = Limits(**inputs["limits"])
    population = {
        name: fixtures / "objects" / row["sha256"]
        for name, row in inputs["resolver_input_population"].items()
    }
    native = next(entry for entry in registry.entries if entry.schema_id == inputs["schema_id"])
    uri = "https://json-schema.org/draft/2020-12/meta/core"
    raw = (
        files("jsonschema_specifications")
        .joinpath("schemas/draft202012/vocabularies/core")
        .read_bytes()
    )
    core = json.loads(raw)
    assert core["$id"] == uri
    reference = reference_bytes(
        raw,
        media_type="application/schema+json",
        digest_basis="raw_bytes",
        schema_id=None,
        limits=limits,
    )
    entry = replace(
        native,
        schema_id=uri,
        owner="JSON Schema",
        schema_ref=reference,
        schema_bytes=raw,
        reference_paths=(),
        common_semantics_id="evidence_manifest_toolkit.common_json.v1",
        schema_role="domain_support",
        schema_dependencies=(),
        domain_support="required_unqualified",
        domain_verifier_ref=None,
        domain_qualification_ref=None,
    )
    complete = replace(registry, entries=registry.entries + (entry,))
    baseline = seal(
        native.schema_bytes,
        schema_id=uri,
        registry=complete,
        resolver=_FileResolver(population),
        limits=limits,
    )
    core["$id"] = "sub/core.json"
    altered_bytes = json.dumps(core).encode()
    altered_ref = reference_bytes(
        altered_bytes,
        media_type="application/schema+json",
        digest_basis="raw_bytes",
        schema_id=None,
        limits=limits,
    )
    changed = replace(entry, schema_bytes=altered_bytes, schema_ref=altered_ref)
    selected = replace(registry, entries=registry.entries + (changed,))
    actual = seal(
        native.schema_bytes,
        schema_id=uri,
        registry=selected,
        resolver=_FileResolver(population),
        limits=limits,
    )
    assert actual == baseline and actual.envelope_json is None
    malformed = json.loads(altered_bytes)
    del malformed["$defs"]["uriReferenceString"]
    bad_bytes = json.dumps(malformed).encode()
    bad_ref = reference_bytes(
        bad_bytes,
        media_type="application/schema+json",
        digest_basis="raw_bytes",
        schema_id=None,
        limits=limits,
    )
    bad_entry = replace(changed, schema_bytes=bad_bytes, schema_ref=bad_ref)
    bad_registry = replace(registry, entries=registry.entries + (bad_entry,))
    with pytest.raises(ConfigurationError) as refused:
        seal(
            native.schema_bytes,
            schema_id=uri,
            registry=bad_registry,
            resolver=_FileResolver(population),
            limits=limits,
        )
    assert asdict(refused.value.reason) == {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": "/registry/entries/8/schema_dependencies",
        "detail": "Invalid local configuration.",
    }
    recovered = seal(
        native.schema_bytes,
        schema_id=uri,
        registry=complete,
        resolver=_FileResolver(population),
        limits=limits,
    )
    assert recovered == baseline
