# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected static dependency source validation

"""Exercise real official schema resources and exact dependency pins through public seal."""

import json
from dataclasses import asdict, replace
from importlib.resources import files
from pathlib import Path

import pytest
from tests.domain.test_verification_report_sources import _FileResolver, _object, _registry

from evidence_manifest_toolkit import (
    ConfigurationError,
    Limits,
    RegistryEntry,
    SchemaDependency,
    reference_bytes,
    seal,
)


def test_complete_official_dependency_length_refusal_and_whole_content_recovery() -> None:
    """Check the actual cached resource length rather than trusting a repeated digest alone.

    Notes
    -----
    All eight added schemas are complete original official Draft2020-12 resources.
    The full original native manifest schema is construction content. The augmented
    caller catalogue is unqualified; no snapshot authentication, signature, Clock or
    domain acceptance is claimed by unsigned construction.
    """
    root = Path(__file__).resolve().parents[2]
    source = _object(
        json.loads(
            (
                root
                / "tests/domain/fixtures/evidence-command-sources/verify-current-whole-fixture.json"
            ).read_bytes()
        )
    )
    inputs = _object(source["complete_library_inputs"])
    original = _registry(inputs["registry"])
    limits = Limits(4194304, 4194304, 67108864, 2048, 32, 96)
    resources = files("jsonschema_specifications").joinpath("schemas/draft202012")
    names = (
        "core",
        "applicator",
        "unevaluated",
        "validation",
        "meta-data",
        "format-annotation",
        "content",
    )
    raw_sources = {"metaschema.json": resources.joinpath("metaschema.json").read_bytes()}
    raw_sources.update(
        {name: resources.joinpath("vocabularies", name).read_bytes() for name in names}
    )
    entries: list[RegistryEntry] = []
    for raw in raw_sources.values():
        document = _object(json.loads(raw))
        identifier = document["$id"]
        assert isinstance(identifier, str)
        reference = reference_bytes(
            raw,
            media_type="application/schema+json",
            digest_basis="raw_bytes",
            schema_id=None,
            limits=limits,
        )
        entries.append(
            RegistryEntry(
                identifier,
                "JSON Schema",
                reference,
                raw,
                "application/schema+json",
                "raw_bytes",
                (),
                "evidence_manifest_toolkit.common_json.v1",
                "domain_support",
                "evidence_manifest_toolkit.declared_refs.v1",
                (),
                "required_unqualified",
                None,
                None,
            )
        )
    dependencies = tuple(
        SchemaDependency(entry.schema_id, entry.schema_ref) for entry in entries[1:]
    )
    main = replace(entries[0], schema_dependencies=dependencies)
    complete = replace(original, entries=original.entries + (main,) + tuple(entries[1:]))
    content_path = root / "src/evidence_manifest_toolkit/_schemas/manifest.json"
    content = content_path.read_bytes()
    resolver = _FileResolver({})
    baseline = seal(
        content, schema_id=main.schema_id, registry=complete, resolver=resolver, limits=limits
    )
    assert json.loads(baseline.canonical_content) == json.loads(content)
    assert baseline.envelope_json is None
    dependency = dependencies[0]
    wrong = replace(
        dependency,
        schema_ref=replace(
            dependency.schema_ref, byte_length=str(int(dependency.schema_ref.byte_length) + 1)
        ),
    )
    altered = replace(main, schema_dependencies=(wrong,) + dependencies[1:])
    supplied = replace(complete, entries=original.entries + (altered,) + tuple(entries[1:]))
    with pytest.raises(ConfigurationError) as caught:
        seal(content, schema_id=main.schema_id, registry=supplied, resolver=resolver, limits=limits)
    assert asdict(caught.value.reason) == {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": "/registry/entries/8/schema_dependencies/0/schema_ref",
        "detail": "Invalid local configuration.",
    }
    recovered = seal(
        content, schema_id=main.schema_id, registry=complete, resolver=resolver, limits=limits
    )
    assert recovered == baseline and not resolver.calls
    assert content_path.read_bytes() == content
    assert all(
        resources.joinpath(
            "metaschema.json" if name == "metaschema.json" else "vocabularies/" + name
        ).read_bytes()
        == raw
        for name, raw in raw_sources.items()
    )
