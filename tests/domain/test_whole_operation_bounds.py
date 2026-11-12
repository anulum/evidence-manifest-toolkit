# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — construction and verification at the bounds of a whole operation

"""Exhaust document size and depth, single-object size, count and graph depth with whole fixtures."""

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, replace
from importlib.resources import files
from pathlib import Path
from typing import cast

import pytest
from tests.domain.test_cli_evidence_sources import _source
from tests.domain.test_public_operation_surface import (
    _sealing_arguments,
    _verification_arguments,
)
from tests.domain.test_verification_report_sources import (
    _array,
    _FileResolver,
    _mapping,
    _object,
)

from evidence_manifest_toolkit import (
    BlobRef,
    InputRefused,
    Limits,
    RegistryEntry,
    SchemaDependency,
    SchemaRegistry,
    SealResult,
    TrustContext,
    VerificationPolicy,
    VerificationReport,
    reference_bytes,
    seal,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_LIMITS = Limits(1048576, 1048576, 16777216, 1024, 32, 64)
_PADDED_LENGTH = 262144
# The deepest schema of the fixtures' registry has 14 levels, so 14 is the smallest depth bound under
# which the registry is acquired at all; each depth test first shows that the fixture completes there.
_REGISTRY_DEPTH = 14
# The fixtures' keyword arguments are held as one mapping of whole original values; the two
# operations are called through them unchanged.
_seal = cast(Callable[..., SealResult], seal)
_verify = cast(Callable[..., VerificationReport], verify)
_REFUSED = {
    "code": "limit_exceeded",
    "subject_digest": None,
    "claim_id": None,
    "pointer": None,
    "detail": "JSON input refused.",
}


def _padded(content: bytes) -> bytes:
    """Return the same JSON document followed by white space up to a fixed length.

    Parameters
    ----------
    content : bytes
        The whole original content of a fixture.

    Returns
    -------
    bytes
        A document of 262144 bytes with the same canonical form: longer than every schema
        of the registry and every object of the fixture, so that it alone meets the bound.
    """
    assert len(content) < _PADDED_LENGTH
    return content + b" " * (_PADDED_LENGTH - len(content))


def test_construction_refuses_content_one_byte_over_the_document_bound() -> None:
    """The registry fits the bound, the content does not; on the bound the original result returns."""
    content, keywords, _ = _sealing_arguments()
    padded = _padded(content)
    with pytest.raises(InputRefused) as caught:
        _seal(padded, limits=replace(_LIMITS, max_json_bytes=_PADDED_LENGTH - 1), **keywords)
    assert asdict(caught.value.reason) == _REFUSED
    packet = _object(json.loads((_FIXTURES / "seal-unsigned-whole-fixture.json").read_bytes()))
    _, keywords, _ = _sealing_arguments()
    completed = _seal(padded, limits=replace(_LIMITS, max_json_bytes=_PADDED_LENGTH), **keywords)
    assert completed.canonical_content == content
    assert _mapping(completed) == packet["expected_entire_SealResult"]


def test_verification_refuses_content_one_byte_over_the_document_bound() -> None:
    """The same bound through verification: a thrown refusal, then the whole original report."""
    content, keywords, _ = _verification_arguments()
    padded = _padded(content)
    with pytest.raises(InputRefused) as caught:
        _verify(padded, limits=replace(_LIMITS, max_json_bytes=_PADDED_LENGTH - 1), **keywords)
    assert asdict(caught.value.reason) == _REFUSED
    expected = _source("verify-current-whole-fixture")["expected_entire_VerificationReport"]
    _, keywords, _ = _verification_arguments()
    completed = _verify(padded, limits=replace(_LIMITS, max_json_bytes=_PADDED_LENGTH), **keywords)
    assert _mapping(completed) == expected


@pytest.mark.parametrize("operation", ("seal", "verify"))
def test_a_registry_schema_one_byte_over_the_single_object_bound_is_refused_before_any_read(
    operation: str,
) -> None:
    """The first schema of the registry meets the bound first, and no object is read.

    Parameters
    ----------
    operation : str
        Construction or verification; both acquire the registry under the same budget.

    Notes
    -----
    Every schema of the fixture's registry is larger than every object its content
    references, so with an honest resolver this is where the single-object bound is met.
    """
    content, keywords, resolver = (
        _sealing_arguments() if operation == "seal" else _verification_arguments()
    )
    registry = keywords["registry"]
    assert isinstance(registry, SchemaRegistry)
    first = len(registry.entries[0].schema_bytes)
    call = _seal if operation == "seal" else _verify
    with pytest.raises(InputRefused) as caught:
        call(content, limits=replace(_LIMITS, max_blob_bytes=first - 1), **keywords)
    assert asdict(caught.value.reason) == {
        "code": "limit_exceeded",
        "subject_digest": registry.snapshot_ref.digest,
        "claim_id": None,
        "pointer": "/registry/entries/0/schema_bytes",
        "detail": "Reference acquisition bound exceeded.",
    }
    assert resolver.calls == []


def _nested(depth: int) -> bytes:
    """Return empty arrays inside each other, a canonical document of exactly that depth.

    Parameters
    ----------
    depth : int
        The number of arrays.

    Returns
    -------
    bytes
        Canonical JSON that no schema of the fixtures admits as a manifest.
    """
    return b"[" * depth + b"]" * depth


def _identity(reference: BlobRef) -> tuple[str, str, str]:
    """Return what the shared budget counts once: digest, digest basis and byte length.

    Parameters
    ----------
    reference : BlobRef
        A complete reference.

    Returns
    -------
    tuple
        The three fields that identify acquired bytes.
    """
    return reference.digest, reference.digest_basis, reference.byte_length


def test_construction_refuses_content_one_level_over_the_depth_bound() -> None:
    """Under a bound the registry fits, content one level deeper is refused for its depth alone."""
    content, keywords, _ = _sealing_arguments()
    packet = _object(json.loads((_FIXTURES / "seal-unsigned-whole-fixture.json").read_bytes()))
    admissible = replace(_LIMITS, max_json_depth=_REGISTRY_DEPTH)
    assert (
        _mapping(_seal(content, limits=admissible, **keywords))
        == packet["expected_entire_SealResult"]
    )
    deeper = _nested(_REGISTRY_DEPTH + 1)
    _, keywords, resolver = _sealing_arguments()
    with pytest.raises(InputRefused) as caught:
        _seal(deeper, limits=admissible, **keywords)
    assert asdict(caught.value.reason) == _REFUSED
    assert resolver.calls == []
    _, keywords, resolver = _sealing_arguments()
    with pytest.raises(InputRefused) as caught:
        _seal(deeper, limits=replace(_LIMITS, max_json_depth=_REGISTRY_DEPTH + 1), **keywords)
    assert asdict(caught.value.reason) == {
        "code": "invalid_schema",
        "subject_digest": "sha256:" + hashlib.sha256(deeper).hexdigest(),
        "claim_id": None,
        "pointer": "",
        "detail": "Input violates its selected schema.",
    }
    assert resolver.calls == []


def test_verification_refuses_content_one_level_over_the_depth_bound() -> None:
    """The same bound through verification: thrown one level over it, a whole report on it.

    Notes
    -----
    The policy is read before the content is parsed, so the refusal follows exactly one
    read. On the bound the content is identified and its schema refuses it inside the
    report; no object the content could name is read.
    """
    content, keywords, _ = _verification_arguments()
    expected = _source("verify-current-whole-fixture")["expected_entire_VerificationReport"]
    admissible = replace(_LIMITS, max_json_depth=_REGISTRY_DEPTH)
    assert _mapping(_verify(content, limits=admissible, **keywords)) == expected
    deeper = _nested(_REGISTRY_DEPTH + 1)
    _, keywords, resolver = _verification_arguments()
    policy = keywords["policy"]
    assert isinstance(policy, VerificationPolicy)
    with pytest.raises(InputRefused) as caught:
        _verify(deeper, limits=admissible, **keywords)
    assert asdict(caught.value.reason) == _REFUSED
    assert [reference for reference, _ in resolver.calls] == [policy.policy_ref]
    _, keywords, resolver = _verification_arguments()
    report = _object(
        _mapping(
            _verify(deeper, limits=replace(_LIMITS, max_json_depth=_REGISTRY_DEPTH + 1), **keywords)
        )
    )
    digest = "sha256:" + hashlib.sha256(deeper).hexdigest()
    assert report["content_ref"] == {
        "digest": digest,
        "byte_length": str(len(deeper)),
        "media_type": "application/json",
        "digest_basis": "jcs_content",
        "schema_id": keywords["schema_id"],
    }
    assert report["structure"] == "invalid"
    assert _array(report["reasons"])[0] == {
        "code": "invalid_schema",
        "subject_digest": digest,
        "claim_id": None,
        "pointer": "",
        "detail": "Input violates its selected schema.",
    }
    original = {
        _object(_object(row)["reference"])["digest"]
        for row in _array(_object(expected)["reference_observations"])
        if _object(row)["subject_digest"] == _object(_object(expected)["content_ref"])["digest"]
        and _object(row)["reference"] is not None
    }
    assert original
    assert not original & {
        reference.digest for reference, _ in resolver.calls if isinstance(reference, BlobRef)
    }


def test_verification_reports_an_exhausted_reference_count_and_completes_exactly_on_it() -> None:
    """One identity short, the last acquisition is reported as refused; on the count nothing is.

    Notes
    -----
    The shared budget counts every unique schema of the registry, every object the resolver
    returns and the content itself. The count the whole fixture needs is derived from the
    registry and from the reads of an unbounded run, and so is the reference that no longer
    fits: the last one that run acquired, found in the fixture's own expected observations.
    """
    content, keywords, resolver = _verification_arguments()
    expected = _object(
        _source("verify-current-whole-fixture")["expected_entire_VerificationReport"]
    )
    assert _mapping(_verify(content, limits=_LIMITS, **keywords)) == expected
    registry = keywords["registry"]
    assert isinstance(registry, SchemaRegistry)
    acquired = [reference for reference, _ in resolver.calls if isinstance(reference, BlobRef)]
    assert len(acquired) == len(resolver.calls)
    identities = {_identity(entry.schema_ref) for entry in registry.entries}
    identities |= {_identity(reference) for reference in acquired}
    needed = len(identities) + 1
    assert needed == 18
    _, keywords, _ = _verification_arguments()
    exact = replace(_LIMITS, max_reference_count=needed)
    assert _mapping(_verify(content, limits=exact, **keywords)) == expected
    last = acquired[-1]
    named = [
        _object(row)
        for row in _array(expected["reference_observations"])
        if _object(row)["reference"] is not None
        and _object(_object(row)["reference"])["digest"] == last.digest
    ]
    assert len(named) == 1
    reason = {
        "code": "limit_exceeded",
        "subject_digest": named[0]["subject_digest"],
        "claim_id": None,
        "pointer": named[0]["pointer"],
        "detail": "Reference count bound exceeded.",
    }
    _, keywords, short = _verification_arguments()
    report = _object(
        _mapping(
            _verify(content, limits=replace(_LIMITS, max_reference_count=needed - 1), **keywords)
        )
    )
    assert _array(report["reasons"])[0] == reason
    assert report["structure"] == "invalid"
    assert report["common_eligibility"] == "refused"
    assert [
        row
        for row in _array(report["reference_observations"])
        if _object(row)["subject_digest"] == named[0]["subject_digest"]
        and _object(row)["pointer"] == named[0]["pointer"]
    ] == [{**named[0], "outcome": "mismatched", "reasons": [reason]}]
    assert [reference for reference, _ in short.calls] == acquired[:-1]


def test_verification_reports_an_exhausted_graph_depth_and_completes_exactly_on_it() -> None:
    """With depth two the whole report returns; with depth one every object two edges away refuses.

    Notes
    -----
    The objects two edges from a root are taken from the fixture's own expected
    observations: what the content and the trust snapshot reference, and what those
    objects reference in turn. An object that is also one edge away is still refused where
    it is met two edges away.
    """
    content, keywords, _ = _verification_arguments()
    expected = _object(
        _source("verify-current-whole-fixture")["expected_entire_VerificationReport"]
    )
    exact = replace(_LIMITS, max_graph_depth=2)
    assert _mapping(_verify(content, limits=exact, **keywords)) == expected
    trust = keywords["trust"]
    assert isinstance(trust, TrustContext)
    edges: dict[str, set[str]] = {}
    for row in _array(expected["reference_observations"]):
        observation = _object(row)
        if observation["reference"] is not None:
            subject = observation["subject_digest"]
            assert isinstance(subject, str)
            target = _object(observation["reference"])["digest"]
            assert isinstance(target, str)
            edges.setdefault(subject, set()).add(target)
    manifest = _object(expected["content_ref"])["digest"]
    assert isinstance(manifest, str)
    roots = {manifest, trust.current_snapshot_ref.digest}
    first = set().union(*(edges[root] for root in roots))
    second = set().union(*(edges.get(digest, set()) for digest in first))
    assert len(first) == 6 and len(second) == 10
    _, keywords, _ = _verification_arguments()
    report = _object(
        _mapping(_verify(content, limits=replace(_LIMITS, max_graph_depth=1), **keywords))
    )
    too_deep = [
        _object(reason)
        for reason in _array(report["reasons"])
        if _object(reason)["detail"] == "Reference graph depth bound exceeded."
    ]
    assert {reason["subject_digest"] for reason in too_deep} == second
    assert all(
        reason
        == {
            "code": "limit_exceeded",
            "subject_digest": reason["subject_digest"],
            "claim_id": None,
            "pointer": None,
            "detail": "Reference graph depth bound exceeded.",
        }
        for reason in too_deep
    )
    assert len(too_deep) == len(second)
    assert report["structure"] == "invalid"
    assert report["common_eligibility"] == "refused"


def _official_entries() -> list[RegistryEntry]:
    """Return registry entries for the official Draft 2020-12 metaschema and its vocabularies.

    Returns
    -------
    list of RegistryEntry
        The metaschema first, then its seven vocabularies with core first, each with its
        whole original bytes and no declared dependency.
    """
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
    sources = [resources.joinpath("metaschema.json").read_bytes()]
    sources.extend(resources.joinpath("vocabularies", name).read_bytes() for name in names)
    entries: list[RegistryEntry] = []
    for raw in sources:
        identifier = _object(json.loads(raw))["$id"]
        assert isinstance(identifier, str)
        reference = reference_bytes(
            raw,
            media_type="application/schema+json",
            digest_basis="raw_bytes",
            schema_id=None,
            limits=_LIMITS,
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
    return entries


def test_construction_refuses_a_schema_dependency_one_edge_over_the_graph_depth() -> None:
    """A dependency of a dependency is two edges away: refused at depth one, complete at two.

    Notes
    -----
    The metaschema declares six of its vocabularies directly and the core vocabulary
    declares the seventh, so the same eight resources are reached, one of them only through
    another. With every vocabulary declared directly the same content seals at depth one,
    which shows that the refusal is of the nesting and of nothing else.
    """
    _, keywords, _ = _verification_arguments()
    original = keywords["registry"]
    assert isinstance(original, SchemaRegistry)
    entries = _official_entries()
    pins = [SchemaDependency(entry.schema_id, entry.schema_ref) for entry in entries[1:]]
    flat = replace(entries[0], schema_dependencies=tuple(pins))
    nested = replace(entries[0], schema_dependencies=(pins[0], *pins[2:]))
    core = replace(entries[1], schema_dependencies=(pins[1],))
    position = len(original.entries)
    content = (
        Path(__file__).resolve().parents[2] / "src/evidence_manifest_toolkit/_schemas/manifest.json"
    ).read_bytes()
    shallow = replace(_LIMITS, max_graph_depth=1)
    resolver = _FileResolver({})
    direct = replace(original, entries=(*original.entries, flat, *entries[1:]))
    baseline = _seal(
        content, schema_id=flat.schema_id, registry=direct, resolver=resolver, limits=shallow
    )
    assert json.loads(baseline.canonical_content) == json.loads(content)
    chained = replace(original, entries=(*original.entries, nested, core, *entries[2:]))
    with pytest.raises(InputRefused) as caught:
        _seal(
            content, schema_id=nested.schema_id, registry=chained, resolver=resolver, limits=shallow
        )
    assert asdict(caught.value.reason) == {
        "code": "limit_exceeded",
        "subject_digest": nested.schema_ref.digest,
        "claim_id": None,
        "pointer": f"/registry/entries/{position}/schema_dependencies",
        "detail": "Reference graph depth bound exceeded.",
    }
    completed = _seal(
        content,
        schema_id=nested.schema_id,
        registry=chained,
        resolver=resolver,
        limits=replace(_LIMITS, max_graph_depth=2),
    )
    assert completed == baseline
    assert resolver.calls == []
