# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — portable original public verification reports

"""Compare entire original reports through public values and an actual bounded file resolver."""

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Literal, cast

import pytest

from evidence_manifest_toolkit import (
    BlobRef,
    DigestBasis,
    InputRefused,
    Limits,
    Reason,
    ReferencePath,
    ReferenceUnavailable,
    RegistryEntry,
    SchemaDependency,
    SchemaRegistry,
    TrustContext,
    Utc,
    VerificationPolicy,
    verify,
)

type _Wire = None | bool | int | float | str | list[_Wire] | dict[str, _Wire]
type _OptionalRule = Literal["schema_optional", "refuse"]
type _Role = Literal[
    "common_control", "common_evidence", "domain_evidence", "domain_verification", "domain_support"
]
type _Domain = Literal["not_required", "required_unqualified", "required_qualified"]
_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_CASES = (
    "verify-current-whole-fixture",
    "verify-historical-whole-fixture",
    "verify-required-signature-absent",
    "verify-narrow-claim-scope",
    "verify-required-evaluation-time-qualification-absent",
    "verify-required-environment-unavailable",
    "verify-required-environment-mismatch",
    "verify-current-expiry-endpoint",
    "verify-current-floor-rollback",
)


def _object(value: object) -> dict[str, object]:
    """Retain the complete fixed fixture mapping without coercion or field projection."""
    assert isinstance(value, dict) and all(isinstance(key, str) for key in value)
    return dict(value)


def _text(value: object) -> str:
    """Retain an actual fixture string."""
    assert isinstance(value, str)
    return value


def _array(value: object) -> list[object]:
    """Retain the complete original fixture array and its source order."""
    assert isinstance(value, list)
    return list(value)


def _bytes(value: object) -> bytes:
    """Decode only the independently fixed fixture's original Base64URL representation."""
    token = _text(value)
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))


def _optional_reference(value: object) -> BlobRef | None:
    """Construct the public declaration from actual source fields without inventing metadata."""
    return None if value is None else BlobRef.from_mapping(_object(value))


def _registry(value: object) -> SchemaRegistry:
    """Construct all fourteen public entry fields from the complete fixed registry source."""
    root = _object(value)
    entries: list[RegistryEntry] = []
    for member in _array(root["entries"]):
        entry = _object(member)
        assert len(entry) == 14
        paths: list[ReferencePath] = []
        for declaration in _array(entry["reference_paths"]):
            path = _object(declaration)
            steps = tuple(
                {key: _text(item) for key, item in _object(step).items()}
                for step in _array(path["steps"])
            )
            paths.append(
                ReferencePath(
                    _text(path["path_id"]),
                    steps,
                    cast(_OptionalRule, _text(path["absent"])),
                    cast(_OptionalRule, _text(path["null"])),
                    cast(Literal["when_present", "policy_optional"], _text(path["requirement"])),
                )
            )
        dependencies = tuple(
            SchemaDependency(
                _text(_object(dependency)["uri"]),
                BlobRef.from_mapping(_object(_object(dependency)["schema_ref"])),
            )
            for dependency in _array(entry["schema_dependencies"])
        )
        entries.append(
            RegistryEntry(
                schema_id=_text(entry["schema_id"]),
                owner=_text(entry["owner"]),
                schema_ref=BlobRef.from_mapping(_object(entry["schema_ref"])),
                schema_bytes=_bytes(entry["schema_bytes"]),
                media_type=_text(entry["media_type"]),
                digest_basis=cast(DigestBasis, _text(entry["digest_basis"])),
                reference_paths=tuple(paths),
                common_semantics_id=_text(entry["common_semantics_id"]),
                schema_role=cast(_Role, _text(entry["schema_role"])),
                closure_profile_id=_text(entry["closure_profile_id"]),
                schema_dependencies=dependencies,
                domain_support=cast(_Domain, _text(entry["domain_support"])),
                domain_verifier_ref=_optional_reference(entry["domain_verifier_ref"]),
                domain_qualification_ref=_optional_reference(entry["domain_qualification_ref"]),
            )
        )
    return SchemaRegistry(BlobRef.from_mapping(_object(root["snapshot_ref"])), tuple(entries))


def _mapping(value: object) -> _Wire:
    """Observe every public result field, preserving tuples, nulls and optional reference spelling."""
    if isinstance(value, BlobRef):
        return dict(value.to_mapping())
    if isinstance(value, bytes):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _mapping(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        assert all(isinstance(key, str) for key in value)
        return {_text(key): _mapping(member) for key, member in value.items()}
    if isinstance(value, (tuple, list)):
        return [_mapping(member) for member in value]
    assert value is None or isinstance(value, (bool, int, float, str))
    return value


class _FileResolver:
    """Supply actual fixed files through both original bounded public Resolver methods.

    Parameters
    ----------
    population : dict
        Exact original digest/basis lookup population with real materialized overrides.
    """

    def __init__(self, population: dict[str, Path]) -> None:
        """Retain actual caller-selected files without accepting their declared identities."""
        self.population = population
        self.calls: list[tuple[BlobRef | str, int]] = []

    def _read(self, key: str, argument: BlobRef | str, maximum: int) -> bytes:
        """Acquire actual bytes within the caller cap and preserve the exact missing argument."""
        self.calls.append((argument, maximum))
        assert type(maximum) is int and maximum > 0
        path = self.population.get(key)
        if path is None:
            raise ReferenceUnavailable(argument)
        try:
            with path.open("rb") as handle:
                data = handle.read(maximum + 1)
        except FileNotFoundError:
            raise ReferenceUnavailable(argument) from None
        if len(data) > maximum:
            raise InputRefused(
                Reason("limit_exceeded", None, None, None, "Reference acquisition bound exceeded.")
            )
        return data

    def resolve(self, reference: BlobRef, *, max_bytes: int) -> bytes:
        """Read the actual original full-reference file under the given bound."""
        return self._read(reference.digest + "|" + reference.digest_basis, reference, max_bytes)

    def resolve_digest(self, digest: str, *, max_bytes: int) -> bytes:
        """Read only the actual native digest target, retaining digest-only missing form."""
        return self._read(digest + "|jcs_content", digest, max_bytes)


@pytest.mark.parametrize("case", _CASES)
def test_original_whole_public_verify_report_and_immutable_sources(
    case: str, tmp_path: Path
) -> None:
    """Compare all original fifteen fields through genuine root verify and public caller values.

    Parameters
    ----------
    case : str
        Complete independently prepared original input and report oracle, pinned before calls.
    tmp_path : Path
        Owned real file for any exact wrong-byte override; original corpus stays unchanged.

    Notes
    -----
    These are conditional fixture computational/source comparisons. The test does not supply
    independent fixture admission, qualified Clock, operational signer or scientific acceptance.
    """
    source_path = _FIXTURES / (case + ".json")
    source_bytes = source_path.read_bytes()
    pins = _array(
        _object(json.loads((_FIXTURES / "source-pins.json").read_bytes()))["original_cases"]
    )
    selected = next(_object(member) for member in pins if _object(member)["case_id"] == case)
    assert hashlib.sha256(source_bytes).hexdigest() == selected["source_sha256"]
    source = _object(json.loads(source_bytes))
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    assert _mapping(registry) == inputs["registry"]
    population: dict[str, Path] = {}
    for key, declaration in _object(inputs["resolver_input_population"]).items():
        record = _object(declaration)
        path = _FIXTURES / "objects" / _text(record["sha256"])
        data = path.read_bytes()
        assert (
            hashlib.sha256(data).hexdigest() == record["sha256"]
            and len(data) == record["byte_length"]
        )
        population[key] = path
    original_paths = set(population.values()) | {source_path}
    for key, value in _object(inputs.get("resolver_overrides", {})).items():
        override = _object(value)
        if override["mode"] == "missing":
            population.pop(key)
        else:
            assert override["mode"] == "exact_wrong_bytes"
            path = tmp_path / "actual-wrong-bytes"
            path.write_bytes(_bytes(override["returned_bytes_base64url"]))
            population[key] = path
    preserved = original_paths | set(population.values())
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in preserved}
    bounds = _object(inputs["limits"])
    assert all(type(value) is int for value in bounds.values())
    limits = Limits(**cast(dict[str, int], bounds))
    local = _object(inputs["trust"])
    mode = _text(local["evaluation_mode"])
    assert mode in {"current", "historical"}
    trust = TrustContext(
        BlobRef.from_mapping(_object(local["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(local["current_snapshot_ref"])),
        _text(local["accepted_sequence_floor"]),
        cast(Literal["current", "historical"], mode),
        Utc(local["evaluation_time"]),
        tuple(_bytes(member) for member in _array(local["control_envelopes"])),
        _optional_reference(local.get("archived_snapshot_ref")),
    )
    expected_trust = dict(local)
    expected_trust.setdefault("archived_snapshot_ref", None)
    assert _mapping(trust) == expected_trust
    declaration = _object(inputs["policy"])
    assert declaration["required_reference_paths"] == [] and declaration["required_purposes"] == [
        "evidence"
    ]
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(declaration["policy_ref"])),
        tuple(_text(value) for value in _array(declaration["required_claim_ids"])),
        ("evidence",),
    )
    assert _mapping(policy) == declaration
    resolver = _FileResolver(population)
    result = verify(
        _bytes(inputs["content_json"]),
        schema_id=_text(inputs["schema_id"]),
        envelopes=tuple(_bytes(value) for value in _array(inputs["envelopes"])),
        registry=registry,
        resolver=resolver,
        limits=limits,
        policy=policy,
        trust=trust,
    )
    assert _mapping(result) == source["expected_entire_VerificationReport"]
    assert resolver.calls
    assert before == {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in preserved
    }
