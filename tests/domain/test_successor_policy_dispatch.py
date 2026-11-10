# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — real caller-policy dispatch before authority acquisition

"""Exercise complete V2 policy selection through the public verifier without fake authority."""

import hashlib
import json
from dataclasses import asdict, replace
from importlib.resources import files
from pathlib import Path
from typing import Literal, cast

import pytest
from tests.domain.test_cli_evidence_sources import _source, _transport
from tests.domain.test_policy_selection_sources import _successor_policy
from tests.domain.test_successor_trust import _callers, _sources
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
    ConfigurationError,
    DelegatedTrustContextV2,
    InputRefused,
    Limits,
    ReferenceUnavailable,
    SchemaRegistry,
    TrustContext,
    Utc,
    VerificationPolicy,
    reference_bytes,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"


@pytest.mark.parametrize("profile_index", (0, 1, 2))
@pytest.mark.parametrize("mode", ("current", "historical"))
def test_whole_successor_policy_dispatch_precedes_authority_and_legacy_recovery(
    profile_index: int, mode: Literal["current", "historical"], tmp_path: Path
) -> None:
    """Retain exact class/policy errors, missing original arguments and whole recovery.

    Parameters
    ----------
    profile_index : int
        Original explicit unsigned, software or delegated caller class.
    mode : {"current", "historical"}
        Complete caller scope, including its required class-specific archive.
    tmp_path : Path
        Actual independently selected policy carrier and reversible missing-source files.

    Notes
    -----
    Original objects are carrier declarations only. No Clock, authority, identity or
    successful V2 method qualification is asserted by these policy-boundary cases.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    bounds = _object(inputs["limits"])
    limits = Limits(**cast(dict[str, int], bounds))
    registry = _registry(inputs["registry"])
    declared = _object(inputs["policy"])
    ordinary = VerificationPolicy(
        BlobRef.from_mapping(_object(declared["policy_ref"])),
        tuple(_text(x) for x in _array(declared["required_claim_ids"])),
        ("evidence",),
    )
    population: dict[str, Path] = {}
    originals: dict[Path, bytes] = {}
    for key, item in _object(inputs["resolver_input_population"]).items():
        row = _object(item)
        path = _FIXTURES / "objects" / _text(row["sha256"])
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
        assert len(raw) == row["byte_length"]
        population[key] = path
        originals[path] = raw
    binding, references, carrier_originals = _sources()
    originals.update(carrier_originals)
    callers = _callers(binding, references, mode)
    caller = callers[profile_index]
    value = _successor_policy(ordinary.policy_ref)
    value["profile_class"] = caller.profile_class
    if profile_index:
        value["authority_rule_ref"] = dict(ordinary.policy_ref.to_mapping())
    if isinstance(caller, DelegatedTrustContextV2):
        value["root_grant_ref"] = dict(caller.root_grant_ref.to_mapping())
    raw = _transport(value)
    path = tmp_path / "whole-successor-policy.json"
    path.write_bytes(raw)
    reference = reference_bytes(
        raw,
        media_type="application/json",
        digest_basis="raw_bytes",
        schema_id="evidence_manifest_toolkit.authority_policy.v2",
        limits=limits,
    )
    selected = VerificationPolicy(
        reference, ordinary.required_claim_ids, ordinary.required_purposes
    )
    population[reference.digest + "|raw_bytes"] = path
    content = _bytes(inputs["content_json"])
    schema = _text(inputs["schema_id"])
    for policy, chosen, pointer, acquired in (
        (ordinary, caller, "/policy_ref", (ordinary.policy_ref,)),
        (selected, callers[(profile_index + 1) % 3], "/profile_class", (reference,)),
        (selected, caller, "/whole_legacy_artifact_policy_ref", (reference, ordinary.policy_ref)),
    ):
        resolver = _FileResolver(population)
        with pytest.raises(ConfigurationError) as caught:
            verify(
                content,
                schema_id=schema,
                envelopes=(),
                registry=registry,
                resolver=resolver,
                limits=limits,
                policy=policy,
                trust=chosen,
            )
        assert asdict(caught.value.reason) == {
            "code": "configuration_error",
            "subject_digest": policy.policy_ref.digest,
            "claim_id": None,
            "pointer": pointer,
            "detail": "Invalid local trust or policy configuration.",
        }
        assert tuple(argument for argument, _ in resolver.calls) == acquired
    for missing in (reference, ordinary.policy_ref):
        key = missing.digest + "|" + missing.digest_basis
        original_path = population[key]
        missing_path = tmp_path / "missing-selected-source.json"
        missing_path.write_bytes(original_path.read_bytes())
        missing_path.unlink()
        resolver = _FileResolver({**population, key: missing_path})
        with pytest.raises(ReferenceUnavailable) as absent:
            verify(
                content,
                schema_id=schema,
                envelopes=(),
                registry=registry,
                resolver=resolver,
                limits=limits,
                policy=selected,
                trust=caller,
            )
        assert absent.value.reference == missing
        assert tuple(argument for argument, _ in resolver.calls) == (
            (reference,) if missing == reference else (reference, ordinary.policy_ref)
        )
    for corrupt in (reference, ordinary.policy_ref):
        original_path = population[corrupt.digest + "|" + corrupt.digest_basis]
        broken = original_path.read_bytes().rstrip()[:-1]
        broken_path = tmp_path / "incomplete-whole-policy.json"
        broken_path.write_bytes(broken)
        broken_ref = reference_bytes(
            broken,
            media_type=corrupt.media_type,
            digest_basis="raw_bytes",
            schema_id=corrupt.schema_id,
            limits=limits,
        )
        lookup = {**population, broken_ref.digest + "|raw_bytes": broken_path}
        if corrupt == reference:
            chosen_ref = broken_ref
            acquired = (broken_ref,)
        else:
            enclosing = _transport(
                {**value, "whole_legacy_artifact_policy_ref": dict(broken_ref.to_mapping())}
            )
            enclosing_path = tmp_path / "whole-policy-with-incomplete-source.json"
            enclosing_path.write_bytes(enclosing)
            chosen_ref = reference_bytes(
                enclosing,
                media_type="application/json",
                digest_basis="raw_bytes",
                schema_id=reference.schema_id,
                limits=limits,
            )
            lookup[chosen_ref.digest + "|raw_bytes"] = enclosing_path
            acquired = (chosen_ref, broken_ref)
        resolver = _FileResolver(lookup)
        with pytest.raises(InputRefused) as malformed:
            verify(
                content,
                schema_id=schema,
                envelopes=(),
                registry=registry,
                resolver=resolver,
                limits=limits,
                policy=VerificationPolicy(chosen_ref, ordinary.required_claim_ids, ("evidence",)),
                trust=caller,
            )
        assert asdict(malformed.value.reason) == {
            "code": "invalid_json",
            "subject_digest": broken_ref.digest,
            "claim_id": None,
            "pointer": "",
            "detail": "Input is not valid strict JSON.",
        }
        assert tuple(argument for argument, _ in resolver.calls) == acquired
        assert broken_path.read_bytes() == broken
    legacy = _object(inputs["trust"])
    trust = TrustContext(
        BlobRef.from_mapping(_object(legacy["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(legacy["current_snapshot_ref"])),
        _text(legacy["accepted_sequence_floor"]),
        "current",
        Utc(legacy["evaluation_time"]),
        tuple(_bytes(x) for x in _array(legacy["control_envelopes"])),
        _optional_reference(legacy.get("archived_snapshot_ref")),
    )
    recovered = verify(
        content,
        schema_id=schema,
        envelopes=tuple(_bytes(x) for x in _array(inputs["envelopes"])),
        registry=registry,
        resolver=_FileResolver(population),
        limits=limits,
        policy=ordinary,
        trust=trust,
    )
    assert _mapping(recovered) == source["expected_entire_VerificationReport"]
    assert path.read_bytes() == raw
    assert all(path.read_bytes() == original for path, original in originals.items())


@pytest.mark.parametrize(
    "case",
    (
        "control_purpose",
        "unsigned_receipts",
        "grant_pair",
        "reserved_registry",
        "legacy_missing_policy",
    ),
)
def test_public_policy_class_boundaries_preserve_original_sources(
    case: str, tmp_path: Path
) -> None:
    """Refuse incompatible ordinary policy selections before any stronger source acquisition.

    Parameters
    ----------
    case : str
        Original control purpose, forbidden unsigned receipt, whole grant/registry conflict
        or absent independently selected legacy policy.
    tmp_path : Path
        Owned whole input sources and exact intentionally unavailable lookup target.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    declaration = _object(inputs["policy"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    registry = _registry(inputs["registry"])
    original_ref = BlobRef.from_mapping(_object(declaration["policy_ref"]))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    originals = {path: path.read_bytes() for path in population.values()}
    binding, references, carriers = _sources()
    originals.update(carriers)
    caller = _callers(binding, references, "current")[2 if case == "grant_pair" else 0]
    value = _successor_policy(original_ref)
    value["profile_class"] = caller.profile_class
    if isinstance(caller, DelegatedTrustContextV2):
        value["authority_rule_ref"] = dict(original_ref.to_mapping())
        value["root_grant_ref"] = dict(caller.current_authority_snapshot_ref.to_mapping())
    raw = _transport(value)
    path = tmp_path / "selected-whole-policy.json"
    path.write_bytes(raw)
    selected = reference_bytes(
        raw,
        media_type="application/json",
        digest_basis="raw_bytes",
        schema_id="evidence_manifest_toolkit.authority_policy.v2",
        limits=limits,
    )
    population[selected.digest + "|raw_bytes"] = path
    policy = VerificationPolicy(
        selected,
        tuple(_text(x) for x in _array(declaration["required_claim_ids"])),
        ("group_certificate",) if case == "control_purpose" else ("evidence",),
    )
    envelopes = (
        tuple(_bytes(x) for x in _array(inputs["envelopes"]))
        if case in {"unsigned_receipts", "legacy_missing_policy"}
        else ()
    )
    pointer = (
        "/required_purposes"
        if case == "control_purpose"
        else "/envelopes"
        if case == "unsigned_receipts"
        else "/root_grant_ref"
        if case == "grant_pair"
        else "/registry/entries"
    )
    if case == "reserved_registry":
        resource = _object(
            json.loads(
                files("evidence_manifest_toolkit")
                .joinpath("_schemas/successor_authority.json")
                .read_bytes()
            )
        )
        definitions = _object(resource["$defs"])
        identifier = "evidence_manifest_toolkit.identity_binding.v2"
        native = {
            **_object(definitions["identity_binding"]),
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": identifier,
            "$defs": definitions,
        }
        schema = _transport(native)
        entry = replace(
            registry.entries[0],
            schema_id=identifier,
            owner="EVIDENCE-MANIFEST-TOOLKIT",
            schema_ref=reference_bytes(
                schema,
                media_type="application/schema+json",
                digest_basis="raw_bytes",
                schema_id=None,
                limits=limits,
            ),
            schema_bytes=schema,
            reference_paths=(),
            common_semantics_id="evidence_manifest_toolkit.common_json.v1",
            schema_role="domain_evidence",
            schema_dependencies=(),
            domain_support="required_unqualified",
            domain_verifier_ref=None,
            domain_qualification_ref=None,
        )
        registry = SchemaRegistry(registry.snapshot_ref, (*registry.entries, entry))
    resolver = _FileResolver(population)
    if case == "legacy_missing_policy":
        legacy = _object(inputs["trust"])
        trusted = TrustContext(
            BlobRef.from_mapping(_object(legacy["bootstrap_policy_ref"])),
            BlobRef.from_mapping(_object(legacy["current_snapshot_ref"])),
            _text(legacy["accepted_sequence_floor"]),
            "current",
            Utc(legacy["evaluation_time"]),
            tuple(_bytes(x) for x in _array(legacy["control_envelopes"])),
            _optional_reference(legacy.get("archived_snapshot_ref")),
        )
        missing = tmp_path / "absent-original-policy.json"
        resolver = _FileResolver({**population, original_ref.digest + "|raw_bytes": missing})
        report = verify(
            _bytes(inputs["content_json"]),
            schema_id=_text(inputs["schema_id"]),
            envelopes=envelopes,
            registry=registry,
            resolver=resolver,
            limits=limits,
            policy=replace(policy, policy_ref=original_ref),
            trust=trusted,
        )
        observed = _object(_mapping(report))
        expected = _object(source["expected_entire_VerificationReport"])
        assert observed.keys() == expected.keys() and len(observed) == 15
        for field in (
            "content_ref",
            "policy_ref",
            "registry_ref",
            "evaluation_mode",
            "evaluation_time",
            "evaluated_claim_ids",
            "structure",
            "domain_verdict",
        ):
            assert observed[field] == expected[field]
        assert report.common_eligibility == report.current_eligibility == "refused"
        assert {reason.code for reason in report.reasons} >= {
            "reference_unavailable",
            "policy_unavailable",
        }
        assert resolver.calls[0][0] == original_ref
    else:
        with pytest.raises(ConfigurationError) as caught:
            verify(
                _bytes(inputs["content_json"]),
                schema_id=_text(inputs["schema_id"]),
                envelopes=envelopes,
                registry=registry,
                resolver=resolver,
                limits=limits,
                policy=policy,
                trust=caller,
            )
        assert asdict(caught.value.reason) == {
            "code": "configuration_error",
            "subject_digest": selected.digest,
            "claim_id": None,
            "pointer": pointer,
            "detail": "Invalid local trust or policy configuration.",
        }
        assert tuple(reference for reference, _ in resolver.calls) == (selected,)
    assert path.read_bytes() == raw
    assert all(path.read_bytes() == raw for path, raw in originals.items())
