# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit caller-owned raw protocol schema and method inputs

"""Declare exact raw method schemas for test callers without installing production identities."""

import base64
import copy
import json
from importlib.resources import files
from pathlib import Path
from typing import cast

from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import (
    _array,
    _FileResolver,
    _object,
    _registry,
    _text,
)

from evidence_manifest_toolkit import BlobRef, Limits, seal

PAYLOAD_KINDS = (
    "challenge",
    "issuer_issuance_observation",
    "receiver_completion_payload",
    "receiver_commit_payload",
)
PAYLOAD_IDS = {kind: "urn:gotm:fixture:native-possession:" + kind + ":1" for kind in PAYLOAD_KINDS}


def possession_registry_input(
    condition: str, inputs: dict[str, object], directory: Path
) -> dict[str, object]:
    """Bind exact installed subordinate definitions into an independent test caller registry.

    Parameters
    ----------
    condition : str
        Whole owning public workflow case, before the caller registry is frozen.
    inputs : dict
        Original complete public caller inputs, never a substituted runtime verifier.
    directory : Path
        Actual owned raw source store.

    Returns
    -------
    dict
        Whole original inputs or an explicit full test-owned registry successor. The
        four test-only metadata IDs are not Common-native IDs, private format tokens,
        producer adoption or native authority. Each schema uses the complete actual
        fixed definitions, not a permissive schema invented to clear a check.
    """
    case = condition.removeprefix("cli_").removeprefix("protected_")
    if not case.startswith("reproduction_possession_"):
        return inputs
    registry = copy.deepcopy(_object(inputs["registry"]))
    entries = _array(registry["entries"])
    source = _object(
        json.loads(
            files("evidence_manifest_toolkit")
            .joinpath("_schemas", "native_method_data.json")
            .read_bytes()
        )
    )
    definitions = _object(source["$defs"])
    for kind in PAYLOAD_KINDS:
        identifier = PAYLOAD_IDS[kind]
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": definitions,
            "$ref": "#/$defs/" + kind,
        }
        raw = json.dumps(schema, ensure_ascii=False, separators=(",", ":")).encode()
        reference = _native_source(raw, directory, "application/schema+json")
        paths = []
        for field, value in _object(_object(definitions[kind])["properties"]).items():
            rule = _object(value)
            if rule == {"$ref": "#/$defs/ref"} or "anyOf" in rule:
                paths.append(
                    {
                        "path_id": kind + ":" + field,
                        "steps": [{"kind": "member", "name": field}],
                        "absent": "schema_optional",
                        "null": "schema_optional",
                        "requirement": "when_present",
                    }
                )
        entries.append(
            {
                "schema_id": identifier,
                "owner": "EVIDENCE-MANIFEST-TOOLKIT-TEST-INPUTS",
                "schema_ref": dict(reference.to_mapping()),
                "schema_bytes": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
                "media_type": "application/schema+json",
                "digest_basis": "raw_bytes",
                "reference_paths": paths,
                "common_semantics_id": "evidence_manifest_toolkit.common_json.v1",
                "schema_role": "domain_support",
                "closure_profile_id": "evidence_manifest_toolkit.declared_refs.v1",
                "schema_dependencies": [],
                "domain_support": "required_unqualified",
                "domain_verifier_ref": None,
                "domain_qualification_ref": None,
            }
        )
    registry["entries"] = entries
    snapshot = _stored(
        {
            "schema_id": "evidence_manifest_toolkit.registry_snapshot.v1",
            "registry_revision": "2",
            "entries": entries,
        },
        directory,
        schema_id="evidence_manifest_toolkit.registry_snapshot.v1",
    )
    registry["snapshot_ref"] = dict(snapshot.to_mapping())
    return {**inputs, "registry": registry}


def possession_method_input(
    condition: str, rules: dict[str, object], directory: Path, *, conditions: BlobRef
) -> None:
    """Freeze complete unqualified issuer/receiver declarations before identity and challenge.

    Parameters
    ----------
    condition : str
        Exact original public possession case.
    rules : dict
        Entire independently selected identity and validation rules, updated before S0.
    directory : Path
        Actual owned raw source store.
    conditions : BlobRef
        Existing explicit unqualified-source disclosure; not a qualified controller.
    """
    if not condition.startswith("reproduction_possession_"):
        return

    def read(reference: object) -> dict[str, object]:
        """Read an entire previously frozen raw source."""
        ref = BlobRef.from_mapping(_object(reference))
        return _object(json.loads((directory / ref.digest[7:]).read_bytes()))

    identity = read(rules["identity_rule_ref"])
    method = read(identity["actual_key_possession_rule_ref"])
    ref = dict(conditions.to_mapping())
    common = {
        field: method[field]
        for field in (
            "method_version",
            "implementation_ref",
            "implementation_environment_ref",
            "implementation_qualification_ref",
            "semantic_law_ref",
        )
    }
    storage = {
        **common,
        "root_source_ref": ref,
        "head_location_ref": ref,
        "namespace_environment_ref": ref,
        "owner_identity_ref": ref,
        "durability_rule_ref": ref,
        "maximum_head_bytes": "1"
        if condition == "reproduction_possession_receiver_head_bound"
        else "1000000",
    }
    storage_ref = _stored(storage, directory)
    issuer_root = _stored({"role": "unqualified issuer storage", "conditions_ref": ref}, directory)
    issuer_storage = {
        **storage,
        "root_source_ref": dict(issuer_root.to_mapping()),
        "maximum_head_bytes": "1"
        if condition == "reproduction_possession_issuer_head_bound"
        else "1000000",
    }
    if condition == "reproduction_possession_issuer_storage_owner":
        issuer_storage["owner_identity_ref"] = dict(issuer_root.to_mapping())
    issuer_storage_ref = _stored(issuer_storage, directory)
    issuer = {
        **common,
        "issuer_identity_ref": ref,
        "issuer_authorization_policy_ref": ref,
        "request_selection_rule_ref": ref,
        "challenge_issuance_method_ref": dict(issuer_storage_ref.to_mapping()),
        "challenge_completion_method_ref": ref
        if condition == "reproduction_possession_issuer_receiver_rule"
        else dict(storage_ref.to_mapping()),
    }
    method.update(
        challenge_issuer_rule_ref=dict(_stored(issuer, directory).to_mapping()),
        receiver_method_ref=dict(storage_ref.to_mapping()),
    )
    if condition == "reproduction_possession_process_scope":
        method["possession_scope"] = "observed_process_signing_capability"
    identity["actual_key_possession_rule_ref"] = dict(_stored(method, directory).to_mapping())
    rules["identity_rule_ref"] = dict(_stored(identity, directory).to_mapping())
    validation = read(rules["validation_rule_ref"])
    validation["independent_identity_policy_ref"] = rules["identity_rule_ref"]
    rules["validation_rule_ref"] = dict(_stored(validation, directory).to_mapping())


class PossessionManifestWriter:
    """Construct complete unsigned native C0 inputs through actual public seal.

    Parameters
    ----------
    inputs : dict
        Full independently prepared caller registry, limits and original source population.
    directory : Path
        Actual owned flat object store for all newly materialised protocol inputs.
    conditions : BlobRef
        Whole unqualified-source disclosure, never protocol/Clock acceptance.
    """

    def __init__(self, inputs: dict[str, object], directory: Path, conditions: BlobRef) -> None:
        """Retain the complete actual construction caller and existing raw sources."""
        self.inputs = inputs
        self.directory = directory
        self.conditions = conditions

    def manifest(self, kind: str, payload: dict[str, object], source: BlobRef) -> BlobRef:
        """Seal one whole declared source C0 with its independently installed test schema.

        Parameters
        ----------
        kind : str
            One statically prepared raw payload definition, never a product dispatch hook.
        payload : dict
            Entire schema-valid native record; no acceptance or qualified source is claimed.
        source : BlobRef
            Complete earlier raw producer source, preserving acyclic construction.

        Returns
        -------
        BlobRef
            Actual public seal canonical content reference; all whole bytes remain stored.
        """
        raw_ref = _stored(payload, self.directory, schema_id=PAYLOAD_IDS[kind])
        declaration = dict(self.conditions.to_mapping())
        content = {
            "schema_id": "evidence_manifest_toolkit.manifest.v1",
            "producer": {
                "tool": "native-possession-source-controls",
                "version": "1",
                "principal": "unqualified-local-controller",
            },
            "created_at": "2025-01-01T00:00:00Z",
            "canonical_profile": "rfc8785-jcs-v1",
            "payload_ref": dict(raw_ref.to_mapping()),
            "source_ref": dict(source.to_mapping()),
            "environment_ref": declaration,
            "derived_from": [],
            "claims": [
                {
                    "claim_id": "native-possession-declared-source",
                    "origin": "architecture_only",
                    "evidence_maturity": "architecture_only",
                    "statement": "Whole declared protocol source; no issuer, receiver, Clock or custody qualification.",
                    "scope": {
                        "subject_digest": raw_ref.digest,
                        "input_class": "unqualified source control",
                        "observation_window": "declared input only",
                        "conditions_ref": declaration,
                        "exclusions": [
                            "native admission",
                            "unpredictable issuance",
                            "durable reception",
                        ],
                    },
                    "source_refs": [dict(raw_ref.to_mapping()), dict(source.to_mapping())],
                    "validation": {"status": "not_claimed"},
                    "verdict": "not_evaluated",
                    "limitations": ["Unqualified source construction and raw equation only."],
                }
            ],
        }
        fixtures = Path(__file__).parent / "fixtures/evidence-command-sources/objects"
        population = {
            key: fixtures / _text(_object(value)["sha256"])
            for key, value in _object(self.inputs["resolver_input_population"]).items()
        }
        for path in self.directory.iterdir():
            if path.is_file() and len(path.name) == 64:
                for basis in ("raw_bytes", "jcs_content"):
                    population["sha256:" + path.name + "|" + basis] = path
        result = seal(
            json.dumps(content, ensure_ascii=False).encode(),
            schema_id="evidence_manifest_toolkit.manifest.v1",
            registry=_registry(self.inputs["registry"]),
            resolver=_FileResolver(population),
            limits=Limits(**cast(dict[str, int], _object(self.inputs["limits"]))),
        )
        assert result.envelope_json is None
        (self.directory / result.content_ref.digest[7:]).write_bytes(result.canonical_content)
        return result.content_ref
