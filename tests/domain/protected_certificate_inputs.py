# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole deliberately unqualified native certificate inputs

"""Keep actual full parent graphs distinct from accepted keys, custody and issuer authority."""

import copy
import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import rfc8785
from tests.domain.method_rule_inputs import method_rule_inputs
from tests.domain.protected_control_inputs import prepare_control_base, protected_control_inputs
from tests.domain.protected_state_inputs import protected_state_inputs
from tests.domain.test_policy_selection_sources import _successor_policy
from tests.domain.test_software_sources import _stored_source
from tests.domain.test_successor_trust import _callers, _sources
from tests.domain.test_verification_report_sources import _array, _object, _text

from evidence_manifest_toolkit import BlobRef, DelegatedTrustContextV2, Limits

type _CertificateJson = (
    None | bool | int | float | str | list[_CertificateJson] | dict[str, _CertificateJson]
)

CERTIFICATE_SOURCE_CASES = (
    "direct",
    "chain",
    "shared_parent",
    "historical",
    "current_history",
    "until_withdrawal",
    "group_scope",
    "principal_scope",
    "role_scope",
    "segment_scope",
    "operation_scope",
    "parent_operation",
    "same_depth",
    "parent_depth_zero",
    "leaf_control",
    "authority",
    "child_empty_window",
    "child_early_window",
    "child_late_window",
    "parent_empty_window",
    "foreign_grant",
    "grant_metadata",
    "grant_as_leaf",
    "parent_kind",
    "missing_leaf",
    "missing_parent",
    "leaf_json",
    "parent_json",
    "graph_depth",
    "cached_depth",
    "cli_direct",
    "cli_role_scope",
    "cli_missing_parent",
)


@dataclass(frozen=True, slots=True)
class CertificateSourceCase:
    """Retain entire original public inputs and the precise authored negative/source oracle.

    Attributes
    ----------
    inputs, declared : dict
        Whole unchanged original manifest/registry/limits/policy fixture sources.
    limits : Limits
        Entire original bounds or explicitly selected smaller graph-depth counterfactual.
    caller : DelegatedTrustContextV2
        Complete frozen source-only caller. Its key/root/Clock claims are not admitted.
    policy_ref : BlobRef
        Whole independently selected matching enclosing policy.
    population, original_bytes : dict
        Full actual resolver population and preserved original owner fixture bodies.
    missing : BlobRef or None
        Exact original deliberately unavailable selected argument, without a fake result.
    expected_subject, expected_pointer, expected_code, expected_detail : str or None
        Complete actual source/refusal position and fixed original diagnostic fields.
    required_sources : tuple of BlobRef
        Whole sources whose actual API acquisition is required in source-consistent cases.
    forbidden_grant : BlobRef or None
        Advertised alternative grant that must not be read or adopted as a replacement root.
    """

    inputs: dict[str, object]
    declared: dict[str, object]
    limits: Limits
    caller: DelegatedTrustContextV2
    policy_ref: BlobRef
    population: dict[str, Path]
    original_bytes: dict[Path, bytes]
    missing: BlobRef | None
    expected_subject: str | None
    expected_pointer: str
    expected_code: str
    expected_detail: str
    required_sources: tuple[BlobRef, ...]
    forbidden_grant: BlobRef | None


def protected_certificate_input(case: str, directory: Path) -> CertificateSourceCase:
    """Create full immutable native parent sources before public verification entry.

    Parameters
    ----------
    case : str
        Exact ordinary source graph or authored full-source counterfactual.
    directory : Path
        Owned original whole input store, never an actual root/controller installation.

    Returns
    -------
    CertificateSourceCase
        Full original public inputs, sources and fixed expected refusal. Even source
        consistency reaches actual missing Clock; no native certificate admission is claimed.
    """
    inputs, declared, base, population, originals = prepare_control_base(directory)
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    binding, references, carriers = _sources()
    originals.update(carriers)
    historical = case == "historical"
    caller = _callers(binding, references, "historical" if historical else "current")[2]
    rule, selection, controls, objects = protected_control_inputs(base, directory)
    population.update(objects)
    grant, snapshot, objects = protected_state_inputs(base, rule, base, directory)
    population.update(objects)

    def body(reference: BlobRef) -> dict[str, object]:
        """Read every member of the actual complete native source."""
        return dict(_object(json.loads((directory / reference.digest[7:]).read_bytes())))

    def store(value: dict[str, object], schema: str) -> BlobRef:
        """Keep entire actual canonical native bytes with complete truthful metadata."""
        raw = rfc8785.dumps(cast(dict[str, _CertificateJson], value))
        digest = hashlib.sha256(raw).hexdigest()
        path = directory / digest
        path.write_bytes(raw)
        reference = BlobRef(
            "sha256:" + digest, str(len(raw)), "application/json", "jcs_content", schema
        )
        population[reference.digest + "|jcs_content"] = path
        return reference

    def key_fault(value: dict[str, object], field: str, identifier: str) -> None:
        """Create one complete key-source contradiction before the whole caller freeze.

        Parameters
        ----------
        value : dict
            Entire actual grant or certificate body, retaining every other original field.
        field, identifier : str
            Exact full source-reference and own native key-ID fields.
        """
        if case.endswith("_id"):
            value[identifier] = "ed25519:" + "0" * 64
            return
        original = BlobRef.from_mapping(_object(value[field]))
        public = (directory / original.digest[7:]).read_bytes()
        raw = public[:-1] if case.endswith("_short") else public + b"\x00"
        digest = hashlib.sha256(raw).hexdigest()
        path = directory / digest
        path.write_bytes(raw)
        reference = BlobRef(
            "sha256:" + digest, str(len(raw)), "application/octet-stream", "raw_bytes"
        )
        population[reference.digest + "|raw_bytes"] = path
        value[field] = dict(reference.to_mapping())

    grant_body, snapshot_body = body(grant), body(snapshot)
    grant_body["remaining_path_length"] = "6"
    if case == "parent_operation":
        scope = copy.deepcopy(_object(grant_body["scope"]))
        scope["permitted_operations"] = ["evidence", "issue_snapshot"]
        grant_body["scope"] = scope
    if case == "parent_depth_zero":
        grant_body["remaining_path_length"] = "0"
    if case == "until_withdrawal":
        grant_body["lifetime"] = {
            "kind": "until_withdrawal",
            "not_before": "2020-01-01T00:00:00Z",
            "not_after": None,
        }
    if case.startswith("key_grant_"):
        key_fault(grant_body, "initial_issuer_public_key_ref", "initial_issuer_key_id")
        snapshot_body["current_issuer_key_id"] = grant_body["initial_issuer_key_id"]
    grant = store(grant_body, "evidence_manifest_toolkit.authority_grant.v2")
    scope = copy.deepcopy(_object(grant_body["scope"]))
    key = _text(grant_body["initial_issuer_key_id"])
    public_ref = _object(grant_body["initial_issuer_public_key_ref"])

    def certificate(parent: BlobRef, *, depth: str, serial: str, issuer: bool) -> dict[str, object]:
        """Retain all twelve native fields, with explicit unqualified public test-key sources."""
        selected_scope = copy.deepcopy(scope)
        selected_scope["permitted_operations"] = (
            ["evidence", "issue_certificate"] if issuer else ["evidence"]
        )
        return {
            "schema_id": "evidence_manifest_toolkit.delegated_certificate.v2",
            "authority_id": grant_body["authority_id"],
            "parent_authorization_ref": dict(parent.to_mapping()),
            "issuer_key_id": key,
            "subject_key_id": key,
            "subject_public_key_ref": public_ref,
            "identity_custody_source_ref": dict(base.to_mapping()),
            "scope": selected_scope,
            "remaining_path_length": depth,
            "not_before": "2022-01-01T00:00:00Z",
            "not_after": "2028-01-01T00:00:00Z",
            "serial": serial,
        }

    schema = "evidence_manifest_toolkit.delegated_certificate.v2"
    parent = grant
    parent_body: dict[str, object] | None = None
    if case.startswith(("key_parent_", "issuer_")) or case in {
        "chain",
        "shared_parent",
        "historical",
        "current_history",
        "missing_parent",
        "parent_json",
        "parent_empty_window",
    }:
        if case == "issuer_ancestor":
            ancestor_body = certificate(grant, depth="4", serial="3", issuer=True)
            ancestor_body.update(
                not_before="2020-01-01T00:00:00Z", not_after="2030-01-01T00:00:00Z"
            )
            parent = store(ancestor_body, schema)
        parent_body = certificate(parent, depth="2", serial="1", issuer=True)
        parent_body.update(not_before="2021-01-01T00:00:00Z", not_after="2029-01-01T00:00:00Z")
        if case == "parent_empty_window":
            parent_body["not_after"] = parent_body["not_before"]
        if case.startswith("key_parent_"):
            key_fault(parent_body, "subject_public_key_ref", "subject_key_id")
        if case == "issuer_ancestor":
            parent_body["issuer_key_id"] = "ed25519:" + "0" * 64
        parent = store(parent_body, schema)
    if case in {"graph_depth", "cached_depth"}:
        for depth in ("5", "4", "3"):
            parent = store(certificate(parent, depth=depth, serial=depth, issuer=True), schema)
        limits = replace(limits, max_graph_depth=3)
    leaf_body = certificate(parent, depth="0", serial="8", issuer=False)
    pointer, code, detail = "", "policy_unavailable", "Protected state sources conflict."
    subject: str | None = None
    forbidden: BlobRef | None = None
    scope_cases = {
        "group_scope": "group_ids",
        "principal_scope": "principal_ids",
        "role_scope": "roles",
        "segment_scope": "tool_segments",
        "operation_scope": "permitted_operations",
    }
    if case in scope_cases:
        changed = copy.deepcopy(_object(leaf_body["scope"]))
        field = scope_cases[case]
        changed[field] = [
            *_array(changed[field]),
            "deployment" if field == "permitted_operations" else "outside-declared-scope",
        ]
        leaf_body["scope"] = changed
        pointer = "/scope/" + field
    if case in {"same_depth", "parent_depth_zero"}:
        leaf_body["remaining_path_length"] = "6" if case == "same_depth" else "0"
        pointer = "/remaining_path_length"
    if case == "leaf_control":
        changed = copy.deepcopy(_object(leaf_body["scope"]))
        changed["permitted_operations"] = ["evidence", "issue_snapshot"]
        leaf_body["scope"] = changed
        pointer = "/scope/permitted_operations"
    if case == "authority":
        leaf_body["authority_id"] = "different-source-authority"
        pointer = "/authority_id"
    if case == "parent_operation":
        pointer = "/parent_authorization_ref"
    if case in {"child_empty_window", "child_early_window", "child_late_window"}:
        field = "not_before" if case == "child_early_window" else "not_after"
        leaf_body[field] = (
            "2019-01-01T00:00:00Z"
            if case == "child_early_window"
            else "2031-01-01T00:00:00Z"
            if case == "child_late_window"
            else leaf_body["not_before"]
        )
        pointer = "/" + field
    if case == "parent_empty_window":
        subject, pointer = parent.digest, "/not_after"
    if case in {"foreign_grant", "grant_metadata"}:
        forbidden = (
            store({**grant_body, "serial": "2"}, "evidence_manifest_toolkit.authority_grant.v2")
            if case == "foreign_grant"
            else replace(grant, media_type="application/alternate+json")
        )
        leaf_body["parent_authorization_ref"] = dict(forbidden.to_mapping())
        pointer = "/parent_authorization_ref"
    if case == "parent_kind":
        earlier = store(
            {**snapshot_body, "root_grant_ref": dict(grant.to_mapping())},
            "evidence_manifest_toolkit.authority_snapshot.v2",
        )
        leaf_body["parent_authorization_ref"] = dict(earlier.to_mapping())
        subject, pointer, code, detail = (
            earlier.digest,
            "",
            "invalid_schema",
            "Input violates its selected schema.",
        )
    if case == "parent_json":
        raw = b"{"
        digest = hashlib.sha256(raw).hexdigest()
        parent = BlobRef("sha256:" + digest, "1", "application/json", "raw_bytes", schema)
        (directory / digest).write_bytes(raw)
        population[parent.digest + "|raw_bytes"] = directory / digest
        leaf_body["parent_authorization_ref"] = dict(parent.to_mapping())
        subject, code, detail = parent.digest, "invalid_json", "Input is not valid strict JSON."
    if case.startswith("key_leaf_"):
        key_fault(leaf_body, "subject_public_key_ref", "subject_key_id")
    if case == "issuer_parent":
        leaf_body["issuer_key_id"] = "ed25519:" + "0" * 64
    if case == "issuer_distinct_subject":
        public = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        digest = hashlib.sha256(public).hexdigest()
        path = directory / digest
        path.write_bytes(public)
        reference = BlobRef(
            "sha256:" + digest, str(len(public)), "application/octet-stream", "raw_bytes"
        )
        population[reference.digest + "|raw_bytes"] = path
        leaf_body["subject_public_key_ref"] = dict(reference.to_mapping())
        leaf_body["subject_key_id"] = "ed25519:" + digest
    leaf = store(leaf_body, schema)
    if case in {"issuer_parent", "issuer_ancestor"}:
        subject = parent.digest if case == "issuer_ancestor" else leaf.digest
        pointer, code, detail = (
            "/issuer_key_id",
            "invalid_delegation",
            "Protected certificate issuer does not match its parent.",
        )
    if case.startswith("key_"):
        subject = (
            grant.digest
            if case.startswith("key_grant_")
            else parent.digest
            if case.startswith("key_parent_")
            else leaf.digest
        )
        pointer = (
            "/initial_issuer_public_key_ref"
            if case.startswith("key_grant_")
            else "/subject_public_key_ref"
        )
        if not case.startswith("key_grant_"):
            code = "invalid_delegation"
            detail = "Selected native key data does not match the certificate subject."
    if pointer and subject is None:
        subject = leaf.digest
    selected = [dict(leaf.to_mapping())]
    if case == "shared_parent":
        sibling = store({**leaf_body, "serial": "9"}, schema)
        selected.append(dict(sibling.to_mapping()))
    if case == "cached_depth":
        prefix = store(certificate(parent, depth="2", serial="6", issuer=True), schema)
        leaf_body["parent_authorization_ref"] = dict(prefix.to_mapping())
        leaf = store(leaf_body, schema)
        selected = [dict(parent.to_mapping()), dict(leaf.to_mapping())]
        subject, pointer, code = prefix.digest, "/parent_authorization_ref", "limit_exceeded"
    if case == "graph_depth":
        # Current leaf plus the two nearest native ancestors exhaust depth3 before the next parent.
        nearest = body(parent)
        next_reference = BlobRef.from_mapping(_object(nearest["parent_authorization_ref"]))
        subject, pointer, code = (
            next_reference.digest,
            "/parent_authorization_ref",
            "limit_exceeded",
        )
    if case == "leaf_json":
        raw = b"{"
        digest = hashlib.sha256(raw).hexdigest()
        leaf = BlobRef("sha256:" + digest, "1", "application/json", "raw_bytes", schema)
        (directory / digest).write_bytes(raw)
        population[leaf.digest + "|raw_bytes"] = directory / digest
        selected = [dict(leaf.to_mapping())]
        subject, code, detail = leaf.digest, "invalid_json", "Input is not valid strict JSON."
    snapshot_body.update(root_grant_ref=dict(grant.to_mapping()), certificate_refs=selected)
    if case == "grant_as_leaf":
        snapshot_body["certificate_refs"] = [dict(grant.to_mapping())]
        pointer, code, detail = ("", "invalid_schema", "Input violates its selected schema.")
    archive = store(snapshot_body, "evidence_manifest_toolkit.authority_snapshot.v2")
    if case == "grant_as_leaf":
        subject = grant.digest
    if case in {"historical", "current_history"}:
        snapshot_body.update(
            sequence="2",
            issued_at="2021-01-01T00:00:00Z",
            previous_snapshot_ref=dict(archive.to_mapping()) if case == "current_history" else None,
        )
    current = store(snapshot_body, "evidence_manifest_toolkit.authority_snapshot.v2")
    caller = replace(
        caller,
        independent_root_selection_ref=base,
        root_grant_ref=grant,
        current_authority_snapshot_ref=current,
        accepted_authority_sequence_floor="1",
        authority_control_selection_ref=selection,
        control_envelopes=controls,
        archived_authority_snapshot_ref=archive if historical else None,
    )
    policy = _successor_policy(base)
    policy.update(
        profile_class=caller.profile_class,
        authority_rule_ref=dict(rule.to_mapping()),
        root_grant_ref=dict(grant.to_mapping()),
    )
    fields, objects = method_rule_inputs(base, directory, profile_class=caller.profile_class)
    population.update(objects)
    policy.update(fields)
    policy_ref = _stored_source(
        policy, directory, schema_id="evidence_manifest_toolkit.authority_policy.v2"
    )
    population[policy_ref.digest + "|raw_bytes"] = directory / policy_ref.digest[7:]
    missing = leaf if case == "missing_leaf" else parent if case == "missing_parent" else None
    if missing is not None:
        population[missing.digest + "|" + missing.digest_basis] = (
            directory / "intentionally-absent-whole-certificate"
        )
    return CertificateSourceCase(
        dict(inputs),
        dict(declared),
        limits,
        caller,
        policy_ref,
        population,
        originals,
        missing,
        subject,
        pointer,
        code,
        detail,
        (grant, current, leaf, parent),
        forbidden,
    )
