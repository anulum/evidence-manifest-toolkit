# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole independently authored control target inputs

"""Keep actual target and receipt contradictions separate from protected state admission."""

import base64
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import rfc8785
from Crypto.Signature import eddsa
from tests.domain.protected_certificate_inputs import (
    CertificateSourceCase,
    protected_certificate_input,
)
from tests.domain.protected_control_inputs import protected_control_inputs
from tests.domain.test_software_sources import _stored_source
from tests.domain.test_verification_report_sources import _array, _object, _text

from evidence_manifest_toolkit import BlobRef

type _TargetJson = None | bool | int | float | str | list[_TargetJson] | dict[str, _TargetJson]

CERTIFICATE_CONTROL_SOURCE_CASES = (
    "certificate_target_group",
    "certificate_target_principal",
    "certificate_target_role",
    "certificate_target_segment",
    "certificate_target_operation",
    "certificate_target_depth",
    "certificate_target_leaf_control",
    "certificate_target_empty",
    "certificate_target_early",
    "certificate_target_late",
    "certificate_target_key_id",
    "certificate_target_key_short",
    "certificate_target_chain",
)

CONTROL_TARGET_CASES = (
    "grant_matching",
    "grant_root_key",
    "grant_root_reference",
    "certificate_matching",
    "certificate_issuer",
    "certificate_parent",
    "snapshot_matching",
    "snapshot_issuer",
)


def protected_control_target_input(case: str, directory: Path) -> CertificateSourceCase:
    """Build entire canonical targets and real native test receipts before caller freeze.

    Parameters
    ----------
    case : str
        Source-compatible operation or one complete target-side contradiction.
    directory : Path
        Owned actual source store; no operational root, key or controller installation.

    Returns
    -------
    CertificateSourceCase
        Complete original public invocation and exact source/Clock refusal oracle.
        Published test key signatures do not supply authority, custody or accepted state.
    """
    chosen = protected_certificate_input("direct", directory)
    operation = (
        "authority_grant"
        if case.startswith("grant_")
        else "issue_certificate"
        if case.startswith("certificate_")
        else "issue_snapshot"
    )
    _, selection, _, population = protected_control_inputs(
        chosen.caller.independent_root_selection_ref, directory, operations=(operation,)
    )
    population.update(chosen.population)

    def body(reference: BlobRef) -> dict[str, object]:
        """Read every original field from the actual whole source."""
        return _object(json.loads((directory / reference.digest[7:]).read_bytes()))

    def native(value: dict[str, object]) -> BlobRef:
        """Retain complete canonical native bytes with exact full source metadata."""
        raw = rfc8785.dumps(cast(dict[str, _TargetJson], value))
        digest = hashlib.sha256(raw).hexdigest()
        path = directory / digest
        path.write_bytes(raw)
        reference = BlobRef(
            "sha256:" + digest,
            str(len(raw)),
            "application/json",
            "jcs_content",
            _text(value["schema_id"]),
        )
        population[reference.digest + "|jcs_content"] = path
        return reference

    selected = body(selection)
    entry = dict(_object(_array(selected["entries"])[0]))
    target = body(BlobRef.from_mapping(_object(entry["target_ref"])))
    if operation in {"authority_grant", "issue_certificate"}:
        public = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        digest = hashlib.sha256(public).hexdigest()
        path = directory / digest
        path.write_bytes(public)
        public_reference = BlobRef(
            "sha256:" + digest, str(len(public)), "application/octet-stream", "raw_bytes"
        )
        population[public_reference.digest + "|raw_bytes"] = path
        key_field, source_field = (
            ("initial_issuer_key_id", "initial_issuer_public_key_ref")
            if operation == "authority_grant"
            else ("subject_key_id", "subject_public_key_ref")
        )
        target.update(
            {key_field: "ed25519:" + digest, source_field: dict(public_reference.to_mapping())}
        )
    if operation != "authority_grant":
        entry.update(
            authorizing_state_ref=dict(chosen.caller.current_authority_snapshot_ref.to_mapping()),
            authorization_ref=dict(chosen.caller.root_grant_ref.to_mapping()),
        )
    if operation == "issue_certificate":
        original_leaf = body(chosen.required_sources[2])
        target.update(
            parent_authorization_ref=dict(chosen.caller.root_grant_ref.to_mapping()),
            scope=original_leaf["scope"],
            not_before=original_leaf["not_before"],
            not_after=original_leaf["not_after"],
            serial="9",
        )
    if operation == "issue_snapshot":
        target = body(chosen.caller.current_authority_snapshot_ref)
        target.update(
            sequence="2",
            issued_at="2021-01-01T00:00:00Z",
            expires_at="2029-01-01T00:00:00Z",
            previous_snapshot_ref=dict(chosen.caller.current_authority_snapshot_ref.to_mapping()),
        )
    field = {
        "grant_root_key": "root_key_id",
        "grant_root_reference": "root_selection_source_ref",
        "certificate_issuer": "issuer_key_id",
        "certificate_parent": "parent_authorization_ref",
        "snapshot_issuer": "current_issuer_key_id",
    }.get(case)
    if field is not None:
        target[field] = (
            dict(chosen.caller.root_grant_ref.to_mapping())
            if field == "root_selection_source_ref"
            else dict(chosen.caller.independent_root_selection_ref.to_mapping())
            if field == "parent_authorization_ref"
            else "ed25519:" + "0" * 64
        )
    pointer = "/" + field if field is not None else ""
    detail = "Protected state sources conflict."
    code = "policy_unavailable"
    additional_sources: tuple[BlobRef, ...] = ()
    scope_fields = {
        "certificate_target_group": "group_ids",
        "certificate_target_principal": "principal_ids",
        "certificate_target_role": "roles",
        "certificate_target_segment": "tool_segments",
        "certificate_target_operation": "permitted_operations",
    }
    if case in scope_fields:
        name = scope_fields[case]
        selected_scope = dict(_object(target["scope"]))
        selected_scope[name] = ["human_review"] if name == "permitted_operations" else ["outside"]
        target["scope"] = selected_scope
        pointer = "/scope/" + name
    if case == "certificate_target_depth":
        target["remaining_path_length"] = "6"
        pointer = "/remaining_path_length"
    if case == "certificate_target_leaf_control":
        selected_scope = dict(_object(target["scope"]))
        selected_scope["permitted_operations"] = ["evidence", "issue_certificate"]
        target["scope"] = selected_scope
        pointer = "/scope/permitted_operations"
    if case == "certificate_target_empty":
        target["not_after"] = target["not_before"]
        pointer = "/not_after"
    if case == "certificate_target_early":
        target["not_before"] = "2019-01-01T00:00:00Z"
        pointer = "/not_before"
    if case == "certificate_target_late":
        target["not_after"] = "2031-01-01T00:00:00Z"
        pointer = "/not_after"
    if case in {"certificate_target_key_id", "certificate_target_key_short"}:
        if case == "certificate_target_key_id":
            target["subject_key_id"] = "ed25519:" + "0" * 64
        else:
            original_key = BlobRef.from_mapping(_object(target["subject_public_key_ref"]))
            public = (directory / original_key.digest[7:]).read_bytes()[:-1]
            digest = hashlib.sha256(public).hexdigest()
            path = directory / digest
            path.write_bytes(public)
            reference = BlobRef(
                "sha256:" + digest, str(len(public)), "application/octet-stream", "raw_bytes"
            )
            population[reference.digest + "|raw_bytes"] = path
            target["subject_public_key_ref"] = dict(reference.to_mapping())
            target["subject_key_id"] = "ed25519:" + digest
        pointer = "/subject_public_key_ref"
        code = "invalid_delegation"
        detail = "Selected native key data does not match the certificate subject."
    if case == "certificate_target_chain":
        parent = dict(target)
        parent_scope = dict(_object(target["scope"]))
        parent_scope["permitted_operations"] = ["evidence", "issue_certificate"]
        parent.update(
            scope=parent_scope,
            remaining_path_length="2",
            serial="10",
            subject_key_id=target["issuer_key_id"],
            subject_public_key_ref=body(chosen.caller.root_grant_ref)[
                "initial_issuer_public_key_ref"
            ],
        )
        parent_reference = native(parent)
        target["parent_authorization_ref"] = dict(parent_reference.to_mapping())
        entry["authorization_ref"] = dict(parent_reference.to_mapping())
        additional_sources = (parent_reference,)
    target_reference = native(target)
    statement = body(BlobRef.from_mapping(_object(entry["statement_ref"])))
    statement.update(
        authorizing_state_ref=entry["authorizing_state_ref"],
        authorization_ref=entry["authorization_ref"],
        content_digest=target_reference.digest,
        content_byte_length=target_reference.byte_length,
        content_schema_id=target_reference.schema_id,
    )
    statement_reference = native(statement)
    # Published RFC8032 section7.1 vector; never an operational/protected secret.
    key = eddsa.import_private_key(
        bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    )
    message = b"GOTM-EMT-AUTHORITY-V2\x00" + rfc8785.dumps(cast(dict[str, _TargetJson], statement))
    signature = eddsa.new(key, "rfc8032").sign(message)
    eddsa.new(key.public_key(), "rfc8032").verify(message, signature)
    envelope = rfc8785.dumps(
        cast(
            dict[str, _TargetJson],
            {
                "statement": statement,
                "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
            },
        )
    )
    entry.update(
        target_ref=dict(target_reference.to_mapping()),
        statement_ref=dict(statement_reference.to_mapping()),
        envelope_digest="sha256:" + hashlib.sha256(envelope).hexdigest(),
    )
    selected["entries"] = [entry]
    selection = _stored_source(selected, directory)
    population[selection.digest + "|raw_bytes"] = directory / selection.digest[7:]
    return replace(
        chosen,
        caller=replace(
            chosen.caller,
            authority_control_selection_ref=selection,
            control_envelopes=(envelope,),
        ),
        population=population,
        expected_subject=target_reference.digest if pointer else None,
        expected_pointer=pointer,
        expected_detail=detail,
        expected_code=code,
        required_sources=(
            *chosen.required_sources,
            *additional_sources,
            target_reference,
            statement_reference,
            selection,
        ),
    )
