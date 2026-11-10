# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole unqualified ordinary native receipt inputs

"""Retain real source graphs and published-test-key receipts without native admission."""

import base64
import copy
import json
from dataclasses import replace
from pathlib import Path

from tests.domain.clock_source_inputs import software_manifest_receipt
from tests.domain.protected_certificate_inputs import (
    CertificateSourceCase,
    protected_certificate_input,
)
from tests.domain.protected_ordinary_obligations import protected_obligation_input
from tests.domain.test_software_sources import _software_table, _stored_source
from tests.domain.test_verification_report_sources import _array, _bytes, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, reference_bytes

ORDINARY_SOURCE_CASES = (
    "global_purpose",
    "intrinsic",
    "matching",
    "parent",
    "historical",
    "digest",
    "length",
    "schema",
    "authorizing",
    "snapshot",
    "authorization",
    "authorization_metadata",
    "signer",
    "principal",
    "role",
    "segment",
    "purpose",
    "signed_early",
    "signed_late",
    "evaluated_early",
    "evaluated_late",
    "unknown_claim",
    "missing_claim",
    "missing_purpose",
    "parent_issuer",
    "missing_scope",
    "corrupt_scope",
    "content_missing",
    "content_invalid",
    "cli_matching",
    "cli_authorization",
    "cli_missing_scope",
)


def ordinary_certificate_state(
    base: BlobRef, grant: BlobRef, snapshot: BlobRef, directory: Path, *, case: str = "matching"
) -> tuple[BlobRef, BlobRef, BlobRef]:
    """Prepare entire declared certificate sources for ordinary API and actual Clock entry.

    Parameters
    ----------
    base, grant, snapshot : BlobRef
        Whole earlier B, grant and current snapshot. Their authority remains unqualified.
    directory : Path
        Actual complete source store.
    case : str
        Matching sources or one deliberate leaf/parent source contradiction.

    Returns
    -------
    tuple of BlobRef
        Complete adapted grant, snapshot and leaf with the original published test key.
    """

    def body(reference: BlobRef) -> dict[str, object]:
        """Read the complete actual body before any change to its declared fields."""
        return _object(json.loads((directory / reference.digest[7:]).read_bytes()))

    def store(value: dict[str, object]) -> BlobRef:
        """Store the entire canonical native source with its original schema identifier."""
        return _stored_source(value, directory, schema_id=_text(value["schema_id"]))

    declared, grant_body, snapshot_body = body(base), body(grant), body(snapshot)
    scope = copy.deepcopy(_object(grant_body["scope"]))
    fields = {
        "principal_ids": "required_principal",
        "roles": "required_role",
        "tool_segments": "required_segment",
    }
    for field, required in fields.items():
        scope[field] = [declared[required]]
        if (
            case
            == {"principal_ids": "principal", "roles": "role", "tool_segments": "segment"}[field]
        ):
            scope[field] = [declared[required], "different-unqualified-source"]
    scope["permitted_operations"] = [
        "evidence",
        "human_review",
        "issue_certificate",
        "issue_snapshot",
        "rotate_authority",
        "revoke_descendants",
    ]
    grant_body.update(scope=scope, remaining_path_length="2")
    grant = store(grant_body)
    key = grant_body["initial_issuer_key_id"]
    leaf_scope = copy.deepcopy(scope)
    for field, required in fields.items():
        leaf_scope[field] = [declared[required]]
        if (
            case
            == {"principal_ids": "principal", "roles": "role", "tool_segments": "segment"}[field]
        ):
            leaf_scope[field] = ["different-unqualified-source"]
    leaf_scope["permitted_operations"] = (
        ["human_review"] if case == "purpose" else ["evidence", "human_review"]
    )
    parent = grant
    if case in {"parent", "parent_issuer"}:
        parent = store(
            {
                "schema_id": "evidence_manifest_toolkit.delegated_certificate.v2",
                "authority_id": grant_body["authority_id"],
                "parent_authorization_ref": dict(grant.to_mapping()),
                "issuer_key_id": key,
                "subject_key_id": key,
                "subject_public_key_ref": grant_body["initial_issuer_public_key_ref"],
                "identity_custody_source_ref": dict(base.to_mapping()),
                "scope": scope,
                "remaining_path_length": "1",
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": "2030-01-01T00:00:00Z",
                "serial": "1",
            }
        )
    leaf = store(
        {
            "schema_id": "evidence_manifest_toolkit.delegated_certificate.v2",
            "authority_id": grant_body["authority_id"],
            "parent_authorization_ref": dict(parent.to_mapping()),
            "issuer_key_id": "ed25519:" + "0" * 64 if case == "parent_issuer" else key,
            "subject_key_id": key,
            "subject_public_key_ref": grant_body["initial_issuer_public_key_ref"],
            "identity_custody_source_ref": dict(base.to_mapping()),
            "scope": leaf_scope,
            "remaining_path_length": "0",
            "not_before": "2022-01-01T00:00:00Z",
            "not_after": "2028-01-01T00:00:00Z",
            "serial": "2",
        }
    )
    snapshot_body.update(
        root_grant_ref=dict(grant.to_mapping()), certificate_refs=[dict(leaf.to_mapping())]
    )
    return grant, store(snapshot_body), leaf


def protected_manifest_receipt(
    content: bytes,
    *,
    snapshot: BlobRef,
    certificate: BlobRef,
    scope: BlobRef,
    created_at: str,
    directory: Path,
    limits: Limits,
    statement_changes: dict[str, object] | None = None,
) -> tuple[BlobRef, bytes]:
    """Sign the entire ordinary native statement using the genuine published RFC test key.

    Parameters
    ----------
    content : bytes
        Complete actual C0, including every original claim and source.
    snapshot, certificate, scope : BlobRef
        Actual complete selected native sources, all explicitly unqualified.
    created_at : str
        Actual supplied UTC token without Clock qualification.
    directory : Path
        Whole immutable source store.
    limits : Limits
        Original public operation limits.
    statement_changes : dict or None
        Deliberate complete statement changes, signed as actually received.

    Returns
    -------
    tuple
        Whole original envelope identity and bytes. Signature math supplies no custody,
        enrolled root, accepted authority or independently qualified Clock.
    """
    table = _software_table(scope, directory, sequence="1")
    changes: dict[str, object] = {
        "authorizing_state_ref": dict(snapshot.to_mapping()),
        "snapshot_ref": dict(snapshot.to_mapping()),
        "authorization_ref": dict(certificate.to_mapping()),
    }
    if statement_changes is not None:
        changes.update(statement_changes)
    return software_manifest_receipt(
        content,
        table=table,
        scope=scope,
        created_at=created_at,
        directory=directory,
        limits=limits,
        statement_changes=changes,
    )


def protected_ordinary_input(
    case: str, directory: Path
) -> tuple[CertificateSourceCase, tuple[bytes, ...], dict[str, object]]:
    """Build complete real API inputs and the independently authored five-field refusal.

    Parameters
    ----------
    case : str
        Whole source-consistent input or a selected original target/scope/time conflict.
    directory : Path
        Owned actual full-file resolver population, without source or sampler replacements.

    Returns
    -------
    tuple
        Complete caller/source case, real native envelopes and exact expected public Reason.
        Consistent cases stop at the actual missing Clock source; none asserts admission.
    """
    chosen = (
        protected_obligation_input(case, directory)
        if case in {"global_purpose", "intrinsic"}
        else protected_certificate_input("direct", directory)
    )
    base = chosen.caller.independent_root_selection_ref
    grant, snapshot, leaf = ordinary_certificate_state(
        base,
        chosen.caller.root_grant_ref,
        chosen.caller.current_authority_snapshot_ref,
        directory,
        case=case,
    )
    caller = replace(chosen.caller, root_grant_ref=grant, current_authority_snapshot_ref=snapshot)
    if case == "historical":
        current = _object(json.loads((directory / snapshot.digest[7:]).read_bytes()))
        current.update(
            sequence="2", previous_snapshot_ref=dict(snapshot.to_mapping()), certificate_refs=[]
        )
        current_ref = _stored_source(current, directory, schema_id=_text(current["schema_id"]))
        caller = replace(
            caller,
            current_authority_snapshot_ref=current_ref,
            archived_authority_snapshot_ref=snapshot,
            evaluation_mode="historical",
        )
    if case in {"evaluated_early", "evaluated_late"}:
        from evidence_manifest_toolkit import Utc

        caller = replace(
            caller,
            evaluation_time=Utc(
                "2021-01-01T00:00:00Z" if case == "evaluated_early" else "2028-01-01T00:00:00Z"
            ),
        )
    policy = _object(json.loads((directory / chosen.policy_ref.digest[7:]).read_bytes()))
    policy["root_grant_ref"] = dict(grant.to_mapping())
    policy_ref = _stored_source(policy, directory, schema_id=_text(policy["schema_id"]))
    inputs = dict(chosen.inputs)
    raw = _bytes(inputs["content_json"])
    content = _object(json.loads(raw))
    missing = None
    if case == "content_invalid":
        del content["producer"]
        raw = json.dumps(content).encode()
    if case == "content_missing":
        original_payload = BlobRef.from_mapping(_object(content["payload_ref"]))
        missing = reference_bytes(
            b'{"deliberately_absent_ordinary_payload":true}',
            media_type=original_payload.media_type,
            digest_basis=original_payload.digest_basis,
            schema_id=original_payload.schema_id,
            limits=chosen.limits,
        )
        content["payload_ref"] = dict(missing.to_mapping())
        raw = json.dumps(content).encode()
    inputs["content_json"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    changes: dict[str, object] = {}
    field = {
        "digest": "content_digest",
        "length": "content_byte_length",
        "schema": "content_schema_id",
        "authorizing": "authorizing_state_ref",
        "snapshot": "snapshot_ref",
        "authorization": "authorization_ref",
        "authorization_metadata": "authorization_ref",
        "signer": "signer_key_id",
        "purpose": "purpose",
        "signed_early": "claimed_signed_at",
        "signed_late": "claimed_signed_at",
        "unknown_claim": "claim_ids",
        "missing_claim": "claim_ids",
        "missing_purpose": "purpose",
    }.get(case)
    if field is not None:
        changes[field] = (
            base.digest
            if case == "digest"
            else "1"
            if case == "length"
            else "evidence_manifest_toolkit.target_descriptor.v1"
            if case == "schema"
            else "ed25519:" + "0" * 64
            if case == "signer"
            else "evidence"
            if case == "purpose"
            else "human_review"
            if case == "missing_purpose"
            else "2021-01-01T00:00:00Z"
            if case == "signed_early"
            else "2028-01-01T00:00:00Z"
            if case == "signed_late"
            else ["unknown-ordinary-claim"]
            if case == "unknown_claim"
            else [_object(_array(content["claims"])[-1])["claim_id"]]
            if case == "missing_claim"
            else dict(replace(leaf, schema_id=None).to_mapping())
            if case == "authorization_metadata"
            else dict(base.to_mapping())
        )
    if case == "global_purpose":
        changes["purpose"] = "human_review"
    if case == "intrinsic":
        changes["claim_ids"] = _array(chosen.declared["required_claim_ids"])[:1]
    scope = base
    if case in {"missing_scope", "corrupt_scope"}:
        scope_raw = b"actual independent opaque scope source"
        scope = reference_bytes(
            scope_raw,
            media_type="application/octet-stream",
            digest_basis="raw_bytes",
            schema_id=None,
            limits=chosen.limits,
        )
        (directory / scope.digest[7:]).write_bytes(
            scope_raw if case == "missing_scope" else b"corrupted scope"
        )
        if case == "missing_scope":
            missing = scope
            (directory / scope.digest[7:]).unlink()
    envelope_ref, envelope = protected_manifest_receipt(
        raw,
        snapshot=snapshot,
        certificate=leaf,
        scope=scope,
        created_at="2026-01-01T00:00:00Z",
        directory=directory,
        limits=chosen.limits,
        statement_changes=changes,
    )
    expected: dict[str, object] = {
        "code": "policy_unavailable",
        "subject_digest": policy_ref.digest,
        "claim_id": None,
        "pointer": "/required_evaluation_time_qualification/clock_qualification_ref",
        "detail": "The required evaluation-time qualification is unavailable.",
    }
    if field is not None or case in {
        "principal",
        "role",
        "segment",
        "parent_issuer",
        "evaluated_early",
        "evaluated_late",
    }:
        code = (
            "scope_missing"
            if case in {"digest", "length", "schema", "authorizing", "snapshot", "unknown_claim"}
            else "invalid_delegation"
        )
        expected.update(
            code=code,
            subject_digest=envelope_ref.digest,
            pointer="/statement/"
            + ("claim_ids/0" if case == "unknown_claim" else field or "authorization_ref"),
            detail="Protected statement does not match its independently selected source or target.",
        )
        if case in {"evaluated_early", "evaluated_late"}:
            expected.update(subject_digest=policy_ref.digest, pointer="/trust/evaluation_time")
        if case == "parent_issuer":
            expected.update(
                subject_digest=leaf.digest,
                pointer="/issuer_key_id",
                detail="Protected certificate issuer does not match its parent.",
            )
        if case in {"missing_claim", "missing_purpose"}:
            content_ref = reference_bytes(
                raw,
                media_type="application/json",
                digest_basis="jcs_content",
                schema_id=_text(inputs["schema_id"]),
                limits=chosen.limits,
            )
            expected.update(
                code="scope_missing",
                subject_digest=content_ref.digest,
                pointer="/claims",
                claim_id=_array(chosen.declared["required_claim_ids"])[0],
                detail="Required signed claim and purpose scope is unavailable.",
            )
    if case == "schema":
        expected["detail"] = "Ordinary statements require the complete native manifest."
    if case == "content_invalid":
        content_ref = reference_bytes(
            raw,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id=_text(inputs["schema_id"]),
            limits=chosen.limits,
        )
        expected.update(
            code="invalid_schema",
            subject_digest=content_ref.digest,
            pointer="",
            detail="Input violates its selected schema.",
        )
    if case == "corrupt_scope":
        statement_raw = json.dumps(_object(json.loads(envelope))["statement"]).encode()
        statement_ref = reference_bytes(
            statement_raw,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id="evidence_manifest_toolkit.signed_statement.v2",
            limits=chosen.limits,
        )
        expected.update(
            code="reference_mismatch",
            subject_digest=statement_ref.digest,
            pointer="/scope_ref",
            detail="Reference byte identity does not match.",
        )
    if case in {"global_purpose", "intrinsic"}:
        content_ref = reference_bytes(
            raw,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id=_text(inputs["schema_id"]),
            limits=chosen.limits,
        )
        expected.update(
            code="scope_missing" if case == "global_purpose" else "signature_required",
            subject_digest=content_ref.digest,
            pointer=None if case == "global_purpose" else "/claims",
            claim_id=None
            if case == "global_purpose"
            else _object(_array(content["claims"])[1])["claim_id"],
            detail="Required signed purpose is unavailable."
            if case == "global_purpose"
            else "The required evidence signature is unavailable.",
        )
    population = dict(chosen.population)
    for path in directory.iterdir():
        if path.is_file() and len(path.name) == 64:
            population["sha256:" + path.name + "|raw_bytes"] = path
            population["sha256:" + path.name + "|jcs_content"] = path
    if missing is not None:
        population[missing.digest + "|" + missing.digest_basis] = directory / missing.digest[7:]
        expected = {
            "code": "reference_unavailable",
            "subject_digest": None,
            "claim_id": None,
            "pointer": None,
            "detail": "Required reference unavailable.",
        }
    chosen = replace(
        chosen,
        inputs=inputs,
        caller=caller,
        policy_ref=policy_ref,
        population=population,
        missing=missing,
        required_sources=(grant, snapshot, leaf),
    )
    return chosen, (envelope,), expected
