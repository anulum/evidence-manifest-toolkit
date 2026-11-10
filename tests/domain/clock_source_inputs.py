# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual signed source inputs without authority admission

"""Prepare whole unqualified Clock C0 sources with genuine published-test-key signatures."""

import base64
import hashlib
import json
from pathlib import Path

from Crypto.Signature import eddsa
from tests.domain.test_verification_report_sources import _array, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, canonicalize_json, reference_bytes

# Published RFC8032 section7.1 test vector, not an operational or protected key.
_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")


def software_acceptance_sources(
    template: bytes,
    *,
    acceptance: BlobRef,
    table: BlobRef,
    scope: BlobRef,
    raw_source: BlobRef,
    environment: BlobRef,
    created_at: str,
    directory: Path,
    limits: Limits,
) -> tuple[BlobRef, BlobRef]:
    """Bind the entire acceptance body and sign its whole C0 using the exact V2 domain.

    Parameters
    ----------
    template : bytes
        Whole original C0, retaining its unqualified maturity and validation declarations.
    acceptance : BlobRef
        Whole actual class-bearing source with six unavailable acceptance outcomes.
    table, scope : BlobRef
        Earlier complete unprotected table and whole rule, never a fabricated grant.
    raw_source, environment : BlobRef
        Entire actual daemon reply and current runtime environment.
    created_at : str
        Actual captured UTC token, without time or Clock qualification substitution.
    directory : Path
        Owned whole content-addressed source store.
    limits : Limits
        Original public source operation bounds for full canonical references.

    Returns
    -------
    tuple of BlobRef
        Whole C0 and actual V2 envelope references. Mathematical test-key/target proof
        supplies no native authority, protected provenance or accepted Clock result.
    """
    body = _object(json.loads(template))
    target = {
        "schema_id": "evidence_manifest_toolkit.target_descriptor.v1",
        "target_id": "unqualified-clock-source-test-host",
        "target_kind": "host",
        "environment_ref": dict(environment.to_mapping()),
        "toolchain_ref": dict(environment.to_mapping()),
        "capabilities": {
            name: {"availability": "unknown", "contract_version": "author-declaration-r1"}
            for name in (
                "timebase",
                "event_transport",
                "run_control",
                "boot_reset",
                "power_monitor",
                "fault_control",
            )
        },
    }
    target_bytes = canonicalize_json(
        json.dumps(target, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), limits=limits
    )
    target_ref = reference_bytes(
        target_bytes,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id="evidence_manifest_toolkit.target_descriptor.v1",
        limits=limits,
    )
    (directory / target_ref.digest[7:]).write_bytes(target_bytes)
    body.update(
        created_at=created_at,
        payload_ref=dict(target_ref.to_mapping()),
        source_ref=dict(raw_source.to_mapping()),
        environment_ref=dict(environment.to_mapping()),
    )
    claims = []
    for original in _array(body["claims"]):
        claim = _object(original)
        claim.update(
            statement="Actual local source retained; physical uncertainty and model qualification unavailable.",
            source_refs=[dict(acceptance.to_mapping()), dict(raw_source.to_mapping())],
            scope={
                **_object(claim["scope"]),
                "subject_digest": acceptance.digest,
                "input_class": "unqualified local source",
                "observation_window": created_at,
            },
            limitations=[
                "Published test key is unprotected; source consistency is not Clock or authority admission."
            ],
        )
        claims.append(claim)
    body["claims"] = claims
    content = canonicalize_json(
        json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), limits=limits
    )
    content_ref = reference_bytes(
        content,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id="evidence_manifest_toolkit.manifest.v1",
        limits=limits,
    )
    (directory / content_ref.digest[7:]).write_bytes(content)
    receipt_ref, _ = software_manifest_receipt(
        content, table=table, scope=scope, created_at=created_at, directory=directory, limits=limits
    )
    return content_ref, receipt_ref


def software_manifest_receipt(
    content: bytes,
    *,
    table: BlobRef,
    scope: BlobRef,
    created_at: str,
    directory: Path,
    limits: Limits,
    statement_changes: dict[str, object] | None = None,
    signing_suffix: bytes = b"",
) -> tuple[BlobRef, bytes]:
    """Sign the whole actual manifest with real RFC test-key math and the separate V2 domain.

    Parameters
    ----------
    content : bytes
        Entire actual ordinary C0; no claim or source projection enters the signed target.
    table, scope : BlobRef
        Earlier full unprotected table and whole selected source rule.
    created_at : str
        Original captured signing token, without Clock admission.
    directory : Path
        Owned exact source store.
    limits : Limits
        Original public bounds for complete canonical identity.
    statement_changes : dict or None
        Whole deliberate target/source/scope conflicts, signed as actually supplied.
    signing_suffix : bytes
        Explicit appended bytes for a genuine wrong-message signature control.

    Returns
    -------
    tuple
        Whole canonical receipt identity and actual original bytes. Its published-key
        signature proves mathematical target/key only, not native authorization or custody.
    """
    content = canonicalize_json(content, limits=limits)
    content_ref = reference_bytes(
        content,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id="evidence_manifest_toolkit.manifest.v1",
        limits=limits,
    )
    claims = [_object(claim) for claim in _array(_object(json.loads(content))["claims"])]
    key = eddsa.import_private_key(_SEED)
    public_key = key.public_key().export_key(format="raw")
    assert isinstance(public_key, bytes)
    table_value = _object(json.loads((directory / table.digest[7:]).read_bytes()))
    key_entry = _object(_array(table_value["authorized_keys"])[0])
    assert (
        base64.urlsafe_b64encode(public_key).rstrip(b"=").decode("ascii")
        == key_entry["raw_public_key_base64url"]
    )
    statement: dict[str, object] = {
        "schema_id": "evidence_manifest_toolkit.signed_statement.v2",
        "profile_id": "evidence_manifest_toolkit.jcs_sha256_ed25519.authority_v2",
        "canonical_profile": "rfc8785-jcs-v1",
        "digest_algorithm": "sha256",
        "content_schema_id": content_ref.schema_id,
        "content_digest": content_ref.digest,
        "content_byte_length": content_ref.byte_length,
        "signer_key_id": "ed25519:" + hashlib.sha256(public_key).hexdigest(),
        "purpose": "evidence",
        "signature_context": "ordinary_statement",
        "authorizing_state_ref": dict(table.to_mapping()),
        "authorization_ref": dict(table.to_mapping()),
        "scope_ref": dict(scope.to_mapping()),
        "snapshot_ref": dict(table.to_mapping()),
        "claim_ids": sorted(
            (_text(claim["claim_id"]) for claim in claims), key=lambda s: s.encode("utf-16-be")
        ),
        "claimed_signed_at": created_at,
    }
    if statement_changes is not None:
        statement.update(statement_changes)
    statement_bytes = canonicalize_json(json.dumps(statement).encode("utf-8"), limits=limits)
    message = b"GOTM-EMT-AUTHORITY-V2\x00" + statement_bytes + signing_suffix
    signature = eddsa.new(key, "rfc8032").sign(message)
    eddsa.new(key.public_key(), "rfc8032").verify(message, signature)
    envelope = canonicalize_json(
        json.dumps(
            {
                "statement": statement,
                "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
            }
        ).encode("utf-8"),
        limits=limits,
    )
    envelope_ref = reference_bytes(
        envelope,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=None,
        limits=limits,
    )
    (directory / envelope_ref.digest[7:]).write_bytes(envelope)
    return envelope_ref, envelope
