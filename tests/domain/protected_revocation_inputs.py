# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole unqualified withdrawal source inputs

"""Keep complete real withdrawal input bodies separate from admitted owner authority."""

import base64
import copy
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
from tests.domain.test_software_sources import _stored_source
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef

type _RevocationJson = (
    None | bool | int | float | str | list[_RevocationJson] | dict[str, _RevocationJson]
)

REVOCATION_SOURCE_CASES = (
    "append",
    "after_machine_expiry",
    "unchanged",
    "removed",
    "reordered",
    "changed_old",
    "duplicate",
    "no_previous",
    "wrong_previous",
    "sequence",
    "time",
    "empty_window",
    "authority_id",
    "root_grant_ref",
    "current_issuer_key_id",
    "current_rotation_ref",
    "registry_ref",
    "certificate_refs",
    "identity_rule_refs",
    "missing_previous",
    "cli_append",
    "cli_reordered",
    "cli_missing_previous",
)


def protected_revocation_input(case: str, directory: Path) -> CertificateSourceCase:
    """Build complete selected withdrawal receipts before the real verification entry.

    Parameters
    ----------
    case : str
        Whole source-consistent declaration or one actual source-delta counterfactual.
    directory : Path
        Owned flat content-addressed input store; no root or provider is installed.

    Returns
    -------
    CertificateSourceCase
        Full original public inputs and exact source oracle. Published RFC8032 test-key
        signatures are real, unprotected and unenrolled. Source consistency reaches
        the actual missing Clock refusal, never admitted withdrawal or positive state.
    """
    chosen = protected_certificate_input("direct", directory)
    population = dict(chosen.population)

    def body(reference: BlobRef) -> dict[str, object]:
        """Read a whole actual stored source without projecting its state fields."""
        return _object(
            json.loads(population[reference.digest + "|" + reference.digest_basis].read_bytes())
        )

    def store(value: dict[str, object]) -> BlobRef:
        """Retain complete canonical native bytes and their full original reference."""
        raw = rfc8785.dumps(cast(dict[str, _RevocationJson], value))
        digest = hashlib.sha256(raw).hexdigest()
        path = directory / digest
        path.write_bytes(raw)
        reference = BlobRef(
            "sha256:" + digest,
            str(len(raw)),
            "application/json",
            "jcs_content",
            cast(str, value["schema_id"]),
        )
        population[reference.digest + "|jcs_content"] = path
        return reference

    caller = chosen.caller
    grant = caller.root_grant_ref
    original = caller.current_authority_snapshot_ref
    previous = body(original)
    revocations = [
        {
            "target_kind": "authority_scope",
            "target_ref": dict(ref.to_mapping()),
            "reason": "compromise",
            "reported_at": "2020-01-01T00:00:00Z",
            "compromise_window": "unknown",
            "compromise_time_bounds_ref": None,
        }
        for ref in (grant, caller.independent_root_selection_ref, original)
    ]
    previous["revocations"] = revocations[:2]
    parent = store(previous)
    target = copy.deepcopy(previous)
    target.update(
        sequence=str(int(cast(str, previous["sequence"])) + 1),
        previous_snapshot_ref=dict(parent.to_mapping()),
        revocations=revocations,
    )
    pointer = ""
    missing = None
    if case == "after_machine_expiry":
        target.update(issued_at="2031-01-01T00:00:00Z", expires_at="2032-01-01T00:00:00Z")
    if case in {"unchanged", "removed", "reordered", "changed_old", "duplicate"}:
        pointer = "/revocations"
        target["revocations"] = (
            revocations[:2]
            if case == "unchanged"
            else revocations[1:]
            if case == "removed"
            else [revocations[1], revocations[0], revocations[2]]
            if case == "reordered"
            else [{**revocations[0], "reported_at": "2021-01-01T00:00:00Z"}, *revocations[1:]]
            if case == "changed_old"
            else [*revocations, revocations[-1]]
        )
    if case in {"no_previous", "wrong_previous"}:
        target["previous_snapshot_ref"] = (
            None if case == "no_previous" else dict(original.to_mapping())
        )
        pointer = "/previous_snapshot_ref"
    if case == "sequence":
        target["sequence"] = previous["sequence"]
        pointer = "/sequence"
    if case == "time":
        target["issued_at"] = "2019-01-01T00:00:00Z"
        pointer = "/issued_at"
    if case == "empty_window":
        target["expires_at"] = target["issued_at"]
        pointer = "/expires_at"
    if case in {
        "authority_id",
        "root_grant_ref",
        "current_issuer_key_id",
        "current_rotation_ref",
        "registry_ref",
        "certificate_refs",
        "identity_rule_refs",
    }:
        pointer = "/" + case
        target[case] = (
            "different-unqualified-authority"
            if case == "authority_id"
            else dict(caller.independent_root_selection_ref.to_mapping())
            if case == "root_grant_ref"
            else "ed25519:" + "1" * 64
            if case == "current_issuer_key_id"
            else []
            if case == "certificate_refs"
            else [dict(grant.to_mapping())]
            if case == "identity_rule_refs"
            else dict(grant.to_mapping())
        )
    target_ref = store(target)
    # Published RFC8032 section7.1 key; never operational or protected authority.
    key = eddsa.import_private_key(
        bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    )
    public = key.public_key().export_key(format="raw")
    assert isinstance(public, bytes)
    signer = "ed25519:" + hashlib.sha256(public).hexdigest()
    statement: dict[str, object] = {
        "schema_id": "evidence_manifest_toolkit.signed_statement.v2",
        "profile_id": "evidence_manifest_toolkit.jcs_sha256_ed25519.authority_v2",
        "canonical_profile": "rfc8785-jcs-v1",
        "digest_algorithm": "sha256",
        "content_schema_id": target_ref.schema_id,
        "content_digest": target_ref.digest,
        "content_byte_length": target_ref.byte_length,
        "signer_key_id": signer,
        "purpose": "revoke_descendants",
        "signature_context": "authority_control",
        "authorizing_state_ref": dict(parent.to_mapping()),
        "authorization_ref": dict(grant.to_mapping()),
        "scope_ref": dict(caller.independent_root_selection_ref.to_mapping()),
        "snapshot_ref": None,
        "claim_ids": [],
        "claimed_signed_at": "2026-10-03T12:00:00Z",
    }
    statement_ref = store(statement)
    message = b"GOTM-EMT-AUTHORITY-V2\x00" + rfc8785.dumps(
        cast(dict[str, _RevocationJson], statement)
    )
    signature = eddsa.new(key, "rfc8032").sign(message)
    eddsa.new(key.public_key(), "rfc8032").verify(message, signature)
    raw = rfc8785.dumps(
        cast(
            dict[str, _RevocationJson],
            {
                "statement": statement,
                "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
            },
        )
    )
    selection = body(caller.authority_control_selection_ref)
    selection["entries"] = [
        {
            "operation": "revoke_descendants",
            "target_ref": dict(target_ref.to_mapping()),
            "statement_ref": dict(statement_ref.to_mapping()),
            "envelope_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            **{
                name: statement[name]
                for name in (
                    "authorizing_state_ref",
                    "authorization_ref",
                    "scope_ref",
                    "signer_key_id",
                )
            },
        }
    ]
    selection_ref = _stored_source(selection, directory)
    population[selection_ref.digest + "|raw_bytes"] = directory / selection_ref.digest[7:]
    if case == "missing_previous":
        population[parent.digest + "|jcs_content"].unlink()
        missing = parent
    return replace(
        chosen,
        population=population,
        caller=replace(
            caller,
            current_authority_snapshot_ref=parent,
            authority_control_selection_ref=selection_ref,
            control_envelopes=(raw,),
        ),
        missing=missing,
        expected_subject=target_ref.digest if pointer else None,
        expected_pointer=pointer,
        required_sources=(
            *chosen.required_sources,
            parent,
            target_ref,
            statement_ref,
            selection_ref,
        ),
    )
