# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete deliberately unqualified rotation sources

"""Keep whole real native rotation inputs distinct from accepted machine authority."""

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

type _RotationJson = (
    None | bool | int | float | str | list[_RotationJson] | dict[str, _RotationJson]
)

ROTATION_SOURCE_CASES = (
    "initial_history",
    "counter_max",
    "counter_too_long",
    "unrotated",
    "current",
    "two_rotations",
    "historical",
    "until_withdrawal",
    "implicit_schema",
    "authority",
    "grant",
    "same_key",
    "wrong_initial",
    "old_key",
    "sequence",
    "time_order",
    "before_grant",
    "after_grant",
    "snapshot_key",
    "snapshot_future",
    "history_drop",
    "history_fork",
    "missing_rotation",
    "missing_parent",
    "depth",
    "control",
    "control_signer",
    "control_old_key",
    "control_previous",
    "control_early",
    "control_late",
    "missing_authorizing_state",
    "cli_current",
    "cli_control_signer",
    "cli_missing_rotation",
)


def protected_rotation_input(case: str, directory: Path) -> CertificateSourceCase:
    """Freeze entire source histories and actual native test receipts before public entry.

    Parameters
    ----------
    case : str
        Whole source-consistent state or one explicitly selected input contradiction.
    directory : Path
        Owned flat actual source store; no enrolled root or signer is installed.

    Returns
    -------
    CertificateSourceCase
        Full original public inputs, actual resolver bytes and exact source-error oracle.
        Deterministic test keys are unprotected and unenrolled. Consistent sources
        reach the real missing Clock refusal, never native/current admission.
    """
    chosen = protected_certificate_input(
        "until_withdrawal" if case == "until_withdrawal" else "direct", directory
    )
    caller = chosen.caller
    population = dict(chosen.population)

    def body(reference: BlobRef) -> dict[str, object]:
        """Keep the complete actual input body without a field projection."""
        return _object(
            json.loads(population[reference.digest + "|" + reference.digest_basis].read_bytes())
        )

    def store(raw: bytes, schema: str | None, media: str = "application/json") -> BlobRef:
        """Retain actual original source bytes and complete native metadata."""
        digest = hashlib.sha256(raw).hexdigest()
        path = directory / digest
        path.write_bytes(raw)
        reference = BlobRef(
            "sha256:" + digest,
            str(len(raw)),
            media,
            "raw_bytes" if schema is None else "jcs_content",
            schema,
        )
        population[reference.digest + "|" + reference.digest_basis] = path
        return reference

    def native(value: dict[str, object]) -> BlobRef:
        """Store the entire canonical source and optionally omit its schema assertion."""
        reference = store(
            rfc8785.dumps(cast(dict[str, _RotationJson], value)), cast(str, value["schema_id"])
        )
        return replace(reference, schema_id=None) if case == "implicit_schema" else reference

    grant, initial = body(caller.root_grant_ref), body(caller.current_authority_snapshot_ref)
    base = dict(caller.independent_root_selection_ref.to_mapping())
    keys = [eddsa.import_private_key(bytes([index]) * 32) for index in (1, 2, 3)]
    publics = [key.public_key().export_key(format="raw") for key in keys]
    assert all(isinstance(key, bytes) for key in publics)
    identifiers = ["ed25519:" + hashlib.sha256(key).hexdigest() for key in publics]
    public_refs = [store(key, None, "application/octet-stream") for key in publics]
    schema = "evidence_manifest_toolkit.authority_rotation.v2"

    def rotation(index: int, previous: BlobRef | None) -> dict[str, object]:
        """Retain every original native rotation field and explicit unqualified custody source."""
        return {
            "schema_id": schema,
            "authority_id": grant["authority_id"],
            "root_grant_ref": dict(caller.root_grant_ref.to_mapping()),
            "previous_rotation_ref": None if previous is None else dict(previous.to_mapping()),
            "old_key_id": grant["initial_issuer_key_id"] if index == 0 else identifiers[index - 1],
            "new_key_id": identifiers[index],
            "new_public_key_ref": dict(public_refs[index].to_mapping()),
            "actual_generation_custody_ref": base,
            "controller_ref": base,
            "effective_at": str(2021 + index) + "-01-01T00:00:00Z",
            "rotation_sequence": str(index + 1),
            "unchanged_scope_ref": base,
        }

    first_body = rotation(0, None)
    if case == "counter_max":
        first_body["rotation_sequence"] = "1" + "0" * 255
    if case == "wrong_initial":
        first_body["old_key_id"] = identifiers[1]
    first = native(first_body)
    second_body = rotation(1, first)
    if case == "counter_max":
        second_body["rotation_sequence"] = "1" + "0" * 254 + "1"
    if case == "counter_too_long":
        second_body["rotation_sequence"] = "1" + "0" * 256
    pointer = ""
    subject = None
    code = "policy_unavailable"
    missing = None
    changes: dict[str, tuple[str, object]] = {
        "authority": ("authority_id", "different-unqualified-authority"),
        "grant": ("root_grant_ref", base),
        "same_key": ("new_key_id", identifiers[0]),
        "old_key": ("old_key_id", grant["initial_issuer_key_id"]),
        "sequence": ("rotation_sequence", "1"),
        "time_order": ("effective_at", "2020-01-01T00:00:00Z"),
        "before_grant": ("effective_at", "2019-01-01T00:00:00Z"),
        "after_grant": ("effective_at", "2030-01-01T00:00:00Z"),
    }
    if case in changes:
        field, changed = changes[case]
        second_body[field] = changed
        pointer = "/" + field
    if case == "control_bad_new_key_length":
        second_body["new_public_key_ref"] = dict(
            store(publics[1][:-1], None, "application/octet-stream").to_mapping()
        )
    if case == "control_bad_new_key_id":
        second_body["new_key_id"] = identifiers[2]
    second = native(second_body)
    single = case in {"current", "wrong_initial"}
    head = first if single else second
    rotations: tuple[BlobRef, ...] = (first,) if single else (first, second)
    if case == "depth":
        head = native(rotation(2, second))
        rotations += (head,)
        chosen = replace(chosen, limits=replace(chosen.limits, max_graph_depth=2))
        pointer, subject, code = "/previous_rotation_ref", second.digest, "limit_exceeded"
    snapshot = copy.deepcopy(initial)
    snapshot.update(
        current_rotation_ref=dict(head.to_mapping()),
        current_issuer_key_id=identifiers[0]
        if single
        else identifiers[2]
        if case == "depth"
        else identifiers[1],
        issued_at="2024-01-01T00:00:00Z",
    )
    if case == "control_bad_new_key_id":
        snapshot["current_issuer_key_id"] = identifiers[2]
    if case == "unrotated":
        snapshot.update(
            current_rotation_ref=None, current_issuer_key_id=grant["initial_issuer_key_id"]
        )
        rotations = ()
    if case == "snapshot_key":
        snapshot["current_issuer_key_id"] = grant["initial_issuer_key_id"]
        pointer = "/current_issuer_key_id"
    if case == "snapshot_future":
        snapshot["issued_at"] = "2020-01-01T00:00:00Z"
        pointer = "/current_rotation_ref"
    archive = None
    if case in {"historical", "history_drop", "history_fork", "initial_history"}:
        earlier_head = first
        if case == "history_fork":
            earlier_head = native(
                {**first_body, "controller_ref": dict(caller.root_grant_ref.to_mapping())}
            )
        earlier = {
            **initial,
            "current_rotation_ref": dict(earlier_head.to_mapping()),
            "current_issuer_key_id": identifiers[0],
            "issued_at": "2021-01-01T00:00:00Z",
        }
        if case == "initial_history":
            earlier.update(
                current_rotation_ref=None,
                current_issuer_key_id=grant["initial_issuer_key_id"],
                issued_at="2020-01-01T00:00:00Z",
            )
        archive = native(earlier)
        snapshot.update(
            sequence=str(int(cast(str, initial["sequence"])) + 1),
            previous_snapshot_ref=dict(archive.to_mapping()),
        )
        if case == "history_drop":
            snapshot.update(
                current_rotation_ref=None, current_issuer_key_id=grant["initial_issuer_key_id"]
            )
        if case != "historical":
            pointer = "/current_rotation_ref"
        if case == "initial_history":
            pointer = ""
    current = native(snapshot)
    if case in {"snapshot_key", "snapshot_future", "history_drop", "history_fork"}:
        subject = current.digest
    elif case in changes:
        subject = second.digest
    elif case == "wrong_initial":
        pointer, subject = "/old_key_id", first.digest
    if case == "counter_too_long":
        pointer, subject, code = "/rotation_sequence", second.digest, "invalid_schema"
    control_case = case.startswith("control") or case == "missing_authorizing_state"
    if control_case:
        previous_head = first
        earlier_issuer = identifiers[0]
        if case == "control_previous":
            previous_head = native(
                {**first_body, "controller_ref": dict(caller.root_grant_ref.to_mapping())}
            )
        earlier = {
            **initial,
            "current_rotation_ref": dict(previous_head.to_mapping()),
            "current_issuer_key_id": earlier_issuer,
            "issued_at": "2021-01-01T00:00:00Z",
        }
        if case == "control_old_key":
            earlier.update(
                current_rotation_ref=None, current_issuer_key_id=grant["initial_issuer_key_id"]
            )
        if case == "control_early":
            earlier["issued_at"] = "2023-01-01T00:00:00Z"
        if case == "control_late":
            earlier["expires_at"] = "2022-01-01T00:00:00Z"
        if case in {
            "control_new_key_withdrawn",
            "control_other_key_withdrawn",
            "control_certificate_withdrawn",
            "control_later_withdrawal",
            "control_bad_withdrawn_key_length",
        }:
            withdrawn: dict[str, object] = dict(
                public_refs[2 if case == "control_other_key_withdrawn" else 1].to_mapping()
            )
            if case == "control_certificate_withdrawn":
                withdrawn = _object(cast(list[object], earlier["certificate_refs"])[0])
            if case == "control_bad_withdrawn_key_length":
                withdrawn = dict(
                    store(publics[2][:-1], None, "application/octet-stream").to_mapping()
                )
            revocation = {
                "target_kind": "certificate" if case == "control_certificate_withdrawn" else "key",
                "target_ref": withdrawn,
                "reason": "retirement",
                "reported_at": "2023-01-01T00:00:00Z"
                if case == "control_later_withdrawal"
                else "2021-01-01T00:00:00Z",
                "compromise_window": "unknown",
                "compromise_time_bounds_ref": None,
            }
            if case != "control_later_withdrawal":
                earlier["revocations"] = [revocation]
            snapshot["revocations"] = [revocation]
            current = native(snapshot)
        earlier_ref = native(earlier)
        signing_key = keys[0]
        signer_id = identifiers[0]
        if case == "control_signer":
            signing_key, signer_id = keys[2], identifiers[2]
        statement: dict[str, object] = {
            "schema_id": "evidence_manifest_toolkit.signed_statement.v2",
            "profile_id": "evidence_manifest_toolkit.jcs_sha256_ed25519.authority_v2",
            "canonical_profile": "rfc8785-jcs-v1",
            "digest_algorithm": "sha256",
            "content_schema_id": schema,
            "content_digest": second.digest,
            "content_byte_length": second.byte_length,
            "signer_key_id": signer_id,
            "purpose": "rotate_authority",
            "signature_context": "authority_control",
            "authorizing_state_ref": dict(earlier_ref.to_mapping()),
            "authorization_ref": dict(caller.root_grant_ref.to_mapping()),
            "scope_ref": base,
            "snapshot_ref": None,
            "claim_ids": [],
            "claimed_signed_at": "2022-01-01T00:00:00Z",
        }
        statement_ref = native(statement)
        message = b"GOTM-EMT-AUTHORITY-V2\x00" + rfc8785.dumps(
            cast(dict[str, _RotationJson], statement)
        )
        signature = eddsa.new(signing_key, "rfc8032").sign(message)
        eddsa.new(signing_key.public_key(), "rfc8032").verify(message, signature)
        raw = rfc8785.dumps(
            cast(
                dict[str, _RotationJson],
                {
                    "statement": statement,
                    "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
                },
            )
        )
        selection = body(caller.authority_control_selection_ref)
        selection["entries"] = [
            {
                "operation": "rotate_authority",
                "target_ref": dict(second.to_mapping()),
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
        selected = _stored_source(selection, directory)
        population[selected.digest + "|raw_bytes"] = directory / selected.digest[7:]
        caller = replace(caller, authority_control_selection_ref=selected, control_envelopes=(raw,))
        if case in {
            "control_signer",
            "control_old_key",
            "control_previous",
            "control_early",
            "control_late",
        }:
            pointer = (
                "/previous_rotation_ref"
                if case == "control_previous"
                else "/effective_at"
                if case in {"control_early", "control_late"}
                else "/old_key_id"
            )
            subject = second.digest
        if case == "missing_authorizing_state":
            missing = earlier_ref
    if case in {
        "control_new_key_withdrawn",
        "control_bad_new_key_length",
        "control_bad_new_key_id",
    }:
        pointer, subject = "/new_public_key_ref", second.digest
    if case == "control_bad_withdrawn_key_length":
        pointer, subject = "/revocations/0/target_ref", earlier_ref.digest
    if case in {"missing_rotation", "missing_parent"}:
        missing = second if case == "missing_rotation" else first
    if missing is not None:
        population[missing.digest + "|" + missing.digest_basis].unlink()
    caller = replace(caller, current_authority_snapshot_ref=current)
    if case == "historical":
        assert archive is not None
        caller = replace(
            caller, evaluation_mode="historical", archived_authority_snapshot_ref=archive
        )
    required = tuple(
        ref
        for ref in chosen.required_sources
        if ref
        not in {
            chosen.caller.current_authority_snapshot_ref,
            chosen.caller.authority_control_selection_ref,
        }
    ) + (current, caller.authority_control_selection_ref, *rotations)
    return replace(
        chosen,
        caller=caller,
        population=population,
        missing=missing,
        expected_subject=subject,
        expected_pointer=pointer,
        expected_code=code,
        required_sources=required,
    )
