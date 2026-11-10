# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole declared receiver transition inputs and independent faults

"""Materialise original receiver records without claiming a real durable receiver service."""

import json
from pathlib import Path

from tests.domain.native_possession_method_inputs import PossessionManifestWriter
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _array, _object

from evidence_manifest_toolkit import BlobRef


def receiver_input(
    challenge: BlobRef,
    proof: BlobRef,
    request: BlobRef,
    identity: dict[str, object],
    method: dict[str, object],
    conditions: BlobRef,
    directory: Path,
    writer: PossessionManifestWriter,
    case: str,
) -> tuple[BlobRef, tuple[BlobRef, str] | None]:
    """Build the entire candidate/transaction/head/commit graph in acyclic source order.

    Parameters
    ----------
    challenge, proof, request : BlobRef
        Actual complete earlier raw challenge, own-key signature bytes and request.
    identity, method : dict
        Entire selected declared runner and earlier fixed possession binding.
    conditions : BlobRef
        Explicit whole unqualified source disclosure, not an admitted bootstrap.
    directory : Path
        Actual owned raw file store.
    writer : PossessionManifestWriter
        Actual public-seal constructor for the already prepared independent caller schemas.
    case : str
        Named whole-source contradiction or matching unqualified input.

    Returns
    -------
    tuple
        Complete final commit C0 reference and the exact independently authored conflict,
        or None. No qualified nonce consumption, actual CAS, durability or Clock follows.
    """

    def ref(value: BlobRef) -> dict[str, str]:
        """Preserve all original reference assertions in each source use."""
        return dict(value.to_mapping())

    def store(value: dict[str, object]) -> BlobRef:
        """Store a whole native method source under its actual raw identity."""
        return _stored(value, directory)

    disclosure = ref(conditions)
    received_at = (
        "2040-01-01T00:00:00Z"
        if case == "receiver_time"
        else "2030-01-01T00:00:00Z"
        if case == "receiver_expiry"
        else "2020-01-01T00:00:00Z"
        if case == "receiver_before_issue"
        else "2024-01-01T00:00:00Z"
        if case == "receiver_issue_boundary"
        else "2025-01-01T00:00:00Z"
    )
    response = {
        "challenge_ref": ref(challenge),
        "proof_bytes_ref": ref(proof),
        "execution_request_ref": ref(request),
        "received_at": received_at,
        "raw_receiver_times_ref": disclosure,
    }
    previous = {
        "controller_identity_ref": disclosure,
        "method_ref": method["receiver_method_ref"],
        "sequence": "0",
        "previous_state_ref": None,
        "issued_challenge_refs": [] if case == "receiver_issued_missing" else [ref(challenge)],
        "completed_response_records": [response] if case == "receiver_replay" else [],
    }
    previous_ref = store(previous)
    following = {
        **previous,
        "sequence": "2" if case == "receiver_sequence" else "1",
        "previous_state_ref": disclosure if case == "receiver_fork" else ref(previous_ref),
        "completed_response_records": [*_array(previous["completed_response_records"]), response],
    }
    following_ref = store(following)
    conflict = (
        (previous_ref, "completed_response_records")
        if case == "receiver_replay"
        else (following_ref, "sequence")
        if case == "receiver_sequence"
        else (following_ref, "previous_state_ref")
        if case == "receiver_fork"
        else (previous_ref, "issued_challenge_refs")
        if case == "receiver_issued_missing"
        else None
    )
    completion = {
        "challenge_ref": ref(challenge),
        "proof_bytes_ref": disclosure if case == "receiver_proof" else ref(proof),
        "execution_request_ref": ref(request),
        "public_key_ref": identity["declared_public_key_ref"],
        "launch_record_ref": identity["actual_launch_or_declared_source_ref"],
        "process_identity_ref": identity["process_identity_ref"],
        "receiver_identity_ref": disclosure,
        "received_at": received_at,
        "raw_receiver_times_ref": disclosure,
        "previous_challenge_state_ref": ref(previous_ref),
        "next_challenge_state_ref": ref(following_ref),
        "receiver_method_ref": method["receiver_method_ref"],
        "receiver_qualification_ref": disclosure,
    }
    candidate = writer.manifest("receiver_completion_payload", completion, previous_ref)
    candidate_value = _object(json.loads((directory / candidate.digest[7:]).read_bytes()))
    completion_ref = BlobRef.from_mapping(_object(candidate_value["payload_ref"]))
    if case in {"receiver_proof", "receiver_time", "receiver_expiry", "receiver_before_issue"}:
        conflict = completion_ref, "proof_bytes_ref" if case == "receiver_proof" else "received_at"
    transaction = {
        "transaction_id": "unqualified-source-transaction",
        "previous_state_ref": ref(previous_ref),
        "next_state_ref": ref(following_ref),
        "candidate_completion_manifest_ref": ref(candidate),
        "receiver_method_ref": method["receiver_method_ref"],
        "controller_identity_ref": disclosure,
    }
    transaction_ref = store(transaction)
    head: dict[str, object] = {
        "state_ref": disclosure if case == "receiver_head" else ref(following_ref),
        "transaction_ref": ref(transaction_ref),
    }
    head_ref = store(head)
    stat = (directory / head_ref.digest[7:]).stat()
    observed = {
        key: str(getattr(stat, "st_" + field))
        for key, field in {
            "device": "dev",
            "inode": "ino",
            "uid": "uid",
            "gid": "gid",
            "mode": "mode",
            "size": "size",
            "mtime_ns": "mtime_ns",
            "ctime_ns": "ctime_ns",
        }.items()
    }
    if case == "receiver_head_mode":
        observed["mode"] = str(0o40700)
    elif case == "receiver_head_size":
        observed["size"] = str(stat.st_size + 1)
    observation = {
        "storage_binding_ref": method["receiver_method_ref"],
        "head_raw_ref": ref(head_ref),
        "before_stat": observed,
        "after_stat": dict(observed),
        "read_started_time_source_ref": disclosure,
        "read_finished_time_source_ref": disclosure,
        "reader_process_identity_ref": disclosure,
        "reader_environment_ref": disclosure,
        "reader_implementation_ref": disclosure,
        "reader_qualification_ref": disclosure,
    }
    if case == "receiver_head_unstable":
        observation["after_stat"] = {**observed, "size": str(stat.st_size + 1)}
    observation_ref = store(observation)
    if case == "receiver_head":
        conflict = head_ref, "state_ref"
    elif case == "receiver_head_unstable":
        conflict = observation_ref, "before_stat"
    elif case in {"receiver_head_mode", "receiver_head_size", "receiver_head_bound"}:
        conflict = observation_ref, "before_stat"
    commit = {
        "transaction_ref": ref(transaction_ref),
        "previous_state_ref": ref(previous_ref),
        "next_state_ref": ref(following_ref),
        "candidate_completion_manifest_ref": ref(candidate),
        "actual_head_observation_ref": ref(observation_ref),
        "commit_observation_time_source_ref": disclosure,
        "receiver_method_ref": method["receiver_method_ref"],
        "controller_identity_ref": disclosure,
    }
    return writer.manifest("receiver_commit_payload", commit, transaction_ref), conflict
