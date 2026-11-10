# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete declared issuer state and head input controls

"""Build explicit unqualified issuance sources without a receiver service or native bootstrap."""

import base64
import json
from pathlib import Path

from tests.domain.native_possession_method_inputs import PAYLOAD_IDS
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _array, _object

from evidence_manifest_toolkit import BlobRef

ISSUANCE_BASE = (
    "issuer_matching",
    "issuer_challenge",
    "issuer_method",
    "issuer_identity",
    "issuer_time_source",
    "issuer_state_method",
    "issuer_state_controller",
    "issuer_previous",
    "issuer_sequence",
    "issuer_reissued",
    "issuer_issued_population",
    "issuer_completed_population",
    "issuer_prior_retained",
    "issuer_prior_dropped",
    "issuer_completion_retained",
    "issuer_completion_dropped",
    "issuer_head_state",
    "issuer_head_binding",
    "issuer_storage_owner",
    "issuer_head_unstable",
    "issuer_head_mode",
    "issuer_head_size",
    "issuer_head_bound",
    "issuer_journal_null",
    "issuer_journal_missing",
    "issuer_journal_bytes",
    "issuer_receiver_rule",
)
ISSUANCE_CASES = tuple("reproduction_possession_" + name for name in ISSUANCE_BASE) + (
    "cli_reproduction_possession_issuer_challenge",
    "cli_reproduction_possession_issuer_journal_missing",
    "protected_reproduction_possession_issuer_matching",
)


def issuer_input(
    challenge: BlobRef,
    *,
    issuer: dict[str, object],
    receiver_method: object,
    conditions: BlobRef,
    directory: Path,
    case: str,
) -> tuple[BlobRef, tuple[BlobRef, str] | None, BlobRef]:
    """Materialise the complete acyclic declared issuance state and actual head bytes.

    Parameters
    ----------
    challenge : BlobRef
        Entire earlier actual raw challenge; it references no future state or C0.
    issuer : dict
        Complete independently selected static issuer rule.
    receiver_method : object
        Distinct earlier receiver-storage source, used only for a named wrong-binding control.
    conditions : BlobRef
        Original explicit unqualified-source disclosure, not a trusted bootstrap.
    directory : Path
        Actual owned source store; no persistent controller or service is activated.
    case : str
        Whole named source relation, preservation, byte or missing-journal control.

    Returns
    -------
    tuple
        Complete issuer-observation reference, independently expected conflicting
        source/field when present, and whole raw journal reference. Prior response
        rows remain unqualified source inputs; no nonce, event, native process,
        actual journal grammar or atomic/durable installation is accepted.
    """

    def ref(value: BlobRef) -> dict[str, str]:
        """Preserve every original reference assertion."""
        return dict(value.to_mapping())

    def store(value: dict[str, object]) -> BlobRef:
        """Retain the entire raw declared source under its actual identity."""
        return _stored(value, directory)

    disclosure = ref(conditions)
    method = issuer["challenge_issuance_method_ref"]
    previous: dict[str, object] = {
        "controller_identity_ref": issuer["issuer_identity_ref"],
        "method_ref": method,
        "sequence": "0",
        "previous_state_ref": None,
        "issued_challenge_refs": [ref(challenge)] if case == "issuer_reissued" else [],
        "completed_response_records": [],
    }
    if case in {
        "issuer_prior_retained",
        "issuer_prior_dropped",
        "issuer_completion_retained",
        "issuer_completion_dropped",
    }:
        bootstrap = store(previous)
        old_challenge = _object(json.loads((directory / challenge.digest[7:]).read_bytes()))
        old_challenge["nonce_base64url"] = (
            base64.urlsafe_b64encode(bytes([255]) * 32).rstrip(b"=").decode()
        )
        old_challenge["issued_at"] = "2023-01-01T00:00:00Z"
        prior = _stored(old_challenge, directory, schema_id=PAYLOAD_IDS["challenge"])
        previous.update(
            sequence="1", previous_state_ref=ref(bootstrap), issued_challenge_refs=[ref(prior)]
        )
        if case in {"issuer_completion_retained", "issuer_completion_dropped"}:
            issue = store(previous)
            previous.update(
                sequence="2",
                previous_state_ref=ref(issue),
                completed_response_records=[
                    {
                        "challenge_ref": ref(prior),
                        "proof_bytes_ref": disclosure,
                        "execution_request_ref": old_challenge["execution_request_ref"],
                        "received_at": "2023-01-02T00:00:00Z",
                        "raw_receiver_times_ref": disclosure,
                    }
                ],
            )
    previous_ref = store(previous)
    old_issued = list(_array(previous["issued_challenge_refs"]))
    following: dict[str, object] = {
        **previous,
        "sequence": str(int(str(previous["sequence"])) + 1),
        "previous_state_ref": ref(previous_ref),
        "issued_challenge_refs": [*old_issued, ref(challenge)],
    }
    field = {
        "issuer_state_method": "method_ref",
        "issuer_state_controller": "controller_identity_ref",
        "issuer_previous": "previous_state_ref",
        "issuer_sequence": "sequence",
        "issuer_issued_population": "issued_challenge_refs",
        "issuer_prior_dropped": "issued_challenge_refs",
        "issuer_completed_population": "completed_response_records",
        "issuer_completion_dropped": "completed_response_records",
    }.get(case)
    if case == "issuer_state_method":
        following["method_ref"] = disclosure
    elif case == "issuer_state_controller":
        following["controller_identity_ref"] = ref(challenge)
    elif case == "issuer_previous":
        following["previous_state_ref"] = disclosure
    elif case == "issuer_sequence":
        following["sequence"] = str(int(str(previous["sequence"])) + 2)
    elif case == "issuer_issued_population":
        following["issued_challenge_refs"] = []
    elif case == "issuer_prior_dropped":
        following["issued_challenge_refs"] = [ref(challenge)]
    elif case == "issuer_completed_population":
        following["completed_response_records"] = [
            {
                "challenge_ref": ref(challenge),
                "proof_bytes_ref": disclosure,
                "execution_request_ref": _object(
                    json.loads((directory / challenge.digest[7:]).read_bytes())
                )["execution_request_ref"],
                "received_at": "2025-01-01T00:00:00Z",
                "raw_receiver_times_ref": disclosure,
            }
        ]
    elif case == "issuer_completion_dropped":
        following["completed_response_records"] = []
    following_ref = store(following)
    conflict = (following_ref, field) if field is not None else None
    if case == "issuer_reissued":
        conflict = previous_ref, "issued_challenge_refs"
    journal = store(
        {
            "source": "Unqualified opaque issuer journal; no native transaction or durability qualification.",
            "challenge_ref": ref(challenge),
            "previous_state_ref": ref(previous_ref),
            "next_state_ref": ref(following_ref),
            "method_ref": method,
            "conditions_ref": disclosure,
        }
    )
    head_ref = store(
        {
            "state_ref": disclosure if case == "issuer_head_state" else ref(following_ref),
            "transaction_ref": None if case == "issuer_journal_null" else ref(journal),
        }
    )
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
    if case == "issuer_head_mode":
        observed["mode"] = str(0o40700)
    elif case == "issuer_head_size":
        observed["size"] = str(stat.st_size + 1)
    head = {
        "storage_binding_ref": receiver_method if case == "issuer_head_binding" else method,
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
    if case == "issuer_head_unstable":
        head["after_stat"] = {**observed, "inode": str(stat.st_ino + 1)}
    head_observation = store(head)
    if case == "issuer_head_state":
        conflict = head_ref, "state_ref"
    elif case == "issuer_journal_null":
        conflict = head_ref, "transaction_ref"
    elif case == "issuer_journal_bytes":
        conflict = head_ref, "transaction_ref"
    elif case == "issuer_head_binding":
        conflict = head_observation, "storage_binding_ref"
    elif case in {
        "issuer_head_unstable",
        "issuer_head_mode",
        "issuer_head_size",
        "issuer_head_bound",
    }:
        conflict = head_observation, "before_stat"
    elif case == "issuer_storage_owner":
        conflict = BlobRef.from_mapping(_object(method)), "owner_identity_ref"
    challenge_value = _object(json.loads((directory / challenge.digest[7:]).read_bytes()))
    observation = {
        "challenge_ref": ref(challenge),
        "previous_state_ref": ref(previous_ref),
        "next_state_ref": ref(following_ref),
        "actual_head_observation_ref": ref(head_observation),
        "issuance_time_sources_ref": challenge_value["issuance_time_sources_ref"],
        "issuer_method_ref": method,
        "issuer_identity_ref": issuer["issuer_identity_ref"],
        "issuer_qualification_ref": disclosure,
    }
    selected_field = {
        "issuer_challenge": "challenge_ref",
        "issuer_method": "issuer_method_ref",
        "issuer_identity": "issuer_identity_ref",
        "issuer_time_source": "issuance_time_sources_ref",
    }.get(case)
    if selected_field is not None:
        observation[selected_field] = (
            receiver_method
            if case == "issuer_method"
            else ref(challenge)
            if case in {"issuer_identity", "issuer_time_source"}
            else disclosure
        )
    observation_ref = _stored(
        observation, directory, schema_id=PAYLOAD_IDS["issuer_issuance_observation"]
    )
    if selected_field is not None:
        conflict = observation_ref, selected_field
    return observation_ref, conflict, journal
