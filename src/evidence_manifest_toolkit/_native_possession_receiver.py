# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete declared challenge reception and commit sources

"""Check whole receiver state transitions without claiming durable CAS or trusted capture."""

from collections.abc import Mapping
from dataclasses import dataclass
from stat import S_ISREG
from typing import cast

from ._budget import ReferenceBudget
from ._closure import ClosureRoot
from ._codecs import decode_reference
from ._content import CompleteContent
from ._errors import InputRefused
from ._format_sources import FixedSource
from ._interfaces import Resolver
from ._json import JsonValue
from ._native_possession_context import native_source_utc
from ._native_possession_sources import (
    NativePossessionSources,
    acquire_possession_manifest,
    acquire_possession_record,
    possession_value,
)
from ._native_record_formats import NativePossessionRecord
from ._subject_formats import SubjectFormat
from ._values import Reason, Utc


@dataclass(frozen=True, slots=True)
class NativeReceiverSources:
    """Keep complete original receiver records and the separately validated candidate C0.

    Attributes
    ----------
    records : tuple of FixedSource
        Entire commit, transaction, completion, before/after state and head/storage records.
    candidate : CompleteContent
        Whole earlier candidate completion C0. Its presence proves no actual commitment.
    candidate_root : ClosureRoot
        Original full reference/bytes with explicit known native C0 dispatch, preserving
        parent-to-descendant depth even when optional schema metadata is absent.
    received_at : Utc
        Exact original Common-valid reception token, not an accepted event Clock.
    """

    records: tuple[FixedSource, ...]
    candidate: CompleteContent
    candidate_root: ClosureRoot
    received_at: Utc


def check_native_receiver_sources(
    sources: NativePossessionSources,
    *,
    method: FixedSource,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> NativeReceiverSources:
    """Recompute complete declared commit/state/head joins before own-key equation checks.

    Parameters
    ----------
    sources : NativePossessionSources
        Entire selected challenge/result/request/key/proof and original receiver C0.
    method : FixedSource
        Independently selected possession binding and exact receiver-method reference.
    formats : Mapping
        Original known structural lookup, never artifact-selected code.
    resolver : Resolver
        Sole bounded offline source. Historical head locations are never opened.
    budget : ReferenceBudget
        SAME cumulative operation allowance and source metadata cache.

    Returns
    -------
    NativeReceiverSources
        Whole source-consistent transition and original reception token. No authenticated
        issuer/receiver, unpredictable nonce, accepted time, protected custody, native
        file observation, actual CAS/durability or key-possession class is established.

    Raises
    ------
    InputRefused
        Original closed source, whole target/context/state/order or reception window conflicts.
    ReferenceUnavailable
        An exact original required receiver source is absent.
    ConfigurationError
        Fixed local grammar or original caller source configuration is invalid.
    """
    selected: list[FixedSource] = []

    def child(parent: FixedSource, field: str, kind: NativePossessionRecord) -> FixedSource:
        """Read the complete original child selected by a known owning-method field."""
        subject = parent.source.reference.digest
        result = acquire_possession_record(
            decode_reference(possession_value(parent)[field], subject=subject, pointer="/" + field),
            kind=kind,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=subject,
            pointer="/" + field,
        )
        selected.append(result)
        return result

    def manifest_value(content: CompleteContent) -> dict[str, JsonValue]:
        """Keep every native manifest field from its actual checked root."""
        ref = content.content_ref
        return cast(
            dict[str, JsonValue],
            content.closure.documents[ref.digest, ref.digest_basis, ref.byte_length].value,
        )

    result = possession_value(sources.result)
    subject = sources.result.source.reference.digest
    commit_ref = decode_reference(
        manifest_value(sources.completion_manifest)["payload_ref"],
        subject=subject,
        pointer="/receiver_completion_manifest_ref/payload_ref",
    )
    commit = acquire_possession_record(
        commit_ref,
        kind="receiver_commit_payload",
        formats=formats,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer="/receiver_completion_manifest_ref/payload_ref",
    )
    selected.append(commit)
    transaction = child(commit, "transaction_ref", "receiver_transaction")
    value = possession_value(commit)
    candidate_ref = decode_reference(
        value["candidate_completion_manifest_ref"],
        subject=commit_ref.digest,
        pointer="/candidate_completion_manifest_ref",
    )
    candidate = acquire_possession_manifest(
        candidate_ref,
        formats=formats,
        resolver=resolver,
        budget=budget,
        subject=commit_ref.digest,
        pointer="/candidate_completion_manifest_ref",
    )
    completion_ref = decode_reference(
        manifest_value(candidate)["payload_ref"],
        subject=candidate_ref.digest,
        pointer="/payload_ref",
    )
    completion = acquire_possession_record(
        completion_ref,
        kind="receiver_completion_payload",
        formats=formats,
        resolver=resolver,
        budget=budget,
        subject=candidate_ref.digest,
        pointer="/payload_ref",
    )
    selected.append(completion)
    previous = child(commit, "previous_state_ref", "challenge_state")
    following = child(commit, "next_state_ref", "challenge_state")
    head = child(commit, "actual_head_observation_ref", "receiver_head_observation")
    head_value = child(head, "head_raw_ref", "receiver_head_value")
    storage = child(head, "storage_binding_ref", "receiver_storage_binding")
    c, t, payload = value, possession_value(transaction), possession_value(completion)
    old, new = possession_value(previous), possession_value(following)
    h, stored, receiver = (
        possession_value(head),
        possession_value(head_value),
        possession_value(storage),
    )
    challenge = possession_value(sources.challenge)

    def check(source: FixedSource, field: str, actual: JsonValue, expected: JsonValue) -> None:
        """Locate one exact full-field contradiction without echoing received source data."""
        if actual != expected:
            raise InputRefused(
                Reason(
                    "invalid_claim",
                    source.source.reference.digest,
                    None,
                    "/" + field,
                    "Native challenge receiver sources conflict.",
                )
            )

    receiver_ref = possession_value(method)["receiver_method_ref"]
    for source, body in ((commit, c), (transaction, t), (completion, payload)):
        check(source, "receiver_method_ref", body["receiver_method_ref"], receiver_ref)
    for field in (
        "previous_state_ref",
        "next_state_ref",
        "candidate_completion_manifest_ref",
        "controller_identity_ref",
    ):
        check(transaction, field, t[field], c[field])
    for field, expected in (
        ("challenge_ref", result["challenge_ref"]),
        ("proof_bytes_ref", result["proof_bytes_ref"]),
        ("execution_request_ref", challenge["execution_request_ref"]),
        ("public_key_ref", challenge["public_key_ref"]),
        ("launch_record_ref", challenge["launch_record_ref"]),
        ("process_identity_ref", challenge["process_identity_ref"]),
        ("previous_challenge_state_ref", c["previous_state_ref"]),
        ("next_challenge_state_ref", c["next_state_ref"]),
    ):
        check(completion, field, payload[field], expected)
    for source, body in ((previous, old), (following, new)):
        check(source, "method_ref", body["method_ref"], receiver_ref)
        check(
            source,
            "controller_identity_ref",
            body["controller_identity_ref"],
            c["controller_identity_ref"],
        )
    check(following, "previous_state_ref", new["previous_state_ref"], c["previous_state_ref"])
    check(following, "sequence", new["sequence"], str(int(cast(str, old["sequence"])) + 1))
    check(
        following,
        "issued_challenge_refs",
        new["issued_challenge_refs"],
        old["issued_challenge_refs"],
    )
    if result["challenge_ref"] not in cast(list[JsonValue], old["issued_challenge_refs"]):
        check(previous, "issued_challenge_refs", False, True)
    prior = cast(list[dict[str, JsonValue]], old["completed_response_records"])
    if any(row["challenge_ref"] == result["challenge_ref"] for row in prior):
        check(previous, "completed_response_records", False, True)
    row = {
        field: payload[field]
        for field in (
            "challenge_ref",
            "proof_bytes_ref",
            "execution_request_ref",
            "received_at",
            "raw_receiver_times_ref",
        )
    }
    check(following, "completed_response_records", new["completed_response_records"], [*prior, row])
    check(head_value, "state_ref", stored["state_ref"], c["next_state_ref"])
    check(head_value, "transaction_ref", stored["transaction_ref"], c["transaction_ref"])
    check(head, "before_stat", h["before_stat"], h["after_stat"])
    before = cast(dict[str, JsonValue], h["before_stat"])
    head_bytes = cast(bytes, head_value.source.raw_bytes)
    if (
        not S_ISREG(int(cast(str, before["mode"])))
        or int(cast(str, before["size"])) != len(head_bytes)
        or len(head_bytes) > int(cast(str, receiver["maximum_head_bytes"]))
    ):
        check(head, "before_stat", False, True)
    check(head, "storage_binding_ref", h["storage_binding_ref"], receiver_ref)
    check(
        storage, "owner_identity_ref", receiver["owner_identity_ref"], c["controller_identity_ref"]
    )
    received = native_source_utc(completion, "received_at")
    if (
        not native_source_utc(sources.challenge, "issued_at").compare(received) <= 0
        or received.compare(native_source_utc(sources.challenge, "expires_at")) >= 0
    ):
        check(completion, "received_at", False, True)
    raw = budget.cached(
        candidate_ref, subject=commit_ref.digest, pointer="/candidate_completion_manifest_ref"
    )
    return NativeReceiverSources(
        tuple(selected),
        candidate,
        ClosureRoot(
            candidate_ref,
            cast(bytes, raw),
            expected_schema_id="evidence_manifest_toolkit.manifest.v1",
        ),
        received,
    )
