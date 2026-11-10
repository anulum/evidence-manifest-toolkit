# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete declared challenge issuance and head sources

"""Bind issuer observation and whole declared state without admitting a controller or nonce."""

from collections.abc import Mapping
from dataclasses import dataclass
from stat import S_ISREG
from typing import cast

from ._acquisition import acquire_reference, identity_reason
from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._errors import InputRefused
from ._format_sources import FixedSource
from ._interfaces import Resolver
from ._json import JsonValue
from ._native_possession_sources import (
    NativePossessionSources,
    acquire_possession_record,
    possession_value,
)
from ._native_record_formats import NativePossessionRecord
from ._subject_formats import SubjectFormat
from ._values import BlobRef, Reason


@dataclass(frozen=True, slots=True)
class NativeIssuanceSources:
    """Retain the whole original issuance observation, states and actual raw journal.

    Attributes
    ----------
    records : tuple of FixedSource
        Complete selected observation, previous/next states, head observation/value
        and independently selected storage binding under existing shared head grammar.
    journal_reference : BlobRef
        Whole actual non-bootstrap journal reference selected by the head source.
    journal_bytes : bytes
        Entire identity-checked original journal. No journal grammar, transaction
        execution, atomicity, durable storage, issuer eligibility or Clock is inferred.
    """

    records: tuple[FixedSource, ...]
    journal_reference: BlobRef
    journal_bytes: bytes


def check_native_issuance_sources(
    sources: NativePossessionSources,
    *,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> NativeIssuanceSources:
    """Bind the complete declared issuance transition to the independent issuer rule.

    Parameters
    ----------
    sources : NativePossessionSources
        Actual whole result/challenge, independently selected issuer and complete C0s.
    formats : Mapping
        Original structural lookup; no received field selects a decoder or native class.
    resolver : Resolver
        Sole bounded byte source. Historical head locations are never opened.
    budget : ReferenceBudget
        SAME original cumulative acquisition allowance, including all prior sources.

    Returns
    -------
    NativeIssuanceSources
        Whole source-consistent observation and raw journal for later actual native
        qualification. No trusted bootstrap, unpredictable nonce, qualified issuer,
        authenticated receipt, historical process, atomic journal/CAS or Clock follows.

    Raises
    ------
    InputRefused
        Original whole shape, selected identity/method/challenge/time, state population,
        head metadata/bytes or original journal identity conflicts.
    ReferenceUnavailable
        An exact original required source or journal is absent; missing never means0.
    ConfigurationError
        The fixed known method grammar or actual caller source configuration is invalid.
    """
    selected: list[FixedSource] = []

    def read(
        reference: BlobRef, kind: NativePossessionRecord, subject: str, pointer: str
    ) -> FixedSource:
        """Retain one whole record under its owning literal source context."""
        record = acquire_possession_record(
            reference,
            kind=kind,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=subject,
            pointer=pointer,
        )
        selected.append(record)
        return record

    def child(parent: FixedSource, field: str, kind: NativePossessionRecord) -> FixedSource:
        """Preserve the complete actual field reference and its original source position."""
        subject = parent.source.reference.digest
        reference = decode_reference(
            possession_value(parent)[field], subject=subject, pointer="/" + field
        )
        return read(reference, kind, subject, "/" + field)

    def check(source: FixedSource, field: str, actual: JsonValue, expected: JsonValue) -> None:
        """Locate an exact full source conflict without echoing received values."""
        if actual != expected:
            raise InputRefused(
                Reason(
                    "invalid_claim",
                    source.source.reference.digest,
                    None,
                    "/" + field,
                    "Native challenge issuance sources conflict.",
                )
            )

    c0 = sources.challenge_manifest
    target = c0.content_ref
    manifest = cast(
        dict[str, JsonValue],
        c0.closure.documents[target.digest, target.digest_basis, target.byte_length].value,
    )
    observation_ref = decode_reference(
        manifest["source_ref"], subject=target.digest, pointer="/source_ref"
    )
    observation = read(observation_ref, "issuer_issuance_observation", target.digest, "/source_ref")
    observed = possession_value(observation)
    issuer, challenge = possession_value(sources.issuer), possession_value(sources.challenge)
    method_ref, controller = issuer["challenge_issuance_method_ref"], issuer["issuer_identity_ref"]
    for field, expected in (
        ("challenge_ref", possession_value(sources.result)["challenge_ref"]),
        ("issuer_method_ref", method_ref),
        ("issuer_identity_ref", controller),
        ("issuance_time_sources_ref", challenge["issuance_time_sources_ref"]),
    ):
        check(observation, field, observed[field], expected)

    previous = child(observation, "previous_state_ref", "challenge_state")
    following = child(observation, "next_state_ref", "challenge_state")
    head = child(observation, "actual_head_observation_ref", "receiver_head_observation")
    head_value = child(head, "head_raw_ref", "receiver_head_value")
    storage = child(head, "storage_binding_ref", "receiver_storage_binding")
    old, new = possession_value(previous), possession_value(following)
    h, stored, binding = (
        possession_value(head),
        possession_value(head_value),
        possession_value(storage),
    )
    for source, value in ((previous, old), (following, new)):
        check(source, "method_ref", value["method_ref"], method_ref)
        check(source, "controller_identity_ref", value["controller_identity_ref"], controller)
    check(
        following, "previous_state_ref", new["previous_state_ref"], observed["previous_state_ref"]
    )
    check(following, "sequence", new["sequence"], str(int(cast(str, old["sequence"])) + 1))
    issued = cast(list[JsonValue], old["issued_challenge_refs"])
    if observed["challenge_ref"] in issued:
        check(previous, "issued_challenge_refs", False, True)
    check(
        following,
        "issued_challenge_refs",
        new["issued_challenge_refs"],
        [*issued, observed["challenge_ref"]],
    )
    check(
        following,
        "completed_response_records",
        new["completed_response_records"],
        old["completed_response_records"],
    )
    check(head_value, "state_ref", stored["state_ref"], observed["next_state_ref"])
    check(head, "storage_binding_ref", h["storage_binding_ref"], method_ref)
    check(storage, "owner_identity_ref", binding["owner_identity_ref"], controller)
    check(head, "before_stat", h["before_stat"], h["after_stat"])
    before = cast(dict[str, JsonValue], h["before_stat"])
    raw_head = cast(bytes, head_value.source.raw_bytes)
    if (
        not S_ISREG(int(cast(str, before["mode"])))
        or int(cast(str, before["size"])) != len(raw_head)
        or len(raw_head) > int(cast(str, binding["maximum_head_bytes"]))
    ):
        check(head, "before_stat", False, True)
    if stored["transaction_ref"] is None:
        check(head_value, "transaction_ref", False, True)
    journal = decode_reference(
        stored["transaction_ref"],
        subject=head_value.source.reference.digest,
        pointer="/transaction_ref",
    )
    raw_journal = acquire_reference(
        journal,
        resolver=resolver,
        budget=budget,
        subject=head_value.source.reference.digest,
        pointer="/transaction_ref",
    )
    failure = identity_reason(
        journal,
        raw_journal,
        budget=budget,
        subject=head_value.source.reference.digest,
        pointer="/transaction_ref",
    )
    if failure is not None:
        raise InputRefused(failure)
    return NativeIssuanceSources(tuple(selected), journal, raw_journal)
