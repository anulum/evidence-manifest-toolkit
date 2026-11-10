# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole selected protected snapshot source histories

"""Retain complete snapshot histories without treating their declarations as authority."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

import rfc8785

from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource, acquire_fixed_source
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._subject_formats import SubjectFormat
from ._values import BlobRef, Digest, Reason, Utc


def protected_source_conflict(
    subject: Digest, pointer: str, *, code: str = "policy_unavailable"
) -> InputRefused:
    """Locate a source contradiction without asserting a protected-state verdict.

    Parameters
    ----------
    subject : str
        Actual selecting policy or whole source identity.
    pointer : str
        Original affected field within that complete source.
    code : str
        Existing source, cycle or operation-limit reason category.

    Returns
    -------
    InputRefused
        Complete fixed five-field diagnostic without received source text.
    """
    return InputRefused(Reason(code, subject, None, pointer, "Protected state sources conflict."))


def acquire_protected_native_source(
    reference: BlobRef,
    *,
    format_name: str,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> FixedSource:
    """Acquire a required whole native body using its independently fixed structural method.

    Parameters
    ----------
    reference : BlobRef
        Entire original caller or earlier-source argument.
    format_name : str
        Owning code's literal native format, never received executable dispatch.
    formats : Mapping
        Original validated internal format lookup.
    resolver : Resolver
        Sole original bounded offline source.
    budget : ReferenceBudget
        SAME cumulative operation quota.
    subject : str
        Actual enclosing source identity.
    pointer : str
        Original containing reference position.

    Returns
    -------
    FixedSource
        Whole actual source, with no key, custody or state admission.

    Raises
    ------
    ReferenceUnavailable
        The exact original source argument is unavailable.
    InputRefused
        Original strict source, metadata, schema or operation bounds fail.
    """
    source = acquire_fixed_source(
        reference,
        format_name=format_name,
        formats=formats,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer=pointer,
    )
    if source.source.raw_bytes is None:
        raise ReferenceUnavailable(reference)
    if source.source.document is None:
        raise InputRefused(source.source.reasons[0])
    return source


@dataclass(frozen=True, slots=True)
class ProtectedSnapshotSource:
    """Keep one complete native declaration and its necessary source-history properties.

    Attributes
    ----------
    fixed : FixedSource
        Complete original reference, bytes, parsed body and fixed native schema.
    authority_id, sequence : str, int
        Declared stream and exact unbounded counter; original tokens remain in fixed.
    issued_at, expires_at : Utc
        Exact finite nonempty source window, without qualified Clock or eligibility.
    previous_reference : BlobRef or None
        Entire original predecessor, absent only at the declared initial boundary.
    revocations : tuple of bytes
        Complete canonical original rows, preserving every compromise/source member.
        Source consistency does not authenticate any withdrawal authority.
    """

    fixed: FixedSource
    authority_id: str
    sequence: int
    issued_at: Utc
    expires_at: Utc
    previous_reference: BlobRef | None
    revocations: tuple[bytes, ...]


def acquire_protected_snapshot(
    reference: BlobRef,
    *,
    grant_reference: BlobRef,
    authority_id: str,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> ProtectedSnapshotSource:
    """Check a full snapshot's selected grant, stream, window and unique whole populations.

    Parameters
    ----------
    reference : BlobRef
        Exact current, archive or predecessor source.
    grant_reference : BlobRef
        Independently selected entire grant, not a grant chosen by this snapshot.
    authority_id : str
        Actual selected grant's complete declared stream identifier.
    formats : Mapping
        Original validated fixed structural lookup.
    resolver : Resolver
        Sole original source, without state discovery.
    budget : ReferenceBudget
        SAME original operation quota.
    subject : str
        Whole selecting source identity.
    pointer : str
        Original source/caller reference position.

    Returns
    -------
    ProtectedSnapshotSource
        Necessary whole source consistency; not an authenticated positive-use state.

    Raises
    ------
    InputRefused
        Original source/schema/quota, full grant/stream/window or population conflict.
    ReferenceUnavailable
        The exact original required source cannot be read.
    """
    fixed = acquire_protected_native_source(
        reference,
        format_name="evidence_manifest_toolkit.authority_snapshot.v2",
        formats=formats,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer=pointer,
    )
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, fixed.source.document).value)
    for field, expected in (
        ("authority_id", authority_id),
        ("root_grant_ref", dict(grant_reference.to_mapping())),
    ):
        if value[field] != expected:
            raise protected_source_conflict(reference.digest, "/" + field)
    issued, expires = Utc(value["issued_at"]), Utc(value["expires_at"])
    if issued.compare(expires) >= 0:
        raise protected_source_conflict(reference.digest, "/expires_at")
    populations = {
        name: tuple(rfc8785.dumps(row) for row in cast(list[JsonValue], value[name]))
        for name in ("certificate_refs", "identity_rule_refs", "revocations")
    }
    for name, rows in populations.items():
        if len(rows) != len(set(rows)):
            raise protected_source_conflict(reference.digest, "/" + name)
    previous = value["previous_snapshot_ref"]
    return ProtectedSnapshotSource(
        fixed,
        authority_id,
        int(cast(str, value["sequence"])),
        issued,
        expires,
        None
        if previous is None
        else decode_reference(previous, subject=reference.digest, pointer="/previous_snapshot_ref"),
        populations["revocations"],
    )


def acquire_protected_snapshot_history(
    first: ProtectedSnapshotSource,
    *,
    grant_reference: BlobRef,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> tuple[ProtectedSnapshotSource, ...]:
    """Retain every earlier whole snapshot while enforcing bounds and withdrawal conservation.

    Parameters
    ----------
    first : ProtectedSnapshotSource
        Entire actual selected current or archive source.
    grant_reference : BlobRef
        Independently selected whole grant shared by this declared stream.
    formats : Mapping
        Original validated fixed structural lookup.
    resolver : Resolver
        Original bounded predecessor source.
    budget : ReferenceBudget
        SAME operation quota and original maximum graph depth.

    Returns
    -------
    tuple of ProtectedSnapshotSource
        Complete newest-to-initial source history. An initial declaration does not
        supply an accepted bootstrap anchor or permit a positive state transition.

    Raises
    ------
    InputRefused
        Source, cycle/depth, grant/stream, sequence/time or removed withdrawal conflicts.
    ReferenceUnavailable
        An exact original predecessor is unavailable.
    """
    history = [first]
    seen = {first.fixed.source.reference}
    while (previous := history[-1].previous_reference) is not None:
        child = history[-1]
        subject = child.fixed.source.reference.digest
        if previous in seen:
            raise protected_source_conflict(
                subject, "/previous_snapshot_ref", code="cycle_detected"
            )
        if len(history) >= budget.limits.max_graph_depth:
            raise protected_source_conflict(
                subject, "/previous_snapshot_ref", code="limit_exceeded"
            )
        parent = acquire_protected_snapshot(
            previous,
            grant_reference=grant_reference,
            authority_id=first.authority_id,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=subject,
            pointer="/previous_snapshot_ref",
        )
        for conflict, pointer in (
            (parent.sequence >= child.sequence, "/sequence"),
            (parent.issued_at.compare(child.issued_at) > 0, "/issued_at"),
            (not set(parent.revocations) <= set(child.revocations), "/revocations"),
        ):
            if conflict:
                raise protected_source_conflict(subject, pointer)
        seen.add(previous)
        history.append(parent)
    return tuple(history)
