# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole independently selected software authorization sources

"""Acquire software tables and exact history without inventing a protected trust state."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

import rfc8785

from ._budget import ReferenceBudget
from ._closure import ClosureResult
from ._codecs import decode_bytes, decode_reference
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import (
    FixedSource,
    acquire_fixed_source,
    close_fixed_sources,
    native_format_lookup,
)
from ._immutable import FrozenJson, freeze_json
from ._interfaces import Resolver
from ._json import JsonValue
from ._statements import key_id
from ._subject_formats import SubjectFormat
from ._successor_trust import SoftwareTrustContextV2
from ._values import BlobRef, Digest, Reason, Utc

_FORMAT = "emt-software-authorization-source-r4"


@dataclass(frozen=True, slots=True)
class SoftwareKeySource:
    """Keep the entire declared key entry and its actual encoding/window checks.

    Attributes
    ----------
    value : Mapping
        All original scope, identity, possession and custody fields, detached and immutable.
    public_key : bytes
        Canonical Base64URL-decoded raw32 bytes with their exact SHA256 key ID checked.
        Curve validity, possession, custody and signing authority remain separate predicates.
    valid_from, valid_until : Utc
        Exact finite nonempty half-open source window; current admission is not asserted.
    """

    value: Mapping[str, FrozenJson]
    public_key: bytes
    valid_from: Utc
    valid_until: Utc


@dataclass(frozen=True, slots=True)
class SoftwareTableSource:
    """Retain one complete selected source without granting its declared authorizations.

    Attributes
    ----------
    fixed : FixedSource
        Entire original reference, actual raw bytes, whole parsed body and fixed schema.
    installation_id, sequence : str, int
        Full stream identity and exact unbounded source counter; original string stays in fixed.
    issued_at : Utc
        Whole source token, independently calendar-checked without qualifying its clock.
    scope_reference, previous_reference : BlobRef, BlobRef or None
        Whole source references; absent initial predecessor remains explicitly None.
    keys : tuple of SoftwareKeySource
        All original unique entries after encoding/ID/window checks, never eligible keys yet.
    """

    fixed: FixedSource
    installation_id: str
    sequence: int
    issued_at: Utc
    scope_reference: BlobRef
    previous_reference: BlobRef | None
    keys: tuple[SoftwareKeySource, ...]


@dataclass(frozen=True, slots=True)
class SoftwareSources:
    """Retain real current/history/archive sources under the original selected floor.

    Attributes
    ----------
    current, selected : SoftwareTableSource
        Current independently selected stream and exact current/historical evaluation source.
    history : tuple of SoftwareTableSource
        Complete current-to-initial order with strict sequence/time/stream and cycle checks.
        Original revocation/identity/custody references remain in every whole body and edge.
    selected_history : tuple of SoftwareTableSource
        Complete independently selected archive history, or current history in current mode.
        It need not be a member of the current chain; current stream/floor still apply.
    closure : ClosureResult
        All complete tables and every selected source edge under the SAME invocation quota.
        Source failures remain reasons; no closure success supplies native authentication.
    accepted_floor : str
        Actual caller's original decimal token, without narrowing or resetting its stream.
    """

    current: SoftwareTableSource
    selected: SoftwareTableSource
    history: tuple[SoftwareTableSource, ...]
    selected_history: tuple[SoftwareTableSource, ...]
    closure: ClosureResult
    accepted_floor: str


def _refuse(subject: Digest, pointer: str, *, code: str = "invalid_schema") -> InputRefused:
    """Locate a software source conflict without echoing source text or declaring root trust.

    Parameters
    ----------
    subject : str
        Actual whole table or enclosing selected policy identity.
    pointer : str
        Original exact affected source/caller position.
    code : str
        Existing typed schema, policy, cycle or operation-limit category.

    Returns
    -------
    InputRefused
        Complete fixed safe diagnostic, retaining the original affected identity.
    """
    return InputRefused(
        Reason(code, subject, None, pointer, "Software authorization source refused.")
    )


def _table(
    reference: BlobRef,
    *,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> SoftwareTableSource:
    """Read the entire actual source and check every entry without a cryptographic provider.

    Parameters
    ----------
    reference : BlobRef
        Exact original current, predecessor or archive argument.
    formats : Mapping
        Original caller lookup plus fixed Common-native structural dispatch.
    resolver : Resolver
        Sole original bounded source, without key/root/source discovery.
    budget : ReferenceBudget
        SAME operation quota for every source and fixed schema.
    subject : str
        Actual whole selecting policy or previous table.
    pointer : str
        Exact reference position in that selector.

    Returns
    -------
    SoftwareTableSource
        Whole syntax/encoding/window-checked source, not an authenticated authorization.

    Raises
    ------
    ReferenceUnavailable
        The whole original required source cannot be acquired, preserving that exact argument.
    InputRefused
        Original source/metadata/quota failure, duplicate entry or encoding/ID/window conflict.
    """
    fixed = acquire_fixed_source(
        reference,
        format_name=_FORMAT,
        formats=formats,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer=pointer,
    )
    source = fixed.source
    if source.raw_bytes is None:
        raise ReferenceUnavailable(reference)
    if source.document is None:
        raise InputRefused(source.reasons[0])
    value = cast(dict[str, JsonValue], source.document.value)
    keys: list[SoftwareKeySource] = []
    entries: set[bytes] = set()
    for index, item in enumerate(cast(list[dict[str, JsonValue]], value["authorized_keys"])):
        location = "/authorized_keys/" + str(index)
        try:
            public_key = decode_bytes(cast(str, item["raw_public_key_base64url"]))
        except ValueError as error:
            raise _refuse(reference.digest, location + "/raw_public_key_base64url") from error
        identifier = cast(str, item["key_id"])
        if len(public_key) != 32 or key_id(public_key) != identifier:
            raise _refuse(reference.digest, location + "/key_id")
        whole_entry = rfc8785.dumps(item)
        if whole_entry in entries:
            raise _refuse(reference.digest, location + "/key_id")
        entries.add(whole_entry)
        lower = Utc(item["valid_from"])
        upper = Utc(item["valid_until"])
        if lower.compare(upper) >= 0:
            raise _refuse(reference.digest, location + "/valid_until")
        keys.append(
            SoftwareKeySource(
                cast(Mapping[str, FrozenJson], freeze_json(item)), public_key, lower, upper
            )
        )
    previous = value["previous_authorization_ref"]
    return SoftwareTableSource(
        fixed,
        cast(str, value["installation_id"]),
        int(cast(str, value["sequence"])),
        Utc(value["issued_at"]),
        decode_reference(
            value["whole_scope_and_signature_rule_ref"],
            subject=reference.digest,
            pointer="/whole_scope_and_signature_rule_ref",
        ),
        None
        if previous is None
        else decode_reference(
            previous, subject=reference.digest, pointer="/previous_authorization_ref"
        ),
        tuple(keys),
    )


def _history(
    first: SoftwareTableSource,
    *,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> tuple[SoftwareTableSource, ...]:
    """Read one complete selected history without substituting another selected stream.

    Parameters
    ----------
    first : SoftwareTableSource
        Actual current or explicit archive source, already structurally checked.
    formats : Mapping
        Original known structural dispatch with the fixed Common formats.
    resolver : Resolver
        Original source for complete predecessor references.
    budget : ReferenceBudget
        SAME operation quota and original depth bound, shared by both histories.

    Returns
    -------
    tuple of SoftwareTableSource
        Complete original newest-to-initial order with all revocations/edges retained.

    Raises
    ------
    ReferenceUnavailable
        An exact original predecessor is absent.
    InputRefused
        Original source, quota, cycle or exact stream/sequence/issued-time order fails.
    """
    history = [first]
    seen = {first.fixed.source.reference}
    while (previous := history[-1].previous_reference) is not None:
        child = history[-1]
        if previous in seen:
            raise _refuse(
                child.fixed.source.reference.digest,
                "/previous_authorization_ref",
                code="cycle_detected",
            )
        if len(history) >= budget.limits.max_graph_depth:
            raise _refuse(
                child.fixed.source.reference.digest,
                "/previous_authorization_ref",
                code="limit_exceeded",
            )
        parent = _table(
            previous,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=child.fixed.source.reference.digest,
            pointer="/previous_authorization_ref",
        )
        if parent.installation_id != first.installation_id:
            raise _refuse(
                parent.fixed.source.reference.digest, "/installation_id", code="policy_unavailable"
            )
        if parent.sequence >= child.sequence:
            raise _refuse(
                parent.fixed.source.reference.digest, "/sequence", code="policy_unavailable"
            )
        if parent.issued_at.compare(child.issued_at) > 0:
            raise _refuse(
                parent.fixed.source.reference.digest, "/issued_at", code="policy_unavailable"
            )
        seen.add(previous)
        history.append(parent)
    return tuple(history)


def acquire_software_sources(
    trust: SoftwareTrustContextV2,
    *,
    authority_rule_reference: BlobRef,
    policy_subject: Digest,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> SoftwareSources:
    """Recompute the exact independently selected software stream before Clock acquisition.

    Parameters
    ----------
    trust : SoftwareTrustContextV2
        Entire validated current/archive selection and original accepted current floor.
    authority_rule_reference : BlobRef
        Whole rule independently selected by the matching enclosing class policy.
    policy_subject : str
        Whole independently selected policy identity.
    formats : Mapping
        Original independently validated caller schemas; no private entries are registered.
    resolver : Resolver
        Sole bounded source for original actual references.
    budget : ReferenceBudget
        SAME operation quota, without history, archive or class allowances.

    Returns
    -------
    SoftwareSources
        Full actual source history/closure and selected scope/floor consistency. This does
        not validate curve points, signatures, custody, identity, Clock or actual authority.

    Raises
    ------
    ReferenceUnavailable
        An exact original required current/predecessor/archive argument is absent.
    InputRefused
        Original source failure, cycle/depth, stream/sequence/time/floor/archive/rule conflict.
    """
    installed = native_format_lookup(formats, budget=budget)
    current = _table(
        trust.software_authorization_ref,
        formats=installed,
        resolver=resolver,
        budget=budget,
        subject=policy_subject,
        pointer="/trust/software_authorization_ref",
    )
    if current.sequence < int(trust.accepted_authorization_sequence_floor):
        raise _refuse(
            policy_subject,
            "/trust/accepted_authorization_sequence_floor",
            code="policy_unavailable",
        )
    history = _history(current, formats=installed, resolver=resolver, budget=budget)
    selected = current
    selected_history = history
    if trust.evaluation_mode == "historical":
        reference = cast(BlobRef, trust.archived_software_authorization_ref)
        selected = _table(
            reference,
            formats=installed,
            resolver=resolver,
            budget=budget,
            subject=policy_subject,
            pointer="/trust/archived_software_authorization_ref",
        )
        if (
            selected.installation_id != current.installation_id
            or selected.sequence > current.sequence
            or selected.issued_at.compare(current.issued_at) > 0
        ):
            raise _refuse(
                policy_subject,
                "/trust/archived_software_authorization_ref",
                code="policy_unavailable",
            )
        selected_history = _history(selected, formats=installed, resolver=resolver, budget=budget)
    if selected.scope_reference != authority_rule_reference:
        raise _refuse(policy_subject, "/authority_rule_ref", code="policy_unavailable")
    closure = close_fixed_sources(
        tuple(table.fixed for table in (*history, *selected_history)),
        formats=installed,
        resolver=resolver,
        budget=budget,
    )
    return SoftwareSources(
        current,
        selected,
        history,
        selected_history,
        closure,
        trust.accepted_authorization_sequence_floor,
    )
