# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole selected rotation source continuity

"""Retain complete rotation histories without accepting keys, controls or current authority."""

from collections.abc import Mapping
from typing import cast

from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._format_sources import FixedSource
from ._immutable import thaw_json
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._protected_control_bindings import ProtectedControlBinding
from ._protected_state_history import (
    ProtectedSnapshotSource,
    acquire_protected_native_source,
    acquire_protected_snapshot,
    acquire_protected_snapshot_history,
    protected_source_conflict,
)
from ._protected_state_sources import ProtectedStateSources
from ._subject_formats import SubjectFormat
from ._values import BlobRef, Utc


def acquire_protected_rotation_sources(
    state: ProtectedStateSources,
    *,
    bindings: tuple[ProtectedControlBinding, ...],
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> tuple[FixedSource, ...]:
    """Check whole rotation and snapshot source continuity under the original selected grant.

    Parameters
    ----------
    state : ProtectedStateSources
        Entire independently selected grant and current/archive snapshot histories.
    bindings : tuple of ProtectedControlBinding
        Actual selected control targets, statements and original authorising-state refs.
    formats : Mapping
        Original known fixed structural lookup, without artifact-selected code.
    resolver : Resolver
        Sole bounded source for every complete original rotation and earlier state.
    budget : ReferenceBudget
        SAME invocation quota and graph-depth ceiling. Strictly decreasing nonnegative
        predecessor sequences also make each history traversal well-founded.

    Returns
    -------
    tuple of FixedSource
        Entire rotations and earlier control snapshots in first-acquisition order.
        Source continuity does not authenticate the controller, unchanged scope, new-key
        possession/custody, native signatures, Clock or positive installed state.

    Raises
    ------
    InputRefused
        Original source/schema/quota or full grant/key/sequence/time/state relation fails.
    ReferenceUnavailable
        An exact original required source is unavailable.
    """
    retained: dict[BlobRef, FixedSource] = {}
    histories: dict[BlobRef, tuple[FixedSource, ...]] = {}

    def value(source: FixedSource) -> dict[str, JsonValue]:
        """Read the whole already validated body without projecting authority fields."""
        return cast(dict[str, JsonValue], cast(AcquiredDocument, source.source.document).value)

    grant = value(state.grant)
    grant_reference = state.grant.source.reference
    lifetime = cast(dict[str, JsonValue], grant["lifetime"])

    def history(reference: BlobRef) -> tuple[FixedSource, ...]:
        """Retain every typed parent while enforcing strict counter and key continuity."""
        cached = histories.get(reference)
        if cached is not None:
            return cached
        rows: list[FixedSource] = []
        next_reference: BlobRef | None = reference
        while next_reference is not None:
            subject = rows[-1].source.reference.digest if rows else reference.digest
            if len(rows) >= budget.limits.max_graph_depth:
                raise protected_source_conflict(
                    subject, "/previous_rotation_ref", code="limit_exceeded"
                )
            source = acquire_protected_native_source(
                next_reference,
                format_name="evidence_manifest_toolkit.authority_rotation.v2",
                formats=formats,
                resolver=resolver,
                budget=budget,
                subject=subject,
                pointer="/previous_rotation_ref" if rows else "/current_rotation_ref",
            )
            body = value(source)
            for field, expected in (
                ("authority_id", grant["authority_id"]),
                ("root_grant_ref", dict(grant_reference.to_mapping())),
            ):
                if body[field] != expected:
                    raise protected_source_conflict(source.source.reference.digest, "/" + field)
            if body["old_key_id"] == body["new_key_id"]:
                raise protected_source_conflict(source.source.reference.digest, "/new_key_id")
            effective = Utc(body["effective_at"])
            if Utc(lifetime["not_before"]).compare(effective) > 0 or (
                lifetime["kind"] == "finite" and effective.compare(Utc(lifetime["not_after"])) >= 0
            ):
                raise protected_source_conflict(source.source.reference.digest, "/effective_at")
            if rows:
                child = value(rows[-1])
                for conflict, pointer in (
                    (
                        int(cast(str, body["rotation_sequence"]))
                        >= int(cast(str, child["rotation_sequence"])),
                        "/rotation_sequence",
                    ),
                    (child["old_key_id"] != body["new_key_id"], "/old_key_id"),
                    (effective.compare(Utc(child["effective_at"])) > 0, "/effective_at"),
                ):
                    if conflict:
                        raise protected_source_conflict(rows[-1].source.reference.digest, pointer)
            retained[source.source.reference] = source
            rows.append(source)
            previous = body["previous_rotation_ref"]
            next_reference = (
                None
                if previous is None
                else decode_reference(
                    previous,
                    subject=source.source.reference.digest,
                    pointer="/previous_rotation_ref",
                )
            )
        if value(rows[-1])["old_key_id"] != grant["initial_issuer_key_id"]:
            raise protected_source_conflict(rows[-1].source.reference.digest, "/old_key_id")
        histories[reference] = tuple(rows)
        return tuple(rows)

    def snapshot_history(rows: tuple[ProtectedSnapshotSource, ...]) -> None:
        """Keep each actual snapshot's head and prevent loss of established rotation history."""
        later_chain: tuple[FixedSource, ...] | None = None
        later_source: FixedSource | None = None
        for snapshot in rows:
            body = value(snapshot.fixed)
            declared = body["current_rotation_ref"]
            reference = (
                None
                if declared is None
                else decode_reference(
                    declared,
                    subject=snapshot.fixed.source.reference.digest,
                    pointer="/current_rotation_ref",
                )
            )
            chain = () if reference is None else history(reference)
            issuer = grant["initial_issuer_key_id"] if not chain else value(chain[0])["new_key_id"]
            if body["current_issuer_key_id"] != issuer:
                raise protected_source_conflict(
                    snapshot.fixed.source.reference.digest, "/current_issuer_key_id"
                )
            if chain and Utc(value(chain[0])["effective_at"]).compare(snapshot.issued_at) > 0:
                raise protected_source_conflict(
                    snapshot.fixed.source.reference.digest, "/current_rotation_ref"
                )
            if (
                later_chain is not None
                and reference is not None
                and reference not in (source.source.reference for source in later_chain)
            ):
                raise protected_source_conflict(
                    cast(FixedSource, later_source).source.reference.digest, "/current_rotation_ref"
                )
            later_chain, later_source = chain, snapshot.fixed

    snapshot_history(state.history)
    snapshot_history(state.selected_history)
    for binding in bindings:
        if binding.entry["operation"] != "rotate_authority":
            continue
        chain = history(binding.target.source.reference)
        target = value(chain[0])
        reference = decode_reference(
            thaw_json(binding.entry["authorizing_state_ref"]),
            subject=binding.statement.source.reference.digest,
            pointer="/authorizing_state_ref",
        )
        earlier = acquire_protected_snapshot(
            reference,
            grant_reference=grant_reference,
            authority_id=state.current.authority_id,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=binding.statement.source.reference.digest,
            pointer="/authorizing_state_ref",
        )
        earlier_history = acquire_protected_snapshot_history(
            earlier,
            grant_reference=grant_reference,
            formats=formats,
            resolver=resolver,
            budget=budget,
        )
        snapshot_history(earlier_history)
        retained.update((row.fixed.source.reference, row.fixed) for row in earlier_history)
        before = value(earlier.fixed)
        for conflict, pointer in (
            (target["old_key_id"] != before["current_issuer_key_id"], "/old_key_id"),
            (
                target["previous_rotation_ref"] != before["current_rotation_ref"],
                "/previous_rotation_ref",
            ),
            (target["old_key_id"] != binding.entry["signer_key_id"], "/old_key_id"),
        ):
            if conflict:
                raise protected_source_conflict(binding.target.source.reference.digest, pointer)
        effective = Utc(target["effective_at"])
        if effective.compare(earlier.issued_at) < 0 or effective.compare(earlier.expires_at) >= 0:
            raise protected_source_conflict(binding.target.source.reference.digest, "/effective_at")
    return tuple(retained.values())
