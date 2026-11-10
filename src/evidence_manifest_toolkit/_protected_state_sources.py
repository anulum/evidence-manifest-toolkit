# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole independently selected protected state source graph

"""Acquire whole grant/current/archive histories without manufacturing an accepted state."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._budget import ReferenceBudget
from ._context_sources import ContextSource, acquire_context_source
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._protected_state_history import (
    ProtectedSnapshotSource,
    acquire_protected_native_source,
    acquire_protected_snapshot,
    acquire_protected_snapshot_history,
    protected_source_conflict,
)
from ._subject_formats import SubjectFormat
from ._successor_trust import DelegatedTrustContextV2
from ._values import BlobRef, Digest, Utc


@dataclass(frozen=True, slots=True)
class ProtectedStateSources:
    """Retain complete independent root/grant and exact selected protected source histories.

    Attributes
    ----------
    root : ContextSource
        Entire earlier root-selection source, not an inferred root grammar or enrolment.
    grant : FixedSource
        Complete selected native grant and its necessary whole rule/root joins.
    current, selected : ProtectedSnapshotSource
        Original current and exact current/historical declarations. Neither is an
        accepted bootstrap, authenticated machine state or positive-use installation.
    history, selected_history : tuple of ProtectedSnapshotSource
        Entire current/archive predecessor populations including all original withdrawals.
    accepted_floor : str
        Caller-selected original current-stream floor token, never reset by archive use.
    """

    root: ContextSource
    grant: FixedSource
    current: ProtectedSnapshotSource
    selected: ProtectedSnapshotSource
    history: tuple[ProtectedSnapshotSource, ...]
    selected_history: tuple[ProtectedSnapshotSource, ...]
    accepted_floor: str

    @property
    def roots(self) -> tuple[FixedSource, ...]:
        """Return whole grant and both histories for the SAME complete source closure.

        Returns
        -------
        tuple of FixedSource
            Original complete source roots, without discarding duplicate metadata edges.
        """
        return (self.grant,) + tuple(row.fixed for row in (*self.history, *self.selected_history))


def acquire_protected_state_sources(
    trust: DelegatedTrustContextV2,
    *,
    rule: FixedSource,
    policy_subject: Digest,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> ProtectedStateSources:
    """Read only explicitly selected protected source histories before Clock admission.

    Parameters
    ----------
    trust : DelegatedTrustContextV2
        Entire explicit root/grant/current/floor/archive selection, without a fallback.
    rule : FixedSource
        Whole already selected r6 control rule. Its source predates grant and invocation.
    policy_subject : str
        Whole caller-selected enclosing policy identity.
    formats : Mapping
        Original validated fixed native source lookup.
    resolver : Resolver
        Sole original bounded offline source; never a bootstrap/controller discovery hook.
    budget : ReferenceBudget
        SAME original operation quota for root, grant and both histories.

    Returns
    -------
    ProtectedStateSources
        Complete source graph and necessary stream/floor/rule conservation only.
        Qualified root/provider/custody, own keys, full rotation/certificate eligibility,
        signatures, original time uncertainty and accepted transitions remain required.

    Raises
    ------
    ReferenceUnavailable
        An exact original required root/grant/current/archive/predecessor is absent.
    InputRefused
        Original source/schema/quota or whole selected stream/rule/floor conflict.
    """
    root = acquire_context_source(
        trust.independent_root_selection_ref,
        expected_control=None,
        resolver=resolver,
        budget=budget,
        subject=policy_subject,
        pointer="/trust/independent_root_selection_ref",
    )
    if root.raw_bytes is None:
        raise ReferenceUnavailable(root.reference)
    if root.document is None:
        raise InputRefused(root.reasons[0])
    grant = acquire_protected_native_source(
        trust.root_grant_ref,
        format_name="evidence_manifest_toolkit.authority_grant.v2",
        formats=formats,
        resolver=resolver,
        budget=budget,
        subject=policy_subject,
        pointer="/trust/root_grant_ref",
    )
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, grant.source.document).value)
    rule_value = cast(dict[str, JsonValue], cast(AcquiredDocument, rule.source.document).value)
    for name, expected in (
        ("automation_policy_ref", dict(rule.source.reference.to_mapping())),
        ("root_selection_source_ref", dict(root.reference.to_mapping())),
        ("rotation_rule_ref", rule_value["rotation_rule_ref"]),
    ):
        if value[name] != expected:
            raise protected_source_conflict(grant.source.reference.digest, "/" + name)
    lifetime = cast(dict[str, JsonValue], value["lifetime"])
    if (
        lifetime["kind"] == "finite"
        and Utc(lifetime["not_before"]).compare(Utc(lifetime["not_after"])) >= 0
    ):
        raise protected_source_conflict(grant.source.reference.digest, "/lifetime/not_after")
    current = acquire_protected_snapshot(
        trust.current_authority_snapshot_ref,
        grant_reference=trust.root_grant_ref,
        authority_id=cast(str, value["authority_id"]),
        formats=formats,
        resolver=resolver,
        budget=budget,
        subject=policy_subject,
        pointer="/trust/current_authority_snapshot_ref",
    )
    if current.sequence < int(trust.accepted_authority_sequence_floor):
        raise protected_source_conflict(policy_subject, "/trust/accepted_authority_sequence_floor")
    history = acquire_protected_snapshot_history(
        current,
        grant_reference=trust.root_grant_ref,
        formats=formats,
        resolver=resolver,
        budget=budget,
    )
    selected, selected_history = current, history
    if trust.evaluation_mode == "historical":
        # The original closed caller parser requires and decodes the whole archive Ref.
        reference = cast(BlobRef, trust.archived_authority_snapshot_ref)
        selected = acquire_protected_snapshot(
            reference,
            grant_reference=trust.root_grant_ref,
            authority_id=current.authority_id,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=policy_subject,
            pointer="/trust/archived_authority_snapshot_ref",
        )
        if (
            selected.sequence > current.sequence
            or selected.issued_at.compare(current.issued_at) > 0
        ):
            raise protected_source_conflict(
                policy_subject, "/trust/archived_authority_snapshot_ref"
            )
        selected_history = acquire_protected_snapshot_history(
            selected,
            grant_reference=trust.root_grant_ref,
            formats=formats,
            resolver=resolver,
            budget=budget,
        )
    return ProtectedStateSources(
        root,
        grant,
        current,
        selected,
        history,
        selected_history,
        trust.accepted_authority_sequence_floor,
    )
