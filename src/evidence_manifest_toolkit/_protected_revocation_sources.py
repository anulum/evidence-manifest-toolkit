# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete withdrawal snapshot source conservation

"""Check whole withdrawal declarations without authenticating a signer or installing state."""

from collections.abc import Mapping
from typing import cast

from ._budget import ReferenceBudget
from ._format_sources import FixedSource
from ._immutable import thaw_json
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._protected_control_bindings import ProtectedControlBinding
from ._protected_state_history import (
    acquire_protected_snapshot,
    acquire_protected_snapshot_history,
    protected_source_conflict,
)
from ._protected_state_sources import ProtectedStateSources
from ._subject_formats import SubjectFormat


def acquire_protected_revocation_sources(
    bindings: tuple[ProtectedControlBinding, ...],
    *,
    state: ProtectedStateSources,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> tuple[FixedSource, ...]:
    """Retain complete withdrawal histories and enforce their exact additive source delta.

    Parameters
    ----------
    bindings : tuple of ProtectedControlBinding
        Entire independently selected operation population with matching actual receipts.
        Other operations retain their own distinct transition predicates.
    state : ProtectedStateSources
        Whole independently selected grant and stream, without accepted key authority.
    formats : Mapping
        Original fixed structural definitions, never received executable dispatch.
    resolver : Resolver
        Sole original bounded source; no alternate state or owner discovery.
    budget : ReferenceBudget
        SAME invocation quota for all complete targets and preceding source histories.

    Returns
    -------
    tuple of FixedSource
        Whole withdrawal targets and histories in selected order. Necessary source
        conservation supplies no surviving owner path, descendant authorisation,
        signature, Clock, positive state or installation. Finite withdrawal-history
        timestamps do not revive an expired machine or extend its grant lifetime.

    Raises
    ------
    InputRefused
        Whole source, history, earlier-state binding or additive withdrawal delta conflicts.
    ReferenceUnavailable
        An exact original required predecessor or source cannot be acquired.
    """
    retained: list[FixedSource] = []
    for binding in bindings:
        if binding.entry["operation"] != "revoke_descendants":
            continue
        reference = binding.target.source.reference
        target = acquire_protected_snapshot(
            reference,
            grant_reference=state.grant.source.reference,
            authority_id=state.current.authority_id,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=reference.digest,
            pointer="",
        )
        previous = target.previous_reference
        if previous is None or thaw_json(binding.entry["authorizing_state_ref"]) != dict(
            previous.to_mapping()
        ):
            raise protected_source_conflict(reference.digest, "/previous_snapshot_ref")
        history = acquire_protected_snapshot_history(
            target,
            grant_reference=state.grant.source.reference,
            formats=formats,
            resolver=resolver,
            budget=budget,
        )
        parent = history[1]
        old = cast(dict[str, JsonValue], cast(AcquiredDocument, parent.fixed.source.document).value)
        new = cast(dict[str, JsonValue], cast(AcquiredDocument, target.fixed.source.document).value)
        for field in old:
            if (
                field
                not in {
                    "sequence",
                    "issued_at",
                    "expires_at",
                    "revocations",
                    "previous_snapshot_ref",
                }
                and new[field] != old[field]
            ):
                raise protected_source_conflict(reference.digest, "/" + field)
        if (
            len(target.revocations) <= len(parent.revocations)
            or target.revocations[: len(parent.revocations)] != parent.revocations
        ):
            raise protected_source_conflict(reference.digest, "/revocations")
        retained.extend(row.fixed for row in history)
    return tuple(retained)
