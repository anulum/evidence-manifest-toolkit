# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — selected current state and complete control authentication

"""Bind independently selected bootstrap, catalogue, history and detached control receipts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._bootstrap_policy import BootstrapDeclaration, parse_bootstrap
from ._budget import ReferenceBudget
from ._closure import ClosureResult, ClosureRoot, traverse_closure
from ._context_sources import acquire_context_source
from ._control_state_validation import control_state_reasons
from ._envelopes import ParsedEnvelope, parse_envelope
from ._errors import InputRefused, ReferenceUnavailable
from ._interfaces import Resolver
from ._registry_types import SchemaRegistry
from ._schema_resources import StaticSchema
from ._snapshot_history import SnapshotHistory, snapshot_history
from ._trust_types import TrustContext
from ._values import BlobRef, Reason

if TYPE_CHECKING:
    from ._native_signature import NativeVerifier


@dataclass(frozen=True, slots=True)
class SelectedTrustState:
    """Retain complete computable state checks without asserting caller approval provenance.

    Attributes
    ----------
    bootstrap : BootstrapDeclaration
        Independently selected local public declarations, retaining their namespace.
    history : SnapshotHistory
        Complete current predecessor population and all retained revocations.
    selected_history : SnapshotHistory
        Explicit current/archive evaluation history, separate from held current revocations.
    selected_reference : BlobRef
        Exact original caller selection for the requested evaluation mode.
    closure : ClosureResult
        Every selected native control/catalogue edge, whole documents and missing arguments.
    envelopes : tuple of ParsedEnvelope
        Entire explicitly supplied root-control receipts, without store discovery.
    reasons : tuple of Reason
        All native shape, source, catalogue, history and actual signature failures.
    """

    bootstrap: BootstrapDeclaration
    history: SnapshotHistory
    selected_history: SnapshotHistory
    selected_reference: BlobRef
    closure: ClosureResult
    envelopes: tuple[ParsedEnvelope, ...]
    reasons: tuple[Reason, ...]


def select_trust_state(
    trust: TrustContext,
    *,
    registry: SchemaRegistry,
    schemas: Mapping[str, StaticSchema],
    resolver: Resolver,
    budget: ReferenceBudget,
    verifier: NativeVerifier,
) -> SelectedTrustState:
    """Recheck the whole independently accepted current selection on each operation.

    Parameters
    ----------
    trust : TrustContext
        Validated trusted caller selection; supplying this value presupposes independent
        owner or fixture acceptance, which identical serialized input cannot prove.
    registry : SchemaRegistry
        Whole independently selected catalogue and entries, already statically validated.
    schemas : Mapping
        Complete registry dispatch table, including the protected native control schemas.
    resolver : Resolver
        Actual bounded source for these exact arguments and their selected closure.
    budget : ReferenceBudget
        Sole cumulative operation budget, shared with content and static schema reads.
    verifier : NativeVerifier
        Initialized maintained full-message native verification implementation.

    Returns
    -------
    SelectedTrustState
        Complete current history, receipts and computable failures; no state is installed,
        floor advanced, root issued, signer enrolled or external clock qualified.

    Raises
    ------
    ReferenceUnavailable
        Bootstrap or current context bytes are absent, preserving the exact original argument.
    InputRefused
        Bootstrap acquisition/declaration or a shared explicit limit cannot be completed.
    """
    bootstrap_source = acquire_context_source(
        trust.bootstrap_policy_ref,
        expected_control=None,
        resolver=resolver,
        budget=budget,
        subject=trust.bootstrap_policy_ref.digest,
        pointer="/trust/bootstrap_policy_ref",
    )
    if bootstrap_source.raw_bytes is None:
        raise ReferenceUnavailable(trust.bootstrap_policy_ref)
    if bootstrap_source.document is None:
        raise InputRefused(bootstrap_source.reasons[0])
    bootstrap = parse_bootstrap(bootstrap_source.document, reference=trust.bootstrap_policy_ref)
    current = acquire_context_source(
        trust.current_snapshot_ref,
        expected_control="trust_snapshot",
        resolver=resolver,
        budget=budget,
        subject=trust.current_snapshot_ref.digest,
        pointer="/trust/current_snapshot_ref",
    )
    if current.raw_bytes is None:
        raise ReferenceUnavailable(trust.current_snapshot_ref)
    if current.document is None:
        raise InputRefused(current.reasons[0])
    roots: tuple[ClosureRoot, ...] = (
        ClosureRoot(
            trust.current_snapshot_ref,
            current.raw_bytes,
            "evidence_manifest_toolkit.trust_snapshot.v1",
        ),
    )
    selected_reference = trust.current_snapshot_ref
    if trust.evaluation_mode == "historical":
        if trust.archived_snapshot_ref is None:
            from ._reference_paths import configuration_refusal

            raise configuration_refusal("/trust/archived_snapshot_ref")
        selected_reference = trust.archived_snapshot_ref
        archive = acquire_context_source(
            selected_reference,
            expected_control="trust_snapshot",
            resolver=resolver,
            budget=budget,
            subject=selected_reference.digest,
            pointer="/trust/archived_snapshot_ref",
        )
        if archive.raw_bytes is None:
            raise ReferenceUnavailable(selected_reference)
        if archive.document is None:
            raise InputRefused(archive.reasons[0])
        roots += (
            ClosureRoot(
                selected_reference, archive.raw_bytes, "evidence_manifest_toolkit.trust_snapshot.v1"
            ),
        )
    closure = traverse_closure(
        roots,
        schemas=schemas,
        resolver=resolver,
        budget=budget,
        requirements=(),
    )
    history = snapshot_history(
        trust.current_snapshot_ref,
        documents=closure.documents,
        accepted_floor=trust.accepted_sequence_floor,
        evaluation_time=trust.evaluation_time,
        apply_current_floor=True,
        apply_time_window=trust.evaluation_mode == "current",
    )
    envelopes = tuple(
        parse_envelope(data, limits=budget.limits) for data in trust.control_envelopes
    )
    selected_history = (
        history
        if trust.evaluation_mode == "current"
        else snapshot_history(
            selected_reference,
            documents=closure.documents,
            accepted_floor=trust.accepted_sequence_floor,
            evaluation_time=trust.evaluation_time,
            apply_current_floor=False,
        )
    )
    reasons = [*closure.reasons, *history.reasons]
    if selected_history is not history:
        reasons.extend(selected_history.reasons)
    reasons.extend(
        control_state_reasons(
            bootstrap,
            bootstrap_reference=trust.bootstrap_policy_ref,
            histories=(history, selected_history),
            closure=closure,
            envelopes=envelopes,
            registry=registry,
            verifier=verifier,
        )
    )
    return SelectedTrustState(
        bootstrap, history, selected_history, selected_reference, closure, envelopes, tuple(reasons)
    )
