# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected control and catalogue validation

"""Authenticate all selected native control sources and retain full catalogue correspondence."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from ._bootstrap_policy import PROFILE, BootstrapDeclaration
from ._closure import ClosureResult
from ._codecs import decode_reference
from ._control_authentication import authenticate_control
from ._control_context import references_agree
from ._envelopes import ParsedEnvelope
from ._json import JsonValue
from ._registry_types import SchemaRegistry
from ._registry_wire import entry_value
from ._snapshot_history import SnapshotHistory
from ._temporal_semantics import temporal_reasons
from ._values import BlobRef, Reason

if TYPE_CHECKING:
    from ._native_signature import NativeVerifier


def control_state_reasons(
    bootstrap: BootstrapDeclaration,
    *,
    bootstrap_reference: BlobRef,
    histories: tuple[SnapshotHistory, ...],
    closure: ClosureResult,
    envelopes: tuple[ParsedEnvelope, ...],
    registry: SchemaRegistry,
    verifier: NativeVerifier,
) -> tuple[Reason, ...]:
    """Check entire native state provenance without approving or installing a selection.

    Parameters
    ----------
    bootstrap : BootstrapDeclaration
        Complete independently selected public declaration; prior acceptance is a caller premise.
    bootstrap_reference : BlobRef
        Original exact independently held local bootstrap identity.
    histories : tuple of SnapshotHistory
        Actual current and independently selected archive histories; shared nodes are checked once.
    closure : ClosureResult
        Entire selected current/archive reference graph and actual schema-valid source objects.
    envelopes : tuple of ParsedEnvelope
        All explicitly supplied root-control receipts, without discovery in storage.
    registry : SchemaRegistry
        Entire independently selected catalogue and original complete entries.
    verifier : NativeVerifier
        Initialized maintained verifier for the exact whole native statement profile.

    Returns
    -------
    tuple of Reason
        Every actual native interval/profile/issuer/signature/catalogue contradiction. No
        prior approval, signer enrollment, clock or domain qualification is inferred.
    """
    reasons: list[Reason] = []
    if not verifier.public_key_valid(bootstrap.root_public_key):
        reasons.append(
            Reason(
                "untrusted_root",
                bootstrap_reference.digest,
                None,
                None,
                "Selected bootstrap public key is outside the required profile.",
            )
        )
    seen: set[tuple[str, str, str]] = set()
    expected_entries = [entry_value(entry) for entry in registry.entries]
    for history in histories:
        for node in history.nodes:
            reference = node.reference
            identity = reference.digest, reference.digest_basis, reference.byte_length
            if identity in seen:
                continue
            seen.add(identity)
            value = cast(dict[str, JsonValue], node.document.value)
            reasons.extend(
                temporal_reasons(
                    value,
                    schema_id="evidence_manifest_toolkit.trust_snapshot.v1",
                    subject=reference.digest,
                )
            )
            authentication = authenticate_control(
                reference,
                purpose="trust_snapshot",
                issuer_root_key_id=cast(str, value["issuer_root_key_id"]),
                bootstrap_policy_digest=bootstrap_reference.digest,
                pinned_root_public_key=bootstrap.root_public_key,
                envelopes=envelopes,
                verifier=verifier,
            )
            reasons.extend(authentication.reasons)
            if PROFILE not in cast(list[str], value["accepted_profile_ids"]):
                reasons.append(
                    Reason(
                        "unsupported_profile",
                        reference.digest,
                        None,
                        "/accepted_profile_ids",
                        "Selected snapshot does not accept the required signature profile.",
                    )
                )
            catalogue_ref = decode_reference(
                value["registry_ref"],
                subject=reference.digest,
                pointer="/registry_ref",
            )
            selected_current = history is histories[0] and node is history.nodes[0]
            if selected_current and (
                not references_agree(
                    catalogue_ref,
                    registry.snapshot_ref,
                    expected_schema="evidence_manifest_toolkit.registry_snapshot.v1",
                )
                or (
                    bootstrap.schema_catalogue_ref is not None
                    and not references_agree(
                        bootstrap.schema_catalogue_ref,
                        registry.snapshot_ref,
                        expected_schema="evidence_manifest_toolkit.registry_snapshot.v1",
                    )
                )
            ):
                reasons.append(
                    Reason(
                        "untrusted_root",
                        reference.digest,
                        None,
                        "/registry_ref",
                        "Current catalogue does not match the independently selected registry.",
                    )
                )
            identity = catalogue_ref.digest, catalogue_ref.digest_basis, catalogue_ref.byte_length
            catalogue = closure.documents.get(identity)
            if (
                catalogue is None
                or not isinstance(catalogue.value, dict)
                or (selected_current and catalogue.value.get("entries") != expected_entries)
            ):
                reasons.append(
                    Reason(
                        "invalid_schema",
                        catalogue_ref.digest,
                        None,
                        "/entries",
                        "Complete catalogue entries do not match the independently selected registry.",
                    )
                )
    for observation in closure.observations:
        edge_reference = observation.reference
        if edge_reference is None or not observation.required or observation.outcome != "matched":
            continue
        identity = (
            edge_reference.digest,
            edge_reference.digest_basis,
            edge_reference.byte_length,
        )
        document = closure.documents.get(identity)
        if identity in seen or document is None or not isinstance(document.value, dict):
            continue
        value = document.value
        if value.get("schema_id") != "evidence_manifest_toolkit.group_certificate.v1":
            continue
        seen.add(identity)
        reasons.extend(
            temporal_reasons(
                value,
                schema_id="evidence_manifest_toolkit.group_certificate.v1",
                subject=edge_reference.digest,
            )
        )
        authentication = authenticate_control(
            edge_reference,
            purpose="group_certificate",
            issuer_root_key_id=cast(str, value["issuer_root_key_id"]),
            bootstrap_policy_digest=bootstrap_reference.digest,
            pinned_root_public_key=bootstrap.root_public_key,
            envelopes=envelopes,
            verifier=verifier,
        )
        reasons.extend(authentication.reasons)
    return tuple(reasons)
