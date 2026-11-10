# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact selected snapshot ancestry and retained revocations

"""Check complete known snapshot relations without installing state or trusting signer time."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._budget import ByteIdentity
from ._codecs import decode_reference
from ._json import AcquiredDocument, JsonValue
from ._utc import utc_key
from ._values import BlobRef, Digest, Reason, Utc


@dataclass(frozen=True, slots=True)
class SnapshotNode:
    """Retain an entire selected native snapshot with its original source identity.

    Attributes
    ----------
    reference : BlobRef
        Actual full selected declaration, retaining its original raw/canonical basis.
    document : AcquiredDocument
        Complete already schema-valid native source and original numeric token custody.
    """

    reference: BlobRef
    document: AcquiredDocument


@dataclass(frozen=True, slots=True)
class LocatedRevocation:
    """Retain each complete original revocation rather than projecting it into a key set.

    Attributes
    ----------
    subject_digest : str
        Actual owning snapshot identity, including older authenticated-state provenance.
    pointer : str
        Exact original native array position.
    record : dict
        All original key/reason/report/window/bounds fields, without deletion or inferred time.
    """

    subject_digest: Digest
    pointer: str
    record: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class SnapshotHistory:
    """Separate complete ancestry/ordering facts from still-required root authentication.

    Attributes
    ----------
    nodes : tuple of SnapshotNode
        Complete selected state followed by every reachable predecessor, in traversal order.
    revocations : tuple of LocatedRevocation
        Every ordered fact from every selected node, including duplicates and earlier states.
    reasons : tuple of Reason
        Actual native relation, floor, validity or missing validated-ancestry contradictions.
        Empty reasons alone establish no root, signature, clock or current eligibility.
    """

    nodes: tuple[SnapshotNode, ...]
    revocations: tuple[LocatedRevocation, ...]
    reasons: tuple[Reason, ...]


def snapshot_history(
    selected: BlobRef,
    *,
    documents: Mapping[ByteIdentity, AcquiredDocument],
    accepted_floor: str,
    evaluation_time: Utc,
    apply_current_floor: bool,
    apply_time_window: bool = True,
) -> SnapshotHistory:
    """Check whole selected ancestry under exact decimal and parsed UTC source laws.

    Parameters
    ----------
    selected : BlobRef
        Explicit current state, or separately selected archive in historical mode.
    documents : Mapping
        Whole schema-valid selected closure documents. Missing entries are not proof of
        unavailable raw bytes; actual acquisition observations supply that separate fact.
    accepted_floor : str
        Already configuration-validated independently held exact nonnegative decimal floor.
    evaluation_time : str
        Already configuration-validated explicit original UTC token, with full fractional order.
    apply_current_floor : bool
        Apply the current floor to current selection. Historical archive evaluation never
        installs an older state or changes the independently held floor.
    apply_time_window : bool
        Apply the explicit evaluation point to the selected state's half-open window.
        Independently held current revocations in historical mode are not dated by an archive
        evaluation point; the selected archive is checked against that point separately.

    Returns
    -------
    SnapshotHistory
        Complete original nodes/revocations and located relation refusals. Ancestor expiry
        is not substituted for selected-state expiry or evidence that a signature existed.

    Raises
    ------
    InputRefused
        A native reference or UTC token violates its independently selected common source law.
    """
    nodes: list[SnapshotNode] = []
    revocations: list[LocatedRevocation] = []
    reasons: list[Reason] = []
    reference = selected
    seen: set[ByteIdentity] = set()
    child: SnapshotNode | None = None
    while True:
        identity = reference.digest, reference.digest_basis, reference.byte_length
        if identity in seen:
            reasons.append(
                Reason(
                    "cycle_detected",
                    reference.digest,
                    None,
                    None,
                    "Selected snapshot history is cyclic.",
                )
            )
            break
        seen.add(identity)
        document = documents.get(identity)
        if (
            document is None
            or not isinstance(document.value, dict)
            or document.value.get("schema_id") != "evidence_manifest_toolkit.trust_snapshot.v1"
        ):
            reasons.append(
                Reason(
                    "invalid_schema",
                    reference.digest,
                    None,
                    "",
                    "Complete validated snapshot history is required.",
                )
            )
            break
        node = SnapshotNode(reference, document)
        value = document.value
        if not nodes:
            if apply_current_floor and int(cast(str, value["sequence"])) < int(accepted_floor):
                reasons.append(
                    Reason(
                        "snapshot_rollback",
                        reference.digest,
                        None,
                        "/sequence",
                        "The supplied snapshot is below the accepted sequence floor.",
                    )
                )
            evaluation = utc_key(evaluation_time)
            if apply_time_window and evaluation < utc_key(cast(str, value["issued_at"])):
                reasons.append(
                    Reason(
                        "snapshot_expired",
                        reference.digest,
                        None,
                        "/issued_at",
                        "Selected snapshot does not cover the explicit evaluation point.",
                    )
                )
            elif apply_time_window and evaluation >= utc_key(cast(str, value["expires_at"])):
                reasons.append(
                    Reason(
                        "snapshot_expired",
                        reference.digest,
                        None,
                        "/expires_at",
                        "The current trust snapshot has expired."
                        if apply_current_floor
                        else "The selected archived trust snapshot has expired.",
                    )
                )
        if child is not None:
            child_value = cast(dict[str, JsonValue], child.document.value)
            if int(cast(str, child_value["sequence"])) <= int(cast(str, value["sequence"])):
                reasons.append(
                    Reason(
                        "snapshot_rollback",
                        child.reference.digest,
                        None,
                        "/sequence",
                        "Snapshot sequence does not strictly exceed its predecessor.",
                    )
                )
            if utc_key(cast(str, child_value["issued_at"])) < utc_key(
                cast(str, value["issued_at"])
            ):
                reasons.append(
                    Reason(
                        "invalid_schema",
                        child.reference.digest,
                        None,
                        "/issued_at",
                        "Snapshot issuance precedes its predecessor.",
                    )
                )
        nodes.append(node)
        revocations.extend(
            LocatedRevocation(reference.digest, "/revocations/" + str(index), record)
            for index, record in enumerate(cast(list[dict[str, JsonValue]], value["revocations"]))
        )
        previous = value.get("previous_snapshot_ref")
        if previous is None:
            break
        child = node
        reference = decode_reference(
            previous, subject=reference.digest, pointer="/previous_snapshot_ref"
        )
    return SnapshotHistory(tuple(nodes), tuple(revocations), tuple(reasons))


def revocation_reasons(history: SnapshotHistory, *, key_id: str) -> tuple[Reason, ...]:
    """Refuse every matching retained revocation without trusting a claimed signing time.

    Parameters
    ----------
    history : SnapshotHistory
        Complete separately root-authenticated relevant current/provenance state history.
    key_id : str
        Actual eligible-delegation candidate key identity being evaluated.

    Returns
    -------
    tuple of Reason
        Every matching located original revocation. Compromise, retirement and policy change
        remain refusals; another key's revocation does not revoke this selected key.
    """
    return tuple(
        Reason(
            "key_revoked",
            revocation.subject_digest,
            None,
            revocation.pointer,
            "Selected key has a retained revocation.",
        )
        for revocation in history.revocations
        if revocation.record["key_id"] == key_id
    )
