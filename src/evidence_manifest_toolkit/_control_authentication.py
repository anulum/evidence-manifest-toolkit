# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete explicitly supplied root-control signature binding

"""Check detached native control signatures against independently supplied pinned root bytes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from ._envelopes import ParsedEnvelope
from ._statements import key_id
from ._values import BlobRef, Digest, Reason

if TYPE_CHECKING:
    from ._native_signature import NativeVerifier


@dataclass(frozen=True, slots=True)
class ControlAuthentication:
    """Keep exact root-signature correspondence separate from bootstrap and current policy.

    Attributes
    ----------
    signature_matches : bool
        At least one complete explicitly supplied control envelope verifies under the pinned
        key and exact content/purpose/bootstrap bindings. No operational enrollment is inferred.
    reasons : tuple of Reason
        Every actual selected receipt defect, or a located missing-control refusal.
        A matching receipt does not erase defects in other supplied receipts.
    """

    signature_matches: bool
    reasons: tuple[Reason, ...]


def authenticate_control(
    content_ref: BlobRef,
    *,
    purpose: Literal["group_certificate", "trust_snapshot"],
    issuer_root_key_id: str,
    bootstrap_policy_digest: Digest,
    pinned_root_public_key: bytes,
    envelopes: tuple[ParsedEnvelope, ...],
    verifier: NativeVerifier,
) -> ControlAuthentication:
    """Check every supplied receipt for the complete independently selected control content.

    Parameters
    ----------
    content_ref : BlobRef
        Actual canonical whole native control identity, length and independent known schema.
    purpose : {"group_certificate", "trust_snapshot"}
        Existing control purpose selected by its actual known content type.
    issuer_root_key_id : str
        Entire native issuer declaration, checked against the independently pinned raw key.
    bootstrap_policy_digest : str
        Exact independently held owner bootstrap identity; received fields cannot replace it.
    pinned_root_public_key : bytes
        Actual independently selected raw32 public bytes, never an artifact's embedded key.
    envelopes : tuple of ParsedEnvelope
        Only actual explicitly supplied complete receipts; store availability selects nothing.
    verifier : NativeVerifier
        Initialized maintained verifier for the exact selected profile and full messages.

    Returns
    -------
    ControlAuthentication
        Signature/binding correspondence and all actual defects. The surrounding caller must
        still establish bootstrap approval, source closure, registry/delegation/history/time,
        operational custody and applicable policy; this function installs no root or state.
    """
    if not verifier.public_key_valid(pinned_root_public_key) or issuer_root_key_id != key_id(
        pinned_root_public_key
    ):
        return ControlAuthentication(
            False,
            (
                Reason(
                    "untrusted_root",
                    content_ref.digest,
                    None,
                    "/issuer_root_key_id",
                    "Control issuer does not match the independently pinned root.",
                ),
            ),
        )
    candidates = tuple(
        envelope
        for envelope in envelopes
        if envelope.statement["content_digest"] == content_ref.digest
    )
    if not candidates:
        return ControlAuthentication(
            False,
            (
                Reason(
                    "signature_required",
                    content_ref.digest,
                    None,
                    None,
                    "Required detached root control signature is missing.",
                ),
            ),
        )
    reasons: list[Reason] = []
    matches = False
    for envelope in candidates:
        failures = list(envelope.reasons)
        statement = envelope.statement
        expected = (
            ("signature_context", "root_control"),
            ("purpose", purpose),
            ("content_schema_id", "evidence_manifest_toolkit." + purpose + ".v1"),
            ("content_byte_length", content_ref.byte_length),
            ("bootstrap_policy_digest", bootstrap_policy_digest),
            ("signer_key_id", issuer_root_key_id),
        )
        for name, value in expected:
            if statement.get(name) != value:
                failures.append(
                    Reason(
                        "untrusted_root"
                        if name in ("bootstrap_policy_digest", "signer_key_id")
                        else "scope_missing",
                        envelope.envelope_ref.digest,
                        None,
                        "/statement/" + name,
                        "Root control statement does not match its independently selected context.",
                    )
                )
        if not verifier.verify(pinned_root_public_key, envelope.message, envelope.signature):
            failures.append(
                Reason(
                    "invalid_signature",
                    envelope.envelope_ref.digest,
                    None,
                    "/signature",
                    "Detached control signature does not verify for its complete message.",
                )
            )
        if not failures:
            matches = True
        reasons.extend(failures)
    return ControlAuthentication(matches, tuple(reasons))
