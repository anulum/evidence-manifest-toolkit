# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected protected receipt mathematics

"""Check the original native equation without supplying protected authority or custody."""

from dataclasses import dataclass

from ._budget import ReferenceBudget
from ._interfaces import Resolver
from ._protected_certificate_keys import acquire_certificate_public_key
from ._protected_ordinary_sources import ProtectedOrdinarySource
from ._signature_provider import initialize_verifier
from ._values import BlobRef, Reason


@dataclass(frozen=True, slots=True)
class ProtectedReceiptMath:
    """Retain the whole source candidate, actual primitive input and mathematical result.

    Attributes
    ----------
    source : ProtectedOrdinarySource
        Complete original target/selected certificate/scope/native receipt correspondence.
    public_key_reference, public_key : BlobRef, bytes
        Exact selected source and unchanged bounded data, without a guessed decoder.
        A key source supplies no enrolled authority, identity, custody or possession proof.
    signature_valid : bool
        Actual raw32 key-ID and exact full-message native equation result, never a class
        acceptance, authenticated issuer, Clock, protected key or current-use verdict.
    reasons : tuple of Reason
        Actual equation contradictions. Key-data contradictions retain their original typed
        source failure before the primitive. Empty proves no other predicate.
    """

    source: ProtectedOrdinarySource
    public_key_reference: BlobRef
    public_key: bytes
    signature_valid: bool
    reasons: tuple[Reason, ...]


def check_protected_receipt_math(
    source: ProtectedOrdinarySource, *, resolver: Resolver, budget: ReferenceBudget
) -> ProtectedReceiptMath:
    """Use the selected certificate's actual raw32 data for the unchanged V2 primitive.

    Parameters
    ----------
    source : ProtectedOrdinarySource
        Whole receipt after complete content, source, scope and declared window checks.
        Its selected native graph already checked every full key Ref's byte identity.
    resolver : Resolver
        Original sole bounded source; no discovery, decoder, root or network fallback.
    budget : ReferenceBudget
        SAME invocation budget with the complete selected native key source cached.

    Returns
    -------
    ProtectedReceiptMath
        Original receipt/certificate and actual raw input with a mathematical result.
        Encoded source objects are not reinterpreted, keys are not generated/enrolled,
        and full native/control/class/Clock/identity/custody checks remain necessary.

    Raises
    ------
    ConfigurationError
        An actual compatible required signature has no conforming maintained verifier.
    InputRefused
        Actual key data/ID, whole reference metadata or an original source limit conflicts.
    ReferenceUnavailable
        The original whole key source is unavailable, preserving its exact argument.
    """
    reference, public = acquire_certificate_public_key(
        source.certificate, resolver=resolver, budget=budget
    )
    verifier = initialize_verifier()
    from ._successor_signatures import verify_successor_signature

    valid = verify_successor_signature(source.envelope, public_key=public, verifier=verifier)
    reasons = (
        ()
        if valid
        else (
            Reason(
                "invalid_signature",
                source.envelope.reference.digest,
                None,
                "/signature",
                "The protected statement signature is invalid.",
            ),
        )
    )
    return ProtectedReceiptMath(source, reference, public, valid, reasons)
