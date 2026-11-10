# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact full-message successor native signature boundary

"""Check V2 mathematical targets without turning key possession into signing authority."""

from typing import cast

import rfc8785

from ._budget import ReferenceBudget
from ._codecs import encode_bytes
from ._errors import EmtError, InputRefused, SignerUnavailable
from ._immutable import thaw_json
from ._interfaces import Signer
from ._native_signature import NativeVerifier
from ._statements import key_id
from ._successor_envelopes import (
    SuccessorEnvelope,
    SuccessorStatement,
    parse_successor_envelope,
)
from ._values import Reason


def verify_successor_signature(
    envelope: SuccessorEnvelope, *, public_key: bytes, verifier: NativeVerifier
) -> bool:
    """Verify the exact complete V2 message and actual claimed signer identity.

    Parameters
    ----------
    envelope : SuccessorEnvelope
        Whole independently parsed V2 target and its original raw64 signature.
    public_key : bytes
        Actual independently selected raw32 bytes, not an artifact-selected trust root.
    verifier : NativeVerifier
        Explicit initialized maintained point implementation for the exact selected equation.

    Returns
    -------
    bool
        Canonical key/identity/signature relationship for the ENTIRE disjoint message.
        This does not qualify provider/custody, authorization, Clock, current use or domain.
    """
    return (
        verifier.public_key_valid(public_key)
        and key_id(public_key) == envelope.statement.value["signer_key_id"]
        and verifier.verify(public_key, envelope.statement.message, envelope.signature)
    )


def sign_successor_statement(
    statement: SuccessorStatement,
    *,
    signer: Signer,
    expected_public_key: bytes,
    verifier: NativeVerifier,
    budget: ReferenceBudget,
) -> bytes:
    """Invoke the authorized adapter once and verify its exact whole-message response.

    Parameters
    ----------
    statement : SuccessorStatement
        Entire validated V2 statement AFTER independent class/source/target/scope/time/
        authority checks. This mathematical boundary grants no missing authorization.
    signer : Signer
        Explicit actual caller-owned adapter; no artifact code or provider is loaded.
    expected_public_key : bytes
        Actual eligible software or protected key from that independently checked state.
    verifier : NativeVerifier
        Initialized exact uncofactored reduced-challenge PureEd25519 implementation.
    budget : ReferenceBudget
        SAME invocation source budget and complete receipt size/depth bounds, without
        a fresh allowance for the returned signature or fixed statement definition.

    Returns
    -------
    bytes
        Complete canonical two-field native envelope, only after exact key/message/raw64
        verification. Original V1 framing and all caller bytes remain unchanged.

    Raises
    ------
    InputRefused
        Declared signer identity differs from the actual independently eligible key.
        The adapter is never called on that conflicting target. A returned whole
        envelope exceeding the operation bounds is refused before publication.
    ConfigurationError
        The complete installed statement definition fails its fixed source binding.
    SignerUnavailable
        Actual adapter key, response type/length, signing or whole-message verification fails;
        private exception text is withheld and no unsigned retry or publication occurs.
    EmtError
        Other typed operation failures retain their original boundary; unexpected
        verifier errors propagate rather than masquerading as adapter failures.
    """
    subject = cast(str, statement.value["content_digest"])
    if (
        not verifier.public_key_valid(expected_public_key)
        or key_id(expected_public_key) != statement.value["signer_key_id"]
    ):
        raise InputRefused(
            Reason(
                "invalid_signature",
                subject,
                None,
                "/signer_key_id",
                "Native signer identity does not match the selected authorization.",
            )
        )
    failure = Reason(
        "signer_unavailable",
        subject,
        None,
        None,
        "The required signer did not supply a verified response for the exact requested message.",
    )
    try:
        supplied: object = signer.public_key
        if not isinstance(supplied, bytes) or supplied != expected_public_key:
            raise SignerUnavailable(failure)
        response: object = signer.sign(statement.message)
        if not isinstance(response, bytes) or len(response) != 64:
            raise SignerUnavailable(failure)
    except SignerUnavailable as error:
        raise SignerUnavailable(failure) from error
    except EmtError:
        raise
    except Exception as error:
        raise SignerUnavailable(failure) from error
    if not verifier.verify(expected_public_key, statement.message, response):
        raise SignerUnavailable(failure)
    encoded = rfc8785.dumps(
        {"statement": thaw_json(statement.value), "signature": encode_bytes(response)}
    )
    return parse_successor_envelope(
        encoded, context=statement.context, budget=budget
    ).canonical_bytes
