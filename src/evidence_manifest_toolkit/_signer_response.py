# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — verified exact signer response and detached envelope

"""Accept only an actual raw64 signature for the complete authorized statement message."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

import rfc8785

from ._errors import EmtError, SignerUnavailable
from ._interfaces import Signer
from ._json import JsonValue
from ._statements import statement_message
from ._values import Reason

if TYPE_CHECKING:
    from ._native_signature import NativeVerifier


def sign_statement(
    statement: Mapping[str, JsonValue],
    *,
    signer: Signer,
    expected_public_key: bytes,
    verifier: NativeVerifier,
) -> bytes:
    """Invoke the selected signer once and independently check its complete response.

    Parameters
    ----------
    statement : Mapping
        Whole schema-valid native statement whose delegation/context/scope is already checked.
    signer : Signer
        Explicit caller-owned actual adapter; this operation never loads artifact code.
    expected_public_key : bytes
        Exact previously authenticated eligible delegation or pinned root public bytes.
    verifier : NativeVerifier
        Actually initialized maintained verifier for the exact selected signature profile.

    Returns
    -------
    bytes
        Canonical detached two-field envelope only after the actual response verifies.

    Raises
    ------
    SignerUnavailable
        Adapter failure, public-byte mismatch, wrong raw response type/length or any exact
        profile/equation refusal yields the fixed original reason with the known content subject.
        No unsigned retry, output publication or private provider text reaches the caller.
    EmtError
        Other typed operation errors retain their original classification. Unexpected
        verifier errors propagate separately from adapter response failures.
    """
    failure = Reason(
        "signer_unavailable",
        cast(str, statement["content_digest"]),
        None,
        None,
        "The required signer did not supply a verified response for the exact requested message.",
    )
    message = statement_message(statement)
    try:
        supplied_key: object = signer.public_key
        if not isinstance(supplied_key, bytes) or supplied_key != expected_public_key:
            raise SignerUnavailable(failure)
        response: object = signer.sign(message)
        if not isinstance(response, bytes) or len(response) != 64:
            raise SignerUnavailable(failure)
    except SignerUnavailable as error:
        raise SignerUnavailable(failure) from error
    except EmtError:
        raise
    except Exception as error:
        raise SignerUnavailable(failure) from error
    if not verifier.verify(expected_public_key, message, response):
        raise SignerUnavailable(failure)
    encoded = base64.urlsafe_b64encode(response).rstrip(b"=").decode("ascii")
    return rfc8785.dumps({"statement": statement, "signature": encoded})
