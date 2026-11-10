# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole native challenge and exact own-key message context

"""Bind all challenge context fields without converting declarations into issuer or custody proof."""

from dataclasses import dataclass
from typing import Literal, cast

import rfc8785

from ._codecs import decode_bytes
from ._errors import InputRefused
from ._format_sources import FixedSource
from ._native_possession_sources import possession_value
from ._values import BlobRef, Reason, Utc

_DOMAIN = b"GOTM-NATIVE-KEY-POSSESSION\x00\x01"


@dataclass(frozen=True, slots=True)
class NativePossessionMessage:
    """Keep the entire actual mathematical message and its declared challenge interval.

    Attributes
    ----------
    message : bytes
        Exact fixed application domain and whole canonical eight-field body.
    issued_at, expires_at : Utc
        Whole original finite challenge interval. No time-source acceptance follows.
    """

    message: bytes
    issued_at: Utc
    expires_at: Utc


def native_source_utc(source: FixedSource, field: str) -> Utc:
    """Validate a whole source UTC token while retaining its actual identity and field.

    Parameters
    ----------
    source : FixedSource
        Complete original native record with a schema-valid string field.
    field : str
        Literal owning callsite field, never received executable or path selection.

    Returns
    -------
    Utc
        Entire unchanged Common-valid token, without Clock qualification.

    Raises
    ------
    InputRefused
        The original Common UTC parser refuses this exact source field.
    """
    try:
        return Utc(possession_value(source)[field])
    except InputRefused as error:
        reason = error.reason
        raise InputRefused(
            Reason(reason.code, source.source.reference.digest, None, "/" + field, reason.detail)
        ) from error


def build_native_possession_message(
    identity: FixedSource,
    identity_rule: FixedSource,
    method: FixedSource,
    result: FixedSource,
    challenge: FixedSource,
    issuer: FixedSource,
    request: FixedSource,
    *,
    role: Literal["producer", "runner"],
    expected_request: BlobRef | None,
) -> NativePossessionMessage:
    """Compare every whole selected context and construct only the exact specified message.

    Parameters
    ----------
    identity, identity_rule, method : FixedSource
        Entire independently selected principal/key/policy and possession declarations.
    result, challenge, issuer, request : FixedSource
        Whole fixed-schema original result, challenge, earlier issuer rule and request.
    role : {"producer", "runner"}
        Independent owning callsite role.
    expected_request : BlobRef or None
        Whole committed runner request; absent producer selection is not admitted here.

    Returns
    -------
    NativePossessionMessage
        Complete source-bound message and exact finite interval. No equation, issuer,
        nonce unpredictability, observed process, custody or possession class is admitted.

    Raises
    ------
    InputRefused
        Actual method, field, role, key, canonical nonce, request or UTC context conflicts.
    """
    declared = possession_value(identity)
    value, challenge_value = possession_value(result), possession_value(challenge)
    method_value, issuer_value = possession_value(method), possession_value(issuer)

    def refuse(source: FixedSource, field: str) -> InputRefused:
        """Locate an original whole source conflict without echoing received values."""
        return InputRefused(
            Reason(
                "invalid_claim",
                source.source.reference.digest,
                None,
                "/" + field,
                "Native key-possession sources conflict.",
            )
        )

    for source, field, actual, expected in (
        (
            result,
            "possession_method_ref",
            value["possession_method_ref"],
            dict(method.source.reference.to_mapping()),
        ),
        (
            result,
            "identity_policy_ref",
            value["identity_policy_ref"],
            dict(identity_rule.source.reference.to_mapping()),
        ),
        (
            challenge,
            "identity_policy_ref",
            challenge_value["identity_policy_ref"],
            value["identity_policy_ref"],
        ),
        (
            challenge,
            "semantic_law_ref",
            challenge_value["semantic_law_ref"],
            method_value["semantic_law_ref"],
        ),
        (
            issuer,
            "semantic_law_ref",
            issuer_value["semantic_law_ref"],
            method_value["semantic_law_ref"],
        ),
        (
            issuer,
            "challenge_completion_method_ref",
            issuer_value["challenge_completion_method_ref"],
            method_value["receiver_method_ref"],
        ),
        (
            challenge,
            "issuer_source_ref",
            challenge_value["issuer_source_ref"],
            issuer_value["issuer_identity_ref"],
        ),
    ):
        if actual != expected:
            raise refuse(source, field)
    for field, identity_field in (
        ("principal_id", "principal_id"),
        ("vendor_id", "vendor_id"),
        ("public_key_ref", "declared_public_key_ref"),
        ("launch_record_ref", "actual_launch_or_declared_source_ref"),
        ("process_identity_ref", "process_identity_ref"),
    ):
        if challenge_value[field] != declared[identity_field]:
            raise refuse(challenge, field)
    if (
        method_value["possession_scope"] == "observed_process_signing_capability"
        and challenge_value["process_identity_ref"] is None
    ):
        raise refuse(challenge, "process_identity_ref")
    request_value = possession_value(request)
    for field, expected in (
        ("request_kind", "producer_context" if role == "producer" else "independent_validation"),
        ("identity_policy_ref", value["identity_policy_ref"]),
        ("expected_principal_id", declared["principal_id"]),
        ("expected_vendor_id", declared["vendor_id"]),
        ("expected_public_key_ref", declared["declared_public_key_ref"]),
    ):
        if request_value[field] != expected:
            raise refuse(request, field)
    if expected_request is not None and request.source.reference != expected_request:
        raise refuse(challenge, "execution_request_ref")
    issued = native_source_utc(challenge, "issued_at")
    expires = native_source_utc(challenge, "expires_at")
    if issued.compare(expires) >= 0:
        raise refuse(challenge, "expires_at")
    try:
        decode_bytes(cast(str, challenge_value["nonce_base64url"]))
    except ValueError as error:
        raise refuse(challenge, "nonce_base64url") from error
    message_value = {
        "possession_method_ref": value["possession_method_ref"],
        "identity_policy_ref": value["identity_policy_ref"],
        "challenge_ref": value["challenge_ref"],
        **{
            field: challenge_value[field]
            for field in (
                "principal_id",
                "vendor_id",
                "public_key_ref",
                "launch_record_ref",
                "process_identity_ref",
            )
        },
    }
    return NativePossessionMessage(_DOMAIN + rfc8785.dumps(message_value), issued, expires)
