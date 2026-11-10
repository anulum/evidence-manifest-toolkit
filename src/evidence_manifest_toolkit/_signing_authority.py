# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact current delegation before signer invocation

"""Require established current authority before requesting any detached signature."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

from ._budget import ReferenceBudget
from ._codecs import decode_bytes, decode_reference
from ._content import CompleteContent
from ._control_authentication import authenticate_control
from ._control_context import references_agree
from ._errors import InputRefused, ReferenceUnavailable
from ._interfaces import Resolver
from ._json import JsonValue
from ._registry_types import SchemaRegistry
from ._schema_resources import StaticSchema
from ._snapshot_history import revocation_reasons
from ._statements import key_id
from ._trust_state import select_trust_state
from ._trust_types import TrustContext
from ._typed_control import acquire_control_link
from ._utc import utc_key
from ._values import Reason

if TYPE_CHECKING:
    from ._native_signature import NativeVerifier


def signing_public_key(
    statement: Mapping[str, JsonValue],
    *,
    content: CompleteContent,
    trust: TrustContext,
    registry: SchemaRegistry,
    schemas: Mapping[str, StaticSchema],
    resolver: Resolver,
    budget: ReferenceBudget,
    verifier: NativeVerifier,
) -> bytes:
    """Return only the exact independently authenticated current eligible public key.

    Parameters
    ----------
    statement : Mapping
        Entire validated native statement with all actual computed content identities.
    content : CompleteContent
        Whole schema-valid content and selected required source closure.
    trust : TrustContext
        Validated current trusted caller selection, independently accepted before this call.
    registry : SchemaRegistry
        Whole independently chosen catalogue and original complete static entries.
    schemas : Mapping
        Already validated full native schema dispatch table.
    resolver : Resolver
        Actual local source, without alternative receipt or key discovery.
    budget : ReferenceBudget
        Sole original operation budget including content and control reads.
    verifier : NativeVerifier
        Actual maintained implementation of the full selected signature profile.

    Returns
    -------
    bytes
        Exact raw32 eligible public key, before any caller signer method is invoked.

    Raises
    ------
    InputRefused
        Current source, full root authentication, delegation, purpose, validity or revocation
        does not hold. This operation creates no root, certificate or trust selection.
    ReferenceUnavailable
        Required original full reference or typed digest is genuinely unavailable.
    """
    state = select_trust_state(
        trust,
        registry=registry,
        schemas=schemas,
        resolver=resolver,
        budget=budget,
        verifier=verifier,
    )
    if state.closure.missing_references:
        raise ReferenceUnavailable(state.closure.missing_references[0])
    if state.reasons:
        raise InputRefused(state.reasons[0])
    reference = content.content_ref

    def refuse(pointer: str, code: str = "invalid_delegation") -> InputRefused:
        """Build a located actual-content authority refusal before signer invocation.

        Parameters
        ----------
        pointer : str
            Exact native statement or content field that contradicts the current selection.
        code : str
            Stable native authority or scope code.

        Returns
        -------
        InputRefused
            Complete authored refusal without interpreting a signer failure as acceptance.
        """
        return InputRefused(
            Reason(
                code,
                reference.digest,
                None,
                pointer,
                "Requested statement is outside the independently selected current authority.",
            )
        )

    if statement["signature_context"] == "root_control":
        if statement["bootstrap_policy_digest"] != trust.bootstrap_policy_ref.digest:
            raise refuse("/bootstrap_policy_digest", "untrusted_root")
        if statement["signer_key_id"] != state.bootstrap.root_key_id:
            raise refuse("/signer_key_id", "untrusted_root")
        identity = reference.digest, reference.digest_basis, reference.byte_length
        value = cast(dict[str, JsonValue], content.closure.documents[identity].value)
        if value["issuer_root_key_id"] != state.bootstrap.root_key_id:
            raise refuse("/issuer_root_key_id", "untrusted_root")
        return state.bootstrap.root_public_key
    if statement["trust_snapshot_digest"] != trust.current_snapshot_ref.digest:
        raise refuse("/trust_snapshot_digest")
    certificate_digest = cast(str, statement["group_certificate_digest"])
    selected = acquire_control_link(
        certificate_digest,
        field="group_certificate_digest",
        statement_digest=reference.digest,
        resolver=resolver,
        budget=budget,
    )
    if selected.missing_digest is not None:
        raise ReferenceUnavailable(selected.missing_digest)
    if selected.observation.reasons:
        raise InputRefused(selected.observation.reasons[0])
    certificate_ref, certificate_document = selected.reference, selected.document
    if certificate_ref is None or certificate_document is None:
        raise refuse("/group_certificate_digest")
    current_value = cast(dict[str, JsonValue], state.history.nodes[0].document.value)
    delegated = [
        decode_reference(
            value,
            subject=trust.current_snapshot_ref.digest,
            pointer="/group_certificate_refs/" + str(index),
        )
        for index, value in enumerate(
            cast(list[JsonValue], current_value["group_certificate_refs"])
        )
    ]
    if not any(
        references_agree(
            certificate_ref,
            candidate,
            expected_schema="evidence_manifest_toolkit.group_certificate.v1",
        )
        for candidate in delegated
    ):
        raise refuse("/group_certificate_digest")
    certificate = cast(dict[str, JsonValue], certificate_document.value)
    authentication = authenticate_control(
        certificate_ref,
        purpose="group_certificate",
        issuer_root_key_id=cast(str, certificate["issuer_root_key_id"]),
        bootstrap_policy_digest=trust.bootstrap_policy_ref.digest,
        pinned_root_public_key=state.bootstrap.root_public_key,
        envelopes=state.envelopes,
        verifier=verifier,
    )
    if authentication.reasons:
        raise InputRefused(authentication.reasons[0])
    if statement["signer_key_id"] != certificate["subject_key_id"]:
        raise refuse("/signer_key_id")
    if statement["purpose"] not in cast(list[str], certificate["allowed_purposes"]):
        raise refuse("/purpose")
    if "evidence_manifest_toolkit" not in cast(list[str], certificate["permitted_tool_segments"]):
        raise refuse("/permitted_tool_segments")
    evaluation = utc_key(trust.evaluation_time)
    if (
        not utc_key(cast(str, certificate["not_before"]))
        <= evaluation
        < utc_key(cast(str, certificate["not_after"]))
    ):
        raise refuse("/not_after")
    revocations = revocation_reasons(state.history, key_id=cast(str, statement["signer_key_id"]))
    if revocations:
        raise InputRefused(revocations[0])
    try:
        public_key = decode_bytes(cast(str, certificate["public_key_base64url"]))
    except ValueError:
        raise refuse("/public_key_base64url") from None
    if (
        not verifier.public_key_valid(public_key)
        or key_id(public_key) != certificate["subject_key_id"]
    ):
        raise refuse("/public_key_base64url")
    return public_key
