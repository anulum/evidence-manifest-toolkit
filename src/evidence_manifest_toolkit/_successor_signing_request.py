# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete successor caller fields and actual signing target

"""Bind V2 signing requests to whole content without borrowing V1 computed fields."""

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from typing import cast

import rfc8785
from referencing.jsonschema import Schema

from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._content import CompleteContent
from ._difference import utf16_key
from ._errors import InputRefused
from ._immutable import thaw_json
from ._json import JsonValue, acquire_document
from ._reference_paths import configuration_refusal
from ._successor_envelopes import (
    SuccessorSignatureContext,
    SuccessorStatement,
    parse_successor_statement,
)
from ._successor_formats import load_fixed_format
from ._trust_types import SigningRequest
from ._utc import utc_key
from ._values import Reason

_COMPUTED = frozenset(("content_schema_id", "content_digest", "content_byte_length"))


def validate_successor_signing_request(
    signing: SigningRequest, *, budget: ReferenceBudget
) -> dict[str, JsonValue]:
    """Validate all thirteen caller fields against the whole fixed V2 source.

    Parameters
    ----------
    signing : SigningRequest
        Entire independently supplied immutable request, omitting exactly the three
        computed V2 content fields. A V1 scope_digest is never admitted or computed.
    budget : ReferenceBudget
        SAME invocation budget for the whole installed schema resource and all
        supplied JSON size/depth limits, without a fresh constructor allowance.

    Returns
    -------
    dict
        Detached complete original caller fields, with all four full authorization
        references, explicit context, original signing UTC and unchanged claim scope.
        No source resolution, key eligibility or signing authority is established.

    Raises
    ------
    ConfigurationError
        Actual caller shape, closed fields, Ref/key/UTC encoding or claim order
        violates the selected native method, or the fixed source cannot be loaded.
    InputRefused
        Loading the whole installed source exceeds the shared operation budget.
    """
    pointer = "/signing/statement_fields"
    if not isinstance(signing, SigningRequest):
        raise configuration_refusal("/signing")
    fields = thaw_json(signing.statement_fields)
    if not isinstance(fields, dict):
        raise configuration_refusal(pointer)
    selected = load_fixed_format(
        "evidence_manifest_toolkit.signed_statement.v2", pointer=pointer, budget=budget
    )
    definition = deepcopy(dict(cast(Mapping[str, object], selected.definition)))
    properties = cast(dict[str, Schema], definition["properties"])
    for name in _COMPUTED:
        del properties[name]
    definition["required"] = [
        name for name in cast(list[str], definition["required"]) if name not in _COMPUTED
    ]
    replace(selected, definition=definition).validate_configuration(fields, pointer=pointer)
    if re.fullmatch(r"ed25519:[0-9a-f]{64}", cast(str, fields["signer_key_id"])) is None:
        raise configuration_refusal(pointer + "/signer_key_id")
    try:
        acquire_document(rfc8785.dumps(fields), limits=budget.limits)
        for name in ("authorizing_state_ref", "authorization_ref", "scope_ref", "snapshot_ref"):
            if fields[name] is not None:
                decode_reference(fields[name], subject=None, pointer="/" + name)
        utc_key(cast(str, fields["claimed_signed_at"]), pointer="/claimed_signed_at")
    except InputRefused as error:
        raise configuration_refusal(pointer + (error.reason.pointer or "")) from error
    except (rfc8785.CanonicalizationError, UnicodeError) as error:
        raise configuration_refusal(pointer) from error
    identifiers = cast(list[str], fields["claim_ids"])
    if identifiers != sorted(identifiers, key=utf16_key):
        raise configuration_refusal(pointer + "/claim_ids")
    return fields


def construct_successor_statement(
    fields: dict[str, JsonValue],
    *,
    content: CompleteContent,
    context: SuccessorSignatureContext,
    budget: ReferenceBudget,
) -> SuccessorStatement:
    """Bind the actual whole content and every selected claim to the full V2 statement.

    Parameters
    ----------
    fields : dict
        All original caller fields after complete request validation; never mutated.
    content : CompleteContent
        Entire actual checked content, original JCS identity and full claim inventory.
    context : {"ordinary_statement", "authority_control"}
        Independent owning operation. A received context never chooses its implementation.
    budget : ReferenceBudget
        SAME invocation budget for full statement bounds and its fixed native definition.

    Returns
    -------
    SuccessorStatement
        All sixteen native fields and exact complete disjoint message, using only
        the three deterministic identities from the actual content. Authority,
        time, class and source eligibility must still precede any Signer access.

    Raises
    ------
    InputRefused
        A selected ordinary claim does not resolve in the actual whole manifest,
        actual native context/purpose/target contradicts its method, or the full
        statement exceeds the invocation bounds or violates the complete schema.
    ConfigurationError
        The whole installed native definition cannot satisfy its fixed binding.
    """
    reference = content.content_ref
    if context == "ordinary_statement":
        if reference.schema_id != "evidence_manifest_toolkit.manifest.v1":
            raise InputRefused(
                Reason(
                    "scope_missing",
                    reference.digest,
                    None,
                    "/content_schema_id",
                    "Ordinary statements require the complete native manifest.",
                )
            )
        actual = {claim.claim_id for claim in content.content_claim_obligations}
        for index, identifier in enumerate(cast(list[str], fields["claim_ids"])):
            if identifier not in actual:
                raise InputRefused(
                    Reason(
                        "scope_missing",
                        reference.digest,
                        identifier,
                        "/claim_ids/" + str(index),
                        "Signed claim scope does not resolve in the complete content.",
                    )
                )
    value = {
        **fields,
        "content_schema_id": reference.schema_id,
        "content_digest": reference.digest,
        "content_byte_length": reference.byte_length,
    }
    return parse_successor_statement(
        acquire_document(rfc8785.dumps(value), limits=budget.limits),
        context=context,
        budget=budget,
        subject=reference.digest,
        pointer="",
    )
