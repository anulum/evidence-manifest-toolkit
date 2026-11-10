# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete caller signing statement construction

"""Validate disjoint caller fields before binding the four computed content identities."""

from copy import deepcopy
from typing import cast

import rfc8785
from jsonschema import Draft202012Validator
from referencing.jsonschema import Schema

from ._content import CompleteContent
from ._errors import InputRefused
from ._immutable import thaw_json
from ._json import JsonValue, acquire_document
from ._reference_paths import configuration_refusal
from ._registry import common_schema
from ._statements import scope_digest
from ._trust_types import SigningRequest
from ._utc import utc_key
from ._values import Limits, Reason

_COMPUTED = {"content_schema_id", "content_digest", "content_byte_length", "scope_digest"}
_CONTROL_CONTENT = {
    "evidence_manifest_toolkit.group_certificate.v1": "group_certificate",
    "evidence_manifest_toolkit.trust_snapshot.v1": "trust_snapshot",
}


def validate_signing_request(signing: SigningRequest, *, limits: Limits) -> dict[str, JsonValue]:
    """Validate exact native caller fields without fabricated computed placeholders.

    Parameters
    ----------
    signing : SigningRequest
        Original context-specific mapping, omitting exactly the four computed fields.
    limits : Limits
        Whole operation acquisition limits for the complete caller statement configuration.

    Returns
    -------
    dict
        Detached complete admitted caller fields, retaining exact Unicode and UTC tokens.

    Raises
    ------
    ConfigurationError
        A native field, context prohibition, closed shape or parsed UTC token is invalid.
    """
    if not isinstance(signing, SigningRequest):
        raise configuration_refusal("/signing")
    fields = thaw_json(signing.statement_fields)
    if not isinstance(fields, dict):
        raise configuration_refusal("/signing/statement_fields")
    original = common_schema("signed_statement", limits=limits)
    if isinstance(original, bool):
        raise configuration_refusal("/registry/entries")
    schema = deepcopy(dict(original))
    properties = cast(dict[str, Schema], schema["properties"])
    for name in _COMPUTED:
        del properties[name]
    schema["required"] = [name for name in schema["required"] if name not in _COMPUTED]
    if not Draft202012Validator(schema).is_valid(fields):
        raise configuration_refusal("/signing/statement_fields")
    try:
        acquire_document(rfc8785.dumps(fields), limits=limits)
        utc_key(cast(str, fields["claimed_signed_at"]))
    except (InputRefused, rfc8785.CanonicalizationError, UnicodeError) as error:
        raise configuration_refusal("/signing/statement_fields") from error
    return fields


def construct_statement(
    fields: dict[str, JsonValue], *, content: CompleteContent
) -> dict[str, JsonValue]:
    """Bind the whole content and actual claim scope without granting signing authority.

    Parameters
    ----------
    fields : dict
        Complete already validated native caller fields, without computed identities.
    content : CompleteContent
        Entire independently checked content and native claim obligations.

    Returns
    -------
    dict
        Complete original native statement with the four deterministic computed fields.
        The caller's mapping and all original content bytes remain unchanged.

    Raises
    ------
    InputRefused
        Group scope is not a native manifest/resolving claim selection or root purpose
        contradicts the actual control content. No first root issuance is performed.
    """
    reference = content.content_ref
    schema_id = reference.schema_id
    if fields["signature_context"] == "group_statement":
        if schema_id != "evidence_manifest_toolkit.manifest.v1":
            raise InputRefused(
                Reason(
                    "scope_missing",
                    reference.digest,
                    None,
                    "/content_schema_id",
                    "Group statements require the complete native manifest.",
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
    elif _CONTROL_CONTENT.get(schema_id or "") != fields["purpose"]:
        raise InputRefused(
            Reason(
                "scope_missing",
                reference.digest,
                None,
                "/purpose",
                "Root purpose does not match the supplied control content.",
            )
        )
    statement = {
        **fields,
        "content_schema_id": schema_id,
        "content_digest": reference.digest,
        "content_byte_length": reference.byte_length,
    }
    statement["scope_digest"] = scope_digest(statement)
    return statement
