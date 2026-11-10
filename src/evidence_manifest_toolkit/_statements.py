# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — disjoint complete statement message construction

"""Bind whole statements and UTF16-sorted scopes without signing a bare digest."""

import hashlib
from collections.abc import Mapping
from typing import cast

import rfc8785

from ._difference import utf16_key
from ._json import JsonValue
from ._values import Digest, Reason

PROFILE_ID = "evidence_manifest_toolkit.jcs_sha256_ed25519.v1"
_GROUP_PREFIX = b"GOTM-EMT-SIGNED-STATEMENT-V1\n"
_ROOT_PREFIX = b"GOTM-EMT-ROOT-CONTROL-V1\n"


def key_id(public_key: bytes) -> str:
    """Identify exact raw public bytes without treating the identity as authority.

    Parameters
    ----------
    public_key : bytes
        Already validated canonical raw32 public key selected by the caller.

    Returns
    -------
    str
        Original ed25519: prefix and lowercase SHA-256 hexadecimal identity.
    """
    return "ed25519:" + hashlib.sha256(public_key).hexdigest()


def scope_digest(statement: Mapping[str, JsonValue]) -> Digest:
    """Compute the original disjoint group-claim or root-purpose scope identity.

    Parameters
    ----------
    statement : Mapping
        Entire known schema-valid context-specific statement, including content_digest.

    Returns
    -------
    str
        SHA-256 of JCS of the exact original scope object. Group claim IDs sort
        by UTF16 code units; their Unicode content is neither normalized nor repaired.
    """
    if statement["signature_context"] == "group_statement":
        identifiers = cast(list[str], statement["claim_ids"])
        scope: dict[str, JsonValue] = {
            "content_digest": statement["content_digest"],
            "claim_ids": cast(list[JsonValue], sorted(identifiers, key=utf16_key)),
        }
    else:
        scope = {"content_digest": statement["content_digest"], "purpose": statement["purpose"]}
    return "sha256:" + hashlib.sha256(rfc8785.dumps(scope)).hexdigest()


def statement_message(statement: Mapping[str, JsonValue]) -> bytes:
    """Construct the whole native domain-prefixed message after context validation.

    Parameters
    ----------
    statement : Mapping
        Complete known schema-valid native statement, including original claimed UTC.

    Returns
    -------
    bytes
        Exact applicable original prefix, one LF and complete RFC8785 statement bytes.
        No envelope, payload digest alone, algorithm fallback or timestamp rewrite enters it.
    """
    prefix = _GROUP_PREFIX if statement["signature_context"] == "group_statement" else _ROOT_PREFIX
    return prefix + rfc8785.dumps(statement)


def statement_reasons(statement: Mapping[str, JsonValue], *, subject: Digest) -> tuple[Reason, ...]:
    """Check unique complete claim scope and its exact computed digest.

    Parameters
    ----------
    statement : Mapping
        Entire native schema-valid statement with disjoint context fields.
    subject : str
        Actual statement content identity for diagnostic locations.

    Returns
    -------
    tuple of Reason
        Actual scope/duplicate refusals, without cryptographic or trust evaluation.
    """
    reasons: list[Reason] = []
    if statement["signature_context"] == "group_statement":
        identifiers = cast(list[str], statement["claim_ids"])
        if len(identifiers) != len(set(identifiers)):
            reasons.append(
                Reason(
                    "scope_missing",
                    subject,
                    None,
                    "/claim_ids",
                    "Claim scope contains duplicate identities.",
                )
            )
    if statement["scope_digest"] != scope_digest(statement):
        reasons.append(
            Reason(
                "scope_missing",
                subject,
                None,
                "/scope_digest",
                "Statement scope digest does not match its complete scope.",
            )
        )
    return tuple(reasons)
