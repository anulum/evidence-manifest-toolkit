# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — closed referenced local verification policy

"""Retain complete policy declarations without inferring authority or clock qualification."""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

import rfc8785

from ._codecs import decode_reference
from ._errors import ConfigurationError, InputRefused
from ._immutable import FrozenJson, freeze_json
from ._json import AcquiredDocument, JsonValue
from ._policy_literals import (
    BASE_FIELDS,
    CLOCK_FIELD,
    CLOCK_REQUIREMENT,
    CLOCK_SOURCE_CONTRACT,
    CLOSURE_RULE,
    FIXTURE_NAMESPACE,
    FIXTURE_ROOT_RULE,
    FIXTURE_TIME_RULE,
    OPERATIONAL_NAMESPACE,
    OPERATIONAL_ROOT_RULE,
    OPERATIONAL_TIME_RULE,
)
from ._values import BlobRef, Reason

_PURPOSES = {
    "evidence",
    "deployment",
    "human_review",
    "group_certificate",
    "trust_snapshot",
    "root_transition",
}
_SOURCE_CHAIN_CANONICAL_SHA256 = "c317f9bbf53b423bcd227f37a1999db65ffe21903d3ffd0ccf92db439c0e1a1c"


@dataclass(frozen=True, slots=True)
class PolicyDeclaration:
    """Keep every authored requirement separate from its actual satisfaction.

    Attributes
    ----------
    namespace : {"fixture", "operational"}
        Parsed closed wire; neither name conveys prior owner approval.
    required_claim_ids, required_purposes : tuple of str
        Entire unique exact ordered populations, without narrowed acceptance scope.
    required_principal, required_role, required_segment : str
        Exact delegation requirements; producer labels remain distinct from certificates.
    requires_clock : bool
        Whether the selected procedure requires independent evaluation-time qualification.
    clock_reference : BlobRef or None
        Actual declared whole clock reference, without fabricated metadata or qualification.
    declaration : Mapping
        Entire immutable source including every fixture false/null/provenance field.
    """

    namespace: Literal["fixture", "operational"]
    required_claim_ids: tuple[str, ...]
    required_purposes: tuple[str, ...]
    required_principal: str
    required_role: str
    required_segment: str
    requires_clock: bool
    clock_reference: BlobRef | None
    declaration: Mapping[str, FrozenJson]


def _failure(subject: str, pointer: str, *, unsupported: bool = False) -> ConfigurationError:
    """Locate a referenced local configuration refusal inside its actual source bytes.

    Parameters
    ----------
    subject : str
        Actual raw acquired document SHA-256 identity.
    pointer : str
        Exact original field position inside that document.
    unsupported : bool
        Whether a locally selected namespace/procedure is unknown rather than malformed.

    Returns
    -------
    ConfigurationError
        All five source-selected Reason fields and the exact fixed authored detail.
    """
    return ConfigurationError(
        Reason(
            "configuration_error",
            subject,
            None,
            pointer,
            "Unsupported local trust or policy configuration."
            if unsupported
            else "Invalid local trust or policy configuration.",
        )
    )


def _population(value: JsonValue, *, subject: str, pointer: str) -> tuple[str, ...]:
    """Check exact ordered string members without coercion, normalization or duplicates.

    Parameters
    ----------
    value : object
        Entire source array, not an inferred missing or null population.
    subject : str
        Actual acquired policy identity.
    pointer : str
        Actual field containing the required population.

    Returns
    -------
    tuple of str
        Every unique nonempty strict Unicode string in its original order.

    Raises
    ------
    ConfigurationError
        The array or any complete member is malformed or duplicated.
    """
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value):
        raise _failure(subject, pointer)
    result = tuple(cast(list[str], value))
    if len(result) != len(set(result)):
        raise _failure(subject, pointer)
    return result


def parse_policy_source(document: AcquiredDocument) -> PolicyDeclaration:
    """Parse the complete independently selected fixed fixture or operational policy wire.

    Parameters
    ----------
    document : AcquiredDocument
        Whole bounded identity-matching local policy source and original numeric lexemes.

    Returns
    -------
    PolicyDeclaration
        Complete source requirements and immutable declaration. Parsing supplies no accepted
        root, signer, role, native quantity, current state, clock or evidence verdict.

    Raises
    ------
    ConfigurationError
        Closed shape, exact source procedure, fixed fixture population or a clock declaration
        is malformed. Diagnostics retain the actual raw policy identity and field position.
    """
    subject = "sha256:" + hashlib.sha256(document.raw_bytes).hexdigest()
    value = document.value
    if not isinstance(value, dict):
        raise _failure(subject, "")
    if "namespace" not in value:
        raise _failure(subject, "/namespace")
    namespace = value["namespace"]
    if namespace not in (FIXTURE_NAMESPACE, OPERATIONAL_NAMESPACE):
        raise _failure(subject, "/namespace", unsupported=isinstance(namespace, str))
    fixture = namespace == FIXTURE_NAMESPACE
    required = BASE_FIELDS + (
        ("actual_accepted_configuration", "source_chain_ref") if fixture else (CLOCK_FIELD,)
    )
    for name in required:
        if name not in value:
            raise _failure(subject, "/" + name)
    for name in value:
        if name not in required and not (fixture and name == CLOCK_FIELD):
            raise _failure(subject, "/" + name)
    claims = _population(
        value["required_claim_ids"], subject=subject, pointer="/required_claim_ids"
    )
    purposes = _population(
        value["required_purposes"], subject=subject, pointer="/required_purposes"
    )
    if not purposes or any(purpose not in _PURPOSES for purpose in purposes):
        raise _failure(subject, "/required_purposes")
    for name in ("required_principal", "required_role", "required_segment"):
        if not isinstance(value[name], str) or not value[name]:
            raise _failure(subject, "/" + name)
    if re.fullmatch(r"[a-z][a-z0-9_]*", cast(str, value["required_segment"])) is None:
        raise _failure(subject, "/required_segment")
    literals: dict[str, JsonValue] = {
        "required_closure": CLOSURE_RULE,
        "time_rule": FIXTURE_TIME_RULE if fixture else OPERATIONAL_TIME_RULE,
        "root_and_key_rule": FIXTURE_ROOT_RULE if fixture else OPERATIONAL_ROOT_RULE,
    }
    if fixture:
        literals.update(
            {
                "required_purposes": ["evidence"],
                "required_principal": "published-public-test-vector-only",
                "required_role": "author_input_fixture",
                "required_segment": "evidence_manifest_toolkit",
                "actual_accepted_configuration": False,
            }
        )
    for name, expected in literals.items():
        if type(value[name]) is not type(expected) or value[name] != expected:
            raise _failure(subject, "/" + name)
    if fixture:
        source = value["source_chain_ref"]
        if not isinstance(source, dict) or set(source) != {"path", "byte_length", "sha256"}:
            raise _failure(subject, "/source_chain_ref")
        if document.number_tokens.get("/source_chain_ref/byte_length") != "20249" or (
            hashlib.sha256(rfc8785.dumps(source)).hexdigest() != _SOURCE_CHAIN_CANONICAL_SHA256
        ):
            raise _failure(subject, "/source_chain_ref")
    clock_ref = None
    if CLOCK_FIELD in value:
        clock = value[CLOCK_FIELD]
        fields = (
            "requirement",
            "clock_qualification_ref",
            "actual_qualification",
            "caller_utc_string_is_qualification",
            "source_contract",
        )
        if not isinstance(clock, dict):
            raise _failure(subject, "/" + CLOCK_FIELD)
        for name in fields:
            if name not in clock:
                raise _failure(subject, "/" + CLOCK_FIELD + "/" + name)
        for name in clock:
            if name not in fields:
                raise _failure(subject, "/" + CLOCK_FIELD + "/" + name)
        for name, expected in (
            ("requirement", CLOCK_REQUIREMENT),
            ("source_contract", CLOCK_SOURCE_CONTRACT),
            ("caller_utc_string_is_qualification", False),
        ):
            if type(clock[name]) is not type(expected) or clock[name] != expected:
                raise _failure(subject, "/" + CLOCK_FIELD + "/" + name)
        declared = clock["actual_qualification"]
        if not isinstance(declared, str) or not declared or (fixture and declared != "unavailable"):
            raise _failure(subject, "/" + CLOCK_FIELD + "/actual_qualification")
        if clock["clock_qualification_ref"] is not None:
            try:
                clock_ref = decode_reference(
                    clock["clock_qualification_ref"],
                    subject=subject,
                    pointer="/" + CLOCK_FIELD + "/clock_qualification_ref",
                )
            except InputRefused:
                raise _failure(subject, "/" + CLOCK_FIELD + "/clock_qualification_ref") from None
    return PolicyDeclaration(
        "fixture" if fixture else "operational",
        claims,
        purposes,
        cast(str, value["required_principal"]),
        cast(str, value["required_role"]),
        cast(str, value["required_segment"]),
        CLOCK_FIELD in value,
        clock_ref,
        cast(Mapping[str, FrozenJson], freeze_json(value)),
    )
