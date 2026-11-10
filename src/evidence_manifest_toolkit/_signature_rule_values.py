# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — fixed native signature-obligation data grammar

"""Decode whole independently selected signature rules without granting a waiver."""

from collections.abc import Mapping
from typing import cast

from ._codecs import decode_reference
from ._errors import ConfigurationError
from ._json import JsonValue
from ._utc import utc_key
from ._values import BlobRef, Digest, Reason

RULE_FIELDS = frozenset(
    {
        "method_id",
        "profile_class",
        "whole_base_policy_ref",
        "whole_conditions_and_limitations_ref",
        "required_claim_ids",
        "required_purposes",
        "required_reference_paths",
        "unsigned_exception",
        "valid_from",
        "valid_until",
        "renewal_rule",
        "provenance_refs",
    }
)
EXCEPTION_FIELDS = frozenset({"content_ref", "claim_ids", "purposes", "validation_record_refs"})


def rule_configuration_refusal(subject: Digest, pointer: str) -> ConfigurationError:
    """Locate an invalid fixed native rule without echoing received strings.

    Parameters
    ----------
    subject : str
        Whole acquired raw rule identity.
    pointer : str
        Actual closed field position.

    Returns
    -------
    ConfigurationError
        Original typed configuration refusal with a fixed safe diagnostic.
    """
    return ConfigurationError(
        Reason("configuration_error", subject, None, pointer, "Invalid signature-obligation rule.")
    )


def rule_object(
    value: JsonValue, fields: frozenset[str], *, subject: Digest, pointer: str
) -> dict[str, JsonValue]:
    """Require the entire closed object without projecting unexpected source members.

    Parameters
    ----------
    value : object
        Entire actual raw object.
    fields : frozenset of str
        Fixed installed complete member population.
    subject : str
        Whole raw rule identity.
    pointer : str
        Actual object position.

    Returns
    -------
    dict
        The original object, without coercion or inserted defaults.

    Raises
    ------
    ConfigurationError
        The value is not an object or its complete member population differs.
    """
    if not isinstance(value, dict) or set(value) != fields:
        raise rule_configuration_refusal(subject, pointer)
    return value


def rule_population(value: JsonValue, *, subject: Digest, pointer: str) -> tuple[str, ...]:
    """Retain a whole unique ordered string population with no wildcard interpretation.

    Parameters
    ----------
    value : object
        Entire declared array; an empty array supplies no inferred exemption.
    subject : str
        Whole raw rule identity.
    pointer : str
        Actual containing field.

    Returns
    -------
    tuple of str
        All exact nonempty members in original order.

    Raises
    ------
    ConfigurationError
        Shape, member type, emptiness or uniqueness is invalid.
    """
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise rule_configuration_refusal(subject, pointer)
    result = tuple(cast(list[str], value))
    if len(set(result)) != len(result):
        raise rule_configuration_refusal(subject, pointer)
    return result


def rule_references(value: JsonValue, *, subject: Digest, pointer: str) -> tuple[BlobRef, ...]:
    """Decode every complete selected reference while retaining ordinary typed failures.

    Parameters
    ----------
    value : object
        Whole ordered reference array.
    subject : str
        Actual containing rule identity.
    pointer : str
        Exact array position.

    Returns
    -------
    tuple of BlobRef
        All whole references with their original metadata, without digest-only deduplication.

    Raises
    ------
    ConfigurationError
        The array or its uniqueness is invalid.
    InputRefused
        An actual original whole reference is malformed.
    """
    if not isinstance(value, list):
        raise rule_configuration_refusal(subject, pointer)
    result = tuple(
        decode_reference(item, subject=subject, pointer=pointer + "/" + str(index))
        for index, item in enumerate(value)
    )
    if len(set(result)) != len(result):
        raise rule_configuration_refusal(subject, pointer)
    return result


def check_rule_header(value: Mapping[str, JsonValue], *, subject: Digest) -> None:
    """Validate the fixed method, all ordinary purposes and the complete renewal window.

    Parameters
    ----------
    value : Mapping
        Entire already closed raw rule object.
    subject : str
        Actual rule identity, retained in malformed UTC diagnostics.

    Raises
    ------
    ConfigurationError
        Method, class, purpose, renewal law or window shape/order is unsupported.
    InputRefused
        An original UTC value is malformed or outside the supported common source history.
    """
    for field, accepted in (
        ("method_id", ("emt_signature_obligations_v1",)),
        (
            "profile_class",
            ("unsigned_declared", "software_local_unprotected", "protected_delegated"),
        ),
        ("renewal_rule", ("fresh_independent_rule_before_expiry_no_implicit_extension",)),
    ):
        if value[field] not in accepted:
            raise rule_configuration_refusal(subject, "/" + field)
    purposes = rule_population(
        value["required_purposes"], subject=subject, pointer="/required_purposes"
    )
    if any(purpose not in ("evidence", "deployment", "human_review") for purpose in purposes):
        raise rule_configuration_refusal(subject, "/required_purposes")
    for field in ("valid_from", "valid_until"):
        if not isinstance(value[field], str):
            raise rule_configuration_refusal(subject, "/" + field)
    if utc_key(
        cast(str, value["valid_from"]), subject_digest=subject, pointer="/valid_from"
    ) >= utc_key(cast(str, value["valid_until"]), subject_digest=subject, pointer="/valid_until"):
        raise rule_configuration_refusal(subject, "/valid_until")
