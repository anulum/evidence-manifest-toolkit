# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — closed offline configuration decoding

"""Decode original caller configurations without loading an artifact-selected executable."""

import re
from typing import Literal, cast

from jsonschema import Draft202012Validator
from referencing.jsonschema import Schema

from ._codecs import DECIMAL_PATTERN, decode_bytes, decode_reference
from ._errors import InputRefused
from ._immutable import freeze_json
from ._invocation_wire import CallerTrust
from ._json import AcquiredDocument, JsonValue
from ._reference_paths import configuration_refusal
from ._registry import common_schema
from ._registry_types import (
    ReferencePath,
    ReferenceRequirement,
    RegistryEntry,
    SchemaDependency,
    SchemaRegistry,
)
from ._statements import PROFILE_ID
from ._successor_configuration import decode_successor_trust
from ._trust_types import Purpose, SignerConfig, SigningRequest, TrustContext, VerificationPolicy
from ._values import BlobRef, DigestBasis, Limits, Utc


def decode_limits(document: AcquiredDocument) -> Limits:
    """Decode all six exact positive integer tokens before using configuration bounds.

    Parameters
    ----------
    document : AcquiredDocument
        Entire strictly acquired local configuration with its pre-conversion number tokens.
        Binary64 rounding never chooses the byte/count/depth bound.

    Returns
    -------
    Limits
        Six exact positive Python integers with no default or unlimited mode.

    Raises
    ------
    ConfigurationError
        A field is missing, unknown, noninteger, boolean, decimal-form or nonpositive.
    """
    names = (
        "max_json_bytes",
        "max_blob_bytes",
        "max_total_reference_bytes",
        "max_reference_count",
        "max_graph_depth",
        "max_json_depth",
    )
    fields = _object(document.value, set(names), pointer="/limits")
    bounds: list[int] = []
    for name in names:
        integer_lexeme = document.number_tokens.get("/" + name)
        if (
            not isinstance(fields[name], float)
            or integer_lexeme is None
            or DECIMAL_PATTERN.fullmatch(integer_lexeme) is None
            or integer_lexeme == "0"
        ):
            raise configuration_refusal("/limits/" + name)
        bounds.append(int(integer_lexeme))
    return Limits(*bounds)


def _object(
    value: JsonValue, required: set[str], *, pointer: str, optional: frozenset[str] = frozenset()
) -> dict[str, JsonValue]:
    """Require the exact closed local configuration object.

    Parameters
    ----------
    value : object
        Complete strict caller value.
    required : set of str
        Entire mandatory field population.
    pointer : str
        Actual local field position.
    optional : frozenset of str
        Only expressly admitted optional fields.

    Returns
    -------
    dict
        Original complete object, without projection.

    Raises
    ------
    ConfigurationError
        The shape omits a required field or adds an unknown field.
    """
    if (
        not isinstance(value, dict)
        or not required <= value.keys()
        or value.keys() - required - optional
    ):
        raise configuration_refusal(pointer)
    return value


def _string(value: JsonValue, *, pointer: str) -> str:
    """Require an actual local configuration string.

    Parameters
    ----------
    value : object
        Complete acquired field.
    pointer : str
        Actual local field position.

    Returns
    -------
    str
        Original string without coercion.

    Raises
    ------
    ConfigurationError
        The supplied value is not a string.
    """
    if not isinstance(value, str):
        raise configuration_refusal(pointer)
    return value


def _strings(value: JsonValue, *, pointer: str) -> tuple[str, ...]:
    """Require a whole ordered string array without coercion.

    Parameters
    ----------
    value : object
        Complete acquired population.
    pointer : str
        Actual local array position.

    Returns
    -------
    tuple of str
        All original entries in source order.

    Raises
    ------
    ConfigurationError
        The population or a member has an invalid type.
    """
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise configuration_refusal(pointer)
    return tuple(cast(list[str], value))


def _reference(value: JsonValue, *, pointer: str) -> BlobRef:
    """Map invalid local reference declarations to configuration refusal.

    Parameters
    ----------
    value : object
        Whole original declaration.
    pointer : str
        Actual local field position.

    Returns
    -------
    BlobRef
        Complete unchanged reference metadata.

    Raises
    ------
    ConfigurationError
        The original reference shape is invalid.
    """
    try:
        return decode_reference(value, subject=None, pointer=pointer)
    except InputRefused as error:
        raise configuration_refusal(pointer) from error


def _bytes(value: JsonValue, *, pointer: str) -> bytes:
    """Decode only canonical local Base64URL bytes.

    Parameters
    ----------
    value : object
        Entire supplied encoding.
    pointer : str
        Actual local field position.

    Returns
    -------
    bytes
        Exact decoded source bytes.

    Raises
    ------
    ConfigurationError
        The type or canonical encoding is invalid.
    """
    try:
        return decode_bytes(_string(value, pointer=pointer))
    except ValueError as error:
        raise configuration_refusal(pointer) from error


def decode_registry(value: JsonValue, *, limits: Limits) -> SchemaRegistry:
    """Decode the entire original selected registry, including every closed entry.

    Parameters
    ----------
    value : object
        Strictly acquired external snapshot_ref/entries configuration; no own digest is added.
    limits : Limits
        Whole operation limits for the fixed common registry schema.

    Returns
    -------
    SchemaRegistry
        Complete immutable typed registry; identity/dependencies/profiles are checked later
        under one shared budget before artifact interpretation or authentication.

    Raises
    ------
    ConfigurationError
        A closed registry, entry, path, dependency, byte encoding or reference is invalid.
    """
    root = _object(value, {"snapshot_ref", "entries"}, pointer="/registry")
    if not isinstance(root["entries"], list):
        raise configuration_refusal("/registry/entries")
    fixed = common_schema("registry_snapshot", limits=limits)
    if isinstance(fixed, bool):
        raise configuration_refusal("/registry/entries")
    validator = Draft202012Validator(fixed).evolve(
        schema=cast(Schema, fixed["properties"]["entries"]["items"])
    )
    entries: list[RegistryEntry] = []
    for index, value in enumerate(root["entries"]):
        pointer = "/registry/entries/" + str(index)
        if not isinstance(value, dict) or not validator.is_valid(value):
            raise configuration_refusal(pointer)
        paths = tuple(
            ReferencePath(
                path_id=cast(str, path["path_id"]),
                steps=tuple(cast(list[dict[str, str]], path["steps"])),
                absent=cast(Literal["schema_optional", "refuse"], path["absent"]),
                null=cast(Literal["schema_optional", "refuse"], path["null"]),
                requirement=cast(Literal["when_present", "policy_optional"], path["requirement"]),
            )
            for path in cast(list[dict[str, JsonValue]], value["reference_paths"])
        )
        dependencies = tuple(
            SchemaDependency(
                uri=cast(str, dependency["uri"]),
                schema_ref=_reference(
                    dependency["schema_ref"], pointer=pointer + "/schema_dependencies"
                ),
            )
            for dependency in cast(list[dict[str, JsonValue]], value["schema_dependencies"])
        )
        entries.append(
            RegistryEntry(
                schema_id=cast(str, value["schema_id"]),
                owner=cast(str, value["owner"]),
                schema_ref=_reference(value["schema_ref"], pointer=pointer + "/schema_ref"),
                schema_bytes=_bytes(value["schema_bytes"], pointer=pointer + "/schema_bytes"),
                media_type=cast(str, value["media_type"]),
                digest_basis=cast(DigestBasis, value["digest_basis"]),
                reference_paths=paths,
                common_semantics_id=cast(str, value["common_semantics_id"]),
                schema_role=cast(
                    Literal[
                        "common_control",
                        "common_evidence",
                        "domain_evidence",
                        "domain_verification",
                        "domain_support",
                    ],
                    value["schema_role"],
                ),
                closure_profile_id=cast(str, value["closure_profile_id"]),
                schema_dependencies=dependencies,
                domain_support=cast(
                    Literal["not_required", "required_unqualified", "required_qualified"],
                    value["domain_support"],
                ),
                domain_verifier_ref=(
                    None
                    if value["domain_verifier_ref"] is None
                    else _reference(
                        value["domain_verifier_ref"], pointer=pointer + "/domain_verifier_ref"
                    )
                ),
                domain_qualification_ref=(
                    None
                    if value["domain_qualification_ref"] is None
                    else _reference(
                        value["domain_qualification_ref"],
                        pointer=pointer + "/domain_qualification_ref",
                    )
                ),
            )
        )
    return SchemaRegistry(
        _reference(root["snapshot_ref"], pointer="/registry/snapshot_ref"), tuple(entries)
    )


def decode_trust(value: JsonValue) -> CallerTrust:
    """Decode the whole explicit legacy or V2 caller selection and ordered control bytes.

    Parameters
    ----------
    value : object
        Complete independently selected legacy or one of the three exact V2 configurations.

    Returns
    -------
    TrustContext or successor context
        Whole immutable independent selection. No snapshot, floor or host time is installed.

    Raises
    ------
    ConfigurationError
        A closed field, reference, mode, array or canonical byte encoding is invalid.
    """
    if isinstance(value, dict) and "namespace" in value:
        return decode_successor_trust(value)
    fields = _object(
        value,
        {
            "bootstrap_policy_ref",
            "current_snapshot_ref",
            "accepted_sequence_floor",
            "evaluation_mode",
            "evaluation_time",
            "control_envelopes",
        },
        pointer="/trust",
        optional=frozenset({"archived_snapshot_ref"}),
    )
    mode = fields["evaluation_mode"]
    if mode not in ("current", "historical"):
        raise configuration_refusal("/trust/evaluation_mode")
    envelopes = fields["control_envelopes"]
    if not isinstance(envelopes, list):
        raise configuration_refusal("/trust/control_envelopes")
    archived = fields.get("archived_snapshot_ref")
    try:
        evaluation_time = Utc(_string(fields["evaluation_time"], pointer="/trust/evaluation_time"))
    except InputRefused:
        raise configuration_refusal("/trust/evaluation_time") from None
    return TrustContext(
        _reference(fields["bootstrap_policy_ref"], pointer="/trust/bootstrap_policy_ref"),
        _reference(fields["current_snapshot_ref"], pointer="/trust/current_snapshot_ref"),
        _string(fields["accepted_sequence_floor"], pointer="/trust/accepted_sequence_floor"),
        cast(Literal["current", "historical"], mode),
        evaluation_time,
        tuple(
            _bytes(envelope, pointer="/trust/control_envelopes/" + str(index))
            for index, envelope in enumerate(envelopes)
        ),
        None if archived is None else _reference(archived, pointer="/trust/archived_snapshot_ref"),
    )


def decode_policy(value: JsonValue) -> VerificationPolicy:
    """Decode exact policy scope and only previously declared reference selectors.

    Parameters
    ----------
    value : object
        Strictly acquired original VerificationPolicy configuration.

    Returns
    -------
    VerificationPolicy
        Entire independently selected policy; its bytes/qualification are not authenticated here.

    Raises
    ------
    ConfigurationError
        A closed policy field, reference or required instance population is invalid.
    """
    fields = _object(
        value,
        {"policy_ref", "required_claim_ids", "required_purposes"},
        pointer="/policy",
        optional=frozenset({"required_reference_paths"}),
    )
    paths = fields.get("required_reference_paths", [])
    if not isinstance(paths, list):
        raise configuration_refusal("/policy/required_reference_paths")
    requirements: list[ReferenceRequirement] = []
    for index, value in enumerate(paths):
        pointer = "/policy/required_reference_paths/" + str(index)
        path = _object(
            value, {"subject_digest", "schema_id", "path_id", "instances"}, pointer=pointer
        )
        instances = path["instances"]
        requirements.append(
            ReferenceRequirement(
                _string(path["subject_digest"], pointer=pointer + "/subject_digest"),
                _string(path["schema_id"], pointer=pointer + "/schema_id"),
                _string(path["path_id"], pointer=pointer + "/path_id"),
                None if instances is None else _strings(instances, pointer=pointer + "/instances"),
            )
        )
    return VerificationPolicy(
        _reference(fields["policy_ref"], pointer="/policy/policy_ref"),
        _strings(fields["required_claim_ids"], pointer="/policy/required_claim_ids"),
        cast(
            tuple[Purpose, ...],
            _strings(fields["required_purposes"], pointer="/policy/required_purposes"),
        ),
        tuple(requirements),
    )


def decode_signing_request(value: JsonValue) -> SigningRequest:
    """Decode only the original statement_fields wrapper, without computed identities.

    Parameters
    ----------
    value : object
        Strictly acquired original signing configuration.

    Returns
    -------
    SigningRequest
        Entire immutable caller fields for subsequent complete native shape validation.

    Raises
    ------
    ConfigurationError
        The wrapper is not closed or its statement_fields are not an object.
    """
    fields = _object(value, {"statement_fields"}, pointer="/signing")
    statement = fields["statement_fields"]
    if not isinstance(statement, dict):
        raise configuration_refusal("/signing/statement_fields")
    return SigningRequest({key: freeze_json(child) for key, child in statement.items()})


def decode_signer_config(value: JsonValue) -> SignerConfig:
    """Decode the four original local adapter fields without receiving secret/code paths.

    Parameters
    ----------
    value : object
        Strictly acquired original SignerConfig configuration.

    Returns
    -------
    SignerConfig
        Exact local adapter reference and public identity; no adapter is enrolled or invoked.

    Raises
    ------
    ConfigurationError
        A closed field or canonical public byte encoding is invalid.
    """
    fields = _object(
        value, {"adapter_ref", "signer_key_id", "public_key", "profile_id"}, pointer="/signer"
    )
    configuration = SignerConfig(
        _string(fields["adapter_ref"], pointer="/signer/adapter_ref"),
        _string(fields["signer_key_id"], pointer="/signer/signer_key_id"),
        _bytes(fields["public_key"], pointer="/signer/public_key"),
        _string(fields["profile_id"], pointer="/signer/profile_id"),
    )
    if not configuration.adapter_ref:
        raise configuration_refusal("/signer/adapter_ref")
    if re.fullmatch(r"ed25519:[0-9a-f]{64}", configuration.signer_key_id) is None:
        raise configuration_refusal("/signer/signer_key_id")
    if len(configuration.public_key) != 32:
        raise configuration_refusal("/signer/public_key")
    if configuration.profile_id != PROFILE_ID:
        raise configuration_refusal("/signer/profile_id")
    return configuration
