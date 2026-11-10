# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — immutable explicit successor caller selections

"""Detach and validate whole successor caller values without authenticating their sources."""

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, cast

from ._codecs import DECIMAL_PATTERN, decode_reference
from ._errors import InputRefused
from ._immutable import FrozenJson, copy_frozen, thaw_json
from ._json import JsonValue
from ._reference_paths import configuration_refusal
from ._successor_formats import load_fixed_format
from ._values import BlobRef, Utc

_ENTRY_REFERENCES = (
    "first_sample_source_ref",
    "source_profile_ref",
    "boot_domain_ref",
    "verification_controller_identity_ref",
    "process_start_identity_ref",
    "entry_observation_method_ref",
    "implementation_environment_ref",
)


def _wire_reference(value: JsonValue, *, pointer: str) -> None:
    """Enforce the original complete reference grammar after structural validation.

    Parameters
    ----------
    value : object
        Whole original reference, with absent optional schema metadata still absent.
    pointer : str
        Exact caller reference argument position.

    Raises
    ------
    ConfigurationError
        A token, field or UTF-8 metadata value violates the original reference contract.
    """
    try:
        decode_reference(value, subject=None, pointer=pointer)
    except InputRefused as error:
        raise configuration_refusal(pointer) from error


def _validate(
    namespace: Literal[
        "EMT_CALLER_TRUST_UNSIGNED_V2",
        "EMT_CALLER_TRUST_SOFTWARE_V2",
        "EMT_CALLER_TRUST_DELEGATED_V2",
    ],
    value: dict[str, JsonValue],
) -> None:
    """Check one fixed caller definition with its entire pinned local resource.

    Parameters
    ----------
    namespace : str
        Fixed binding selected by the public value class, never by received artifact fields.
    value : dict
        Complete detached caller fields with original references and encoded receipt bytes.

    Raises
    ------
    ConfigurationError
        The fixed resource is unavailable or changed, or a complete field violates its schema.
    """
    load_fixed_format(namespace, pointer="/trust").validate_configuration(value, pointer="/trust")
    binding = cast(dict[str, JsonValue], value["clock_entry_binding"])
    try:
        cast(str, binding["request_id"]).encode("utf-8")
    except UnicodeError as error:
        raise configuration_refusal("/trust/clock_entry_binding/request_id") from error
    for name in _ENTRY_REFERENCES:
        _wire_reference(binding[name], pointer="/trust/clock_entry_binding/" + name)
    for name in ("accepted_authorization_sequence_floor", "accepted_authority_sequence_floor"):
        if name in value and DECIMAL_PATTERN.fullmatch(cast(str, value[name])) is None:
            raise configuration_refusal("/trust/" + name)


def _binding(value: Mapping[str, FrozenJson]) -> Mapping[str, FrozenJson]:
    """Detach the full binding before validation or later caller mutation.

    Parameters
    ----------
    value : Mapping
        Entire independently selected nine-field binding and complete nested references.

    Returns
    -------
    Mapping
        Detached immutable values in original order, without source interpretation.

    Raises
    ------
    ConfigurationError
        A cyclic or excessively recursive caller tree cannot be detached.
    """
    try:
        return cast(Mapping[str, FrozenJson], copy_frozen(value))
    except RecursionError as error:
        raise configuration_refusal("/trust/clock_entry_binding") from error


def _reference(value: object, *, pointer: str) -> dict[str, JsonValue]:
    """Preserve a complete public reference without converting an absent or wrong type.

    Parameters
    ----------
    value : object
        Exact public reference selected by the caller.
    pointer : str
        Its literal local configuration position.

    Returns
    -------
    dict
        All original reference fields, omitting only its absent optional schema identifier.

    Raises
    ------
    ConfigurationError
        The supplied value is not a BlobRef.
    """
    if not isinstance(value, BlobRef):
        raise configuration_refusal(pointer)
    try:
        wire: dict[str, JsonValue] = dict(value.to_mapping())
    except InputRefused as error:
        raise configuration_refusal(pointer) from error
    return wire


def _envelopes(value: object) -> list[JsonValue]:
    """Encode the caller's ordered immutable receipt bytes without parsing or discovery.

    Parameters
    ----------
    value : object
        Exact tuple of independently supplied detached envelope bytes.

    Returns
    -------
    list of str
        Canonical unpadded Base64URL values in original order.

    Raises
    ------
    ConfigurationError
        The population is mutable or a member is not bytes.
    """
    if not isinstance(value, tuple) or any(not isinstance(item, bytes) for item in value):
        raise configuration_refusal("/trust/control_envelopes")
    return [
        base64.urlsafe_b64encode(item).rstrip(b"=").decode("ascii")
        for item in cast(tuple[bytes, ...], value)
    ]


@dataclass(frozen=True, slots=True)
class UnsignedTrustContextV2:
    """Select the explicit unsigned caller class and its frozen Clock entry binding.

    Attributes
    ----------
    namespace : str
        Exact EMT_CALLER_TRUST_UNSIGNED_V2 carrier identifier.
    profile_class : str
        Exact unsigned_declared class, with no protected or software authority fields.
    evaluation_mode : {"current", "historical"}
        Original requested evaluation scope; historical supplies no protected archive.
    evaluation_time : str
        Original valid UTC token; construction does not qualify it as actual time.
    clock_entry_binding : Mapping
        Complete immutable nine-field selection, frozen before the whole Clock subject.
        Its references are declarations; construction neither reads nor accepts their sources.
    """

    namespace: str
    profile_class: str
    evaluation_mode: Literal["current", "historical"]
    evaluation_time: Utc
    clock_entry_binding: Mapping[str, FrozenJson]

    def __post_init__(self) -> None:
        """Freeze the complete caller binding and validate the closed unsigned carrier."""
        object.__setattr__(self, "clock_entry_binding", _binding(self.clock_entry_binding))
        _validate(
            "EMT_CALLER_TRUST_UNSIGNED_V2",
            {
                "namespace": self.namespace,
                "profile_class": self.profile_class,
                "evaluation_mode": self.evaluation_mode,
                "evaluation_time": self.evaluation_time,
                "clock_entry_binding": thaw_json(self.clock_entry_binding),
            },
        )


@dataclass(frozen=True, slots=True)
class SoftwareTrustContextV2:
    """Select complete software-local authority without claiming protected delegation.

    Attributes
    ----------
    namespace : str
        Exact EMT_CALLER_TRUST_SOFTWARE_V2 carrier identifier.
    profile_class : str
        Exact software_local_unprotected class.
    evaluation_mode : {"current", "historical"}
        Independent requested current or archived software state.
    evaluation_time : str
        Original valid UTC token; no host time or qualified Clock is supplied by this value.
    clock_entry_binding : Mapping
        Detached complete nine-field binding with every original source reference.
    software_authorization_ref : BlobRef
        Whole independently selected software authorization table, not a root grant.
    accepted_authorization_sequence_floor : str
        Exact nonnegative canonical decimal floor; construction never advances it.
    archived_software_authorization_ref : BlobRef or None
        Required in historical mode and absent in current wire input.
        None represents that optional field's absence in this new value type only.
    """

    namespace: str
    profile_class: str
    evaluation_mode: Literal["current", "historical"]
    evaluation_time: Utc
    clock_entry_binding: Mapping[str, FrozenJson]
    software_authorization_ref: BlobRef
    accepted_authorization_sequence_floor: str
    archived_software_authorization_ref: BlobRef | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        """Detach the binding and enforce complete current-versus-archive source grammar."""
        object.__setattr__(self, "clock_entry_binding", _binding(self.clock_entry_binding))
        value: dict[str, JsonValue] = {
            "namespace": self.namespace,
            "profile_class": self.profile_class,
            "evaluation_mode": self.evaluation_mode,
            "evaluation_time": self.evaluation_time,
            "clock_entry_binding": thaw_json(self.clock_entry_binding),
            "software_authorization_ref": _reference(
                self.software_authorization_ref, pointer="/trust/software_authorization_ref"
            ),
            "accepted_authorization_sequence_floor": self.accepted_authorization_sequence_floor,
        }
        if self.archived_software_authorization_ref is not None:
            value["archived_software_authorization_ref"] = _reference(
                self.archived_software_authorization_ref,
                pointer="/trust/archived_software_authorization_ref",
            )
        _validate("EMT_CALLER_TRUST_SOFTWARE_V2", value)


@dataclass(frozen=True, slots=True)
class DelegatedTrustContextV2:
    """Select the complete protected caller state without provisioning or accepting it.

    Attributes
    ----------
    namespace : str
        Exact EMT_CALLER_TRUST_DELEGATED_V2 carrier identifier.
    profile_class : str
        Exact protected_delegated class, without an unsigned or software fallback.
    evaluation_mode : {"current", "historical"}
        Original independent current/archive evaluation scope.
    evaluation_time : str
        Complete valid UTC token; actual Clock qualification remains separate.
    clock_entry_binding : Mapping
        Entire detached nine-field caller selection frozen before the Clock subject.
    independent_root_selection_ref, root_grant_ref : BlobRef
        Full earlier independent root choice and actual owner grant declarations.
    current_authority_snapshot_ref : BlobRef
        Complete independently selected current state; it is never installed by construction.
    accepted_authority_sequence_floor : str
        Exact pinned nonnegative decimal floor, retained without narrowing or advancement.
    control_envelopes : tuple of bytes
        Complete explicitly supplied detached envelopes in their original order.
    archived_authority_snapshot_ref : BlobRef or None
        Required only in historical mode; None means absent in this new type's wire input.
    authority_control_selection_ref : BlobRef
        Whole earlier protected control rule/expected-population selection.
    """

    namespace: str
    profile_class: str
    evaluation_mode: Literal["current", "historical"]
    evaluation_time: Utc
    clock_entry_binding: Mapping[str, FrozenJson]
    independent_root_selection_ref: BlobRef
    root_grant_ref: BlobRef
    current_authority_snapshot_ref: BlobRef
    accepted_authority_sequence_floor: str
    control_envelopes: tuple[bytes, ...]
    archived_authority_snapshot_ref: BlobRef | None = field(default=None, kw_only=True)
    authority_control_selection_ref: BlobRef

    def __post_init__(self) -> None:
        """Freeze and validate every protected selection field without acquiring authority."""
        object.__setattr__(self, "clock_entry_binding", _binding(self.clock_entry_binding))
        value: dict[str, JsonValue] = {
            "namespace": self.namespace,
            "profile_class": self.profile_class,
            "evaluation_mode": self.evaluation_mode,
            "evaluation_time": self.evaluation_time,
            "clock_entry_binding": thaw_json(self.clock_entry_binding),
            "independent_root_selection_ref": _reference(
                self.independent_root_selection_ref, pointer="/trust/independent_root_selection_ref"
            ),
            "root_grant_ref": _reference(self.root_grant_ref, pointer="/trust/root_grant_ref"),
            "current_authority_snapshot_ref": _reference(
                self.current_authority_snapshot_ref,
                pointer="/trust/current_authority_snapshot_ref",
            ),
            "accepted_authority_sequence_floor": self.accepted_authority_sequence_floor,
            "control_envelopes": _envelopes(self.control_envelopes),
            "authority_control_selection_ref": _reference(
                self.authority_control_selection_ref,
                pointer="/trust/authority_control_selection_ref",
            ),
        }
        if self.archived_authority_snapshot_ref is not None:
            value["archived_authority_snapshot_ref"] = _reference(
                self.archived_authority_snapshot_ref,
                pointer="/trust/archived_authority_snapshot_ref",
            )
        _validate("EMT_CALLER_TRUST_DELEGATED_V2", value)
