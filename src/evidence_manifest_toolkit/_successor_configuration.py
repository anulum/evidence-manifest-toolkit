# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete successor caller configuration decoding

"""Decode the three explicit caller selections without choosing authority from an artifact."""

from collections.abc import Mapping
from typing import Literal, cast

from ._codecs import decode_bytes, decode_reference
from ._errors import InputRefused
from ._immutable import FrozenJson, freeze_json
from ._invocation_wire import SuccessorTrust
from ._json import JsonValue
from ._reference_paths import configuration_refusal
from ._successor_formats import load_fixed_format
from ._successor_trust import (
    DelegatedTrustContextV2,
    SoftwareTrustContextV2,
    UnsignedTrustContextV2,
)
from ._values import BlobRef, Utc

_NAMESPACES = frozenset(
    {
        "EMT_CALLER_TRUST_UNSIGNED_V2",
        "EMT_CALLER_TRUST_SOFTWARE_V2",
        "EMT_CALLER_TRUST_DELEGATED_V2",
    }
)


def _reference(value: JsonValue, *, name: str) -> BlobRef:
    """Retain whole reference metadata and the actual caller field in typed refusals."""
    pointer = "/trust/" + name
    try:
        return decode_reference(value, subject=None, pointer=pointer)
    except InputRefused as error:
        raise configuration_refusal(pointer) from error


def decode_successor_trust(value: dict[str, JsonValue]) -> SuccessorTrust:
    """Decode every field of the explicitly selected closed V2 caller configuration.

    Parameters
    ----------
    value : dict
        Complete independently supplied caller configuration. Its exact namespace chooses
        one of three fixed constructor contracts, never received executable code or a key.
        Fields, ordered control bytes, full references and UTC/floor lexemes are retained.

    Returns
    -------
    UnsignedTrustContextV2 or SoftwareTrustContextV2 or DelegatedTrustContextV2
        Entire immutable selected caller. Decoding neither acquires authority nor qualifies
        Clock, custody, current state, a signer or the availability of the selected method.

    Raises
    ------
    ConfigurationError
        Namespace, complete fixed source grammar, UTC token, reference or canonical byte
        encoding is invalid. Current-mode forbidden archives are not silently discarded.
    """
    namespace = value.get("namespace")
    if not isinstance(namespace, str) or namespace not in _NAMESPACES:
        raise configuration_refusal("/trust/namespace")
    load_fixed_format(namespace, pointer="/trust").validate_configuration(value, pointer="/trust")
    try:
        evaluation_time = Utc(cast(str, value["evaluation_time"]))
    except InputRefused as error:
        raise configuration_refusal("/trust/evaluation_time") from error
    mode = cast(Literal["current", "historical"], value["evaluation_mode"])
    profile_class = cast(str, value["profile_class"])
    binding = cast(Mapping[str, FrozenJson], freeze_json(value["clock_entry_binding"]))
    if namespace == "EMT_CALLER_TRUST_UNSIGNED_V2":
        return UnsignedTrustContextV2(namespace, profile_class, mode, evaluation_time, binding)
    if namespace == "EMT_CALLER_TRUST_SOFTWARE_V2":
        return SoftwareTrustContextV2(
            namespace,
            profile_class,
            mode,
            evaluation_time,
            binding,
            _reference(value["software_authorization_ref"], name="software_authorization_ref"),
            cast(str, value["accepted_authorization_sequence_floor"]),
            archived_software_authorization_ref=(
                _reference(
                    value["archived_software_authorization_ref"],
                    name="archived_software_authorization_ref",
                )
                if "archived_software_authorization_ref" in value
                else None
            ),
        )
    envelopes: list[bytes] = []
    for index, raw in enumerate(cast(list[str], value["control_envelopes"])):
        try:
            envelopes.append(decode_bytes(raw))
        except ValueError as error:
            raise configuration_refusal("/trust/control_envelopes/" + str(index)) from error
    return DelegatedTrustContextV2(
        namespace,
        profile_class,
        mode,
        evaluation_time,
        binding,
        _reference(value["independent_root_selection_ref"], name="independent_root_selection_ref"),
        _reference(value["root_grant_ref"], name="root_grant_ref"),
        _reference(value["current_authority_snapshot_ref"], name="current_authority_snapshot_ref"),
        cast(str, value["accepted_authority_sequence_floor"]),
        tuple(envelopes),
        archived_authority_snapshot_ref=(
            _reference(
                value["archived_authority_snapshot_ref"], name="archived_authority_snapshot_ref"
            )
            if "archived_authority_snapshot_ref" in value
            else None
        ),
        authority_control_selection_ref=_reference(
            value["authority_control_selection_ref"], name="authority_control_selection_ref"
        ),
    )
