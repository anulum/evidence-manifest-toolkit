# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole immutable invocation configuration values

"""Serialize complete selected caller and registry values for whole-source equality."""

from ._codecs import encode_bytes, reference_value
from ._immutable import thaw_json
from ._json import JsonValue
from ._registry_types import SchemaRegistry
from ._registry_wire import entry_value
from ._successor_trust import (
    DelegatedTrustContextV2,
    SoftwareTrustContextV2,
    UnsignedTrustContextV2,
)
from ._trust_types import TrustContext

type SuccessorTrust = UnsignedTrustContextV2 | SoftwareTrustContextV2 | DelegatedTrustContextV2
type CallerTrust = TrustContext | SuccessorTrust


def successor_trust_value(trust: SuccessorTrust) -> dict[str, JsonValue]:
    """Retain every selected caller field without a projected subject or invented null.

    Parameters
    ----------
    trust : UnsignedTrustContextV2 or SoftwareTrustContextV2 or DelegatedTrustContextV2
        Entire already validated immutable caller selection. Source acquisition and
        semantic admission remain separate; this function loads no schema or provider.

    Returns
    -------
    dict
        Complete five/eight/twelve-field contract, with an absent conditional archive
        omitted as required by the current-mode wire. Nested binding values, lexical
        floors, full references and ordered original envelope bytes are retained.
    """
    result: dict[str, JsonValue] = {
        "namespace": trust.namespace,
        "profile_class": trust.profile_class,
        "evaluation_mode": trust.evaluation_mode,
        "evaluation_time": trust.evaluation_time,
        "clock_entry_binding": thaw_json(trust.clock_entry_binding),
    }
    if isinstance(trust, SoftwareTrustContextV2):
        result.update(
            software_authorization_ref=reference_value(trust.software_authorization_ref),
            accepted_authorization_sequence_floor=trust.accepted_authorization_sequence_floor,
        )
        if trust.archived_software_authorization_ref is not None:
            result["archived_software_authorization_ref"] = reference_value(
                trust.archived_software_authorization_ref
            )
    elif isinstance(trust, DelegatedTrustContextV2):
        result.update(
            independent_root_selection_ref=reference_value(trust.independent_root_selection_ref),
            root_grant_ref=reference_value(trust.root_grant_ref),
            current_authority_snapshot_ref=reference_value(trust.current_authority_snapshot_ref),
            accepted_authority_sequence_floor=trust.accepted_authority_sequence_floor,
            control_envelopes=[encode_bytes(raw) for raw in trust.control_envelopes],
            authority_control_selection_ref=reference_value(trust.authority_control_selection_ref),
        )
        if trust.archived_authority_snapshot_ref is not None:
            result["archived_authority_snapshot_ref"] = reference_value(
                trust.archived_authority_snapshot_ref
            )
    return result


def registry_value(registry: SchemaRegistry) -> dict[str, JsonValue]:
    """Retain the entire caller registry rather than substituting its snapshot digest.

    Parameters
    ----------
    registry : SchemaRegistry
        Actual independently validated complete caller catalogue and original entry order.

    Returns
    -------
    dict
        Both original configuration fields and all fourteen fields of every entry,
        including raw schema bytes, ordered selectors/dependencies and domain declarations.
        No native/private entry or inferred URI alias is inserted.
    """
    return {
        "snapshot_ref": reference_value(registry.snapshot_ref),
        "entries": [entry_value(entry) for entry in registry.entries],
    }
