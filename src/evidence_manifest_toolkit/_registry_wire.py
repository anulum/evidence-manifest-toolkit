# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact native registry entry serialization

"""Serialize the fourteen entry fields without inventing a registry revision or root."""

from ._codecs import encode_bytes, reference_value
from ._json import JsonValue
from ._registry_types import ReferencePath, RegistryEntry


def path_value(path: ReferencePath) -> dict[str, JsonValue]:
    """Serialize all original selector fields without interpreting literal names.

    Parameters
    ----------
    path : ReferencePath
        Whole independently chosen typed selector.

    Returns
    -------
    dict
        Exact five-field wire mapping and every original step.
    """
    steps: list[JsonValue] = [{key: value for key, value in step.items()} for step in path.steps]
    return {
        "path_id": path.path_id,
        "steps": steps,
        "absent": path.absent,
        "null": path.null,
        "requirement": path.requirement,
    }


def entry_value(entry: RegistryEntry) -> dict[str, JsonValue]:
    """Serialize one complete native entry without substituting payload/resource IDs.

    Parameters
    ----------
    entry : RegistryEntry
        Complete independently selected raw schema source and its traversal/role fields.

    Returns
    -------
    dict
        Exactly fourteen original wire fields, with canonical schema_bytes Base64URL.
    """
    dependencies: list[JsonValue] = [
        {"uri": dependency.uri, "schema_ref": reference_value(dependency.schema_ref)}
        for dependency in entry.schema_dependencies
    ]
    paths: list[JsonValue] = [path_value(path) for path in entry.reference_paths]
    return {
        "schema_id": entry.schema_id,
        "owner": entry.owner,
        "schema_ref": reference_value(entry.schema_ref),
        "schema_bytes": encode_bytes(entry.schema_bytes),
        "media_type": entry.media_type,
        "digest_basis": entry.digest_basis,
        "reference_paths": paths,
        "common_semantics_id": entry.common_semantics_id,
        "schema_role": entry.schema_role,
        "closure_profile_id": entry.closure_profile_id,
        "schema_dependencies": dependencies,
        "domain_support": entry.domain_support,
        "domain_verifier_ref": (
            None
            if entry.domain_verifier_ref is None
            else reference_value(entry.domain_verifier_ref)
        ),
        "domain_qualification_ref": (
            None
            if entry.domain_qualification_ref is None
            else reference_value(entry.domain_qualification_ref)
        ),
    }
