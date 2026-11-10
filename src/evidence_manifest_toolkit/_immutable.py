# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — immutable JSON declarations

"""Detach result declarations from mutable parser and caller populations."""

from collections.abc import Mapping
from types import MappingProxyType

from ._json import JsonValue

type FrozenJson = None | bool | float | str | tuple[FrozenJson, ...] | Mapping[str, FrozenJson]


def freeze_json(value: JsonValue) -> FrozenJson:
    """Detach complete JSON arrays and objects into immutable containers.

    Parameters
    ----------
    value : object
        Whole strict common JSON tree.

    Returns
    -------
    object
        Immutable tuples/mappings preserving every original value and order.
    """
    if isinstance(value, dict):
        return MappingProxyType({key: freeze_json(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(freeze_json(child) for child in value)
    return value


def copy_frozen(value: FrozenJson) -> FrozenJson:
    """Detach valid immutable caller mappings at every depth.

    Parameters
    ----------
    value : object
        Whole typed immutable caller tree.

    Returns
    -------
    object
        Independent immutable containers without reordering or rewriting scalars.
    """
    if isinstance(value, Mapping):
        return MappingProxyType({key: copy_frozen(child) for key, child in value.items()})
    if isinstance(value, tuple):
        return tuple(copy_frozen(child) for child in value)
    return value


def thaw_json(value: FrozenJson) -> JsonValue:
    """Detach immutable caller values into complete native JSON containers.

    Parameters
    ----------
    value : object
        Entire valid immutable mapping/tuple/scalar tree, with exact original strings.

    Returns
    -------
    object
        Independent dictionaries/lists suitable for native schema and JCS validation.
        No input object or array is reordered or changed in place.
    """
    if isinstance(value, Mapping):
        return {key: thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(child) for child in value]
    return value
