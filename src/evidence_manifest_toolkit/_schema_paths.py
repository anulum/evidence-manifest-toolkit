# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — selector compatibility with pinned schema positions

"""Check typed selector positions within known schema branches before reading evidence."""

from typing import cast
from urllib.parse import urljoin

from referencing.exceptions import Unresolvable
from referencing.jsonschema import Schema

from ._reference_paths import configuration_refusal
from ._registry_types import ReferencePath
from ._schema_resources import StaticSchema


def _expanded(selected: list[tuple[Schema, str]], static: StaticSchema) -> list[tuple[Schema, str]]:
    """Expand known static schema branches and references without fetching resources.

    Parameters
    ----------
    selected : list of tuple
        Actual schema nodes and their resource bases.
    static : StaticSchema
        Independently bound complete offline resource population.

    Returns
    -------
    list of tuple
        Reachable schema nodes and actual bases, with recursion guarded.
    """
    result: list[tuple[Schema, str]] = []
    pending = list(selected)
    visited: set[tuple[int, str]] = set()
    while pending:
        node, base = pending.pop()
        key = id(node), base
        if key in visited or isinstance(node, bool):
            continue
        visited.add(key)
        identifier: object = node.get("$id")
        if isinstance(identifier, str):
            base = urljoin(base, identifier)
        result.append((node, base))
        for keyword in ("$ref", "$dynamicRef"):
            reference: object = node.get(keyword)
            if isinstance(reference, str):
                resolved = static.resources.resolver(base).lookup(reference)
                pending.append(
                    (
                        resolved.contents,
                        urljoin(base, reference.split("#", 1)[0])
                        if not reference.startswith("#")
                        else base,
                    )
                )
        for name in ("allOf", "anyOf", "oneOf"):
            branches: object = node.get(name)
            if isinstance(branches, list):
                pending.extend(
                    (cast(Schema, child), base)
                    for child in branches
                    if isinstance(child, (dict, bool))
                )
        for name in ("then", "else"):
            branch: object = node.get(name)
            if isinstance(branch, (dict, bool)):
                pending.append((cast(Schema, branch), base))
    return result


def validate_schema_path(static: StaticSchema, path: ReferencePath, *, pointer: str) -> None:
    """Require every member/index/each step to address a known schema position.

    Parameters
    ----------
    static : StaticSchema
        Entire independently supplied schema and checked static dependency resources.
    path : ReferencePath
        Complete already grammar-validated literal selector.
    pointer : str
        Actual caller configuration location of this selector.

    Raises
    ------
    ConfigurationError
        A step is incompatible with every known branch or does not end at a reference.
        Complete runtime branch validation remains required before selector expansion.
    """
    base = "" if isinstance(static.schema, bool) else static.schema.get("$id", "")
    selected: list[tuple[Schema, str]] = [(static.schema, str(base))]
    try:
        for step in path.steps:
            children: list[tuple[Schema, str]] = []
            for node, uri in _expanded(selected, static):
                if isinstance(node, bool):
                    continue
                if step["kind"] == "member":
                    properties: object = node.get("properties")
                    if isinstance(properties, dict):
                        child: object = properties.get(step["name"])
                        if isinstance(child, (dict, bool)):
                            children.append((cast(Schema, child), uri))
                else:
                    prefix: object = node.get("prefixItems", [])
                    items: object = node.get("items")
                    types: object = node.get("type")
                    if types != "array" and not (isinstance(types, list) and "array" in types):
                        continue
                    if step["kind"] == "each":
                        if isinstance(prefix, list):
                            children.extend(
                                (cast(Schema, child), uri)
                                for child in prefix
                                if isinstance(child, (dict, bool))
                            )
                        if isinstance(items, dict):
                            children.append((cast(Schema, items), uri))
                    else:
                        index = int(step["index"])
                        if isinstance(prefix, list) and index < len(prefix):
                            child = prefix[index]
                            if isinstance(child, (dict, bool)):
                                children.append((cast(Schema, child), uri))
                        elif isinstance(items, dict):
                            children.append((cast(Schema, items), uri))
            if not children:
                raise configuration_refusal(pointer + "/steps")
            selected = children
        for node, _ in _expanded(selected, static):
            if isinstance(node, bool):
                continue
            properties = node.get("properties")
            if (
                isinstance(properties, dict)
                and {"digest", "byte_length", "media_type", "digest_basis"} <= properties.keys()
            ):
                return
    except Unresolvable as error:
        raise configuration_refusal(pointer + "/steps") from error
    raise configuration_refusal(pointer + "/steps")
