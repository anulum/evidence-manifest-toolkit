# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — independently supplied static schema resources

"""Validate pinned Draft2020-12 resources using an offline, explicit dependency set."""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import cast
from urllib.parse import urljoin

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT202012, Schema

from ._difference import pointer_member, utf16_key
from ._errors import InputRefused
from ._json import JsonValue, parse_document
from ._reference_paths import configuration_refusal
from ._registry_types import ReferencePath, RegistryEntry, SchemaDependency
from ._utc import utc_key
from ._values import Digest, Limits, Reason

_DIALECT = "https://json-schema.org/draft/2020-12/schema"
_MAP_SUBSCHEMAS = ("$defs", "properties", "patternProperties", "dependentSchemas")
_ARRAY_SUBSCHEMAS = ("allOf", "anyOf", "oneOf", "prefixItems")
_SINGLE_SUBSCHEMAS = (
    "additionalProperties",
    "unevaluatedProperties",
    "propertyNames",
    "items",
    "unevaluatedItems",
    "contains",
    "not",
    "if",
    "then",
    "else",
)


def subschemas(schema: Schema) -> Iterator[Schema]:
    """Visit actual schema positions, excluding example and const payload dictionaries.

    Parameters
    ----------
    schema : Mapping or bool
        Whole static Draft2020-12 resource.

    Returns
    -------
    Iterator
        Actual child schema positions, without treating instance examples as schemas.
    """
    if isinstance(schema, bool):
        return
    for name in _MAP_SUBSCHEMAS:
        children: object = schema.get(name)
        if isinstance(children, dict):
            for child in children.values():
                if isinstance(child, (dict, bool)):
                    yield cast(Schema, child)
    for name in _ARRAY_SUBSCHEMAS:
        children = schema.get(name)
        if isinstance(children, list):
            for child in children:
                if isinstance(child, (dict, bool)):
                    yield cast(Schema, child)
    for name in _SINGLE_SUBSCHEMAS:
        child = schema.get(name)
        if isinstance(child, (dict, bool)):
            yield cast(Schema, child)


def parse_schema(data: bytes, *, limits: Limits, pointer: str) -> Schema:
    """Check strict source bytes, the fixed dialect and the complete metaschema.

    Parameters
    ----------
    data : bytes
        Independently selected raw resource bytes, already identity checked.
    limits : Limits
        Shared operation bounds, including complete schema document/depth limits.
    pointer : str
        Actual resource location in caller configuration.

    Returns
    -------
    Mapping or bool
        Complete parsed schema under the sole supported Draft2020-12 dialect.

    Raises
    ------
    ConfigurationError
        Parsing, metaschema validity or declared vocabulary/dialect is unsupported.
    """
    try:
        value = parse_document(data, limits=limits)
    except InputRefused as error:
        raise configuration_refusal(pointer) from error
    if not isinstance(value, (dict, bool)):
        raise configuration_refusal(pointer)
    schema = cast(Schema, value)
    pending = [schema]
    while pending:
        selected = pending.pop()
        if isinstance(selected, bool):
            continue
        if "$schema" in selected and selected["$schema"] != _DIALECT:
            raise configuration_refusal(pointer)
        vocabularies: object = selected.get("$vocabulary", {})
        if not isinstance(vocabularies, dict):
            raise configuration_refusal(pointer)
        for uri, required in vocabularies.items():
            if required and uri not in {
                "https://json-schema.org/draft/2020-12/vocab/" + name
                for name in (
                    "core",
                    "applicator",
                    "unevaluated",
                    "validation",
                    "meta-data",
                    "format-annotation",
                    "content",
                )
            }:
                raise configuration_refusal(pointer)
        pending.extend(subschemas(selected))
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as error:
        raise configuration_refusal(pointer) from error
    return schema


def utc_format_checker() -> FormatChecker:
    """Bind date-time annotations to the selected complete UTC history and grammar."""
    checker = FormatChecker()

    @checker.checks("date-time", raises=InputRefused)
    def admitted(value: object) -> bool:
        """Apply the selected UTC law to actual date-time strings.

        Parameters
        ----------
        value : object
            Complete instance supplied by the native format checker.

        Returns
        -------
        bool
            True after the applicable token check.

        Raises
        ------
        InputRefused
            The UTC token violates the selected historical/calendar law.
        """
        if isinstance(value, str):
            utc_key(value)
        return True

    return checker


@dataclass(frozen=True, slots=True)
class StaticSchema:
    """Keep one payload validator with only its independently pinned resources.

    Attributes
    ----------
    entry : RegistryEntry
        Exact caller-selected identity, owner, semantics and traversal declaration.
    schema : Mapping or bool
        Complete raw source interpretation; resource identity stays separate.
    resources : Registry
        Offline resources consisting of this source and exact declared dependencies.
    """

    entry: RegistryEntry
    schema: Schema
    resources: Registry[Schema]

    @property
    def reference_paths(self) -> tuple[ReferencePath, ...]:
        """Return every path from the original unchanged caller-selected entry.

        Returns
        -------
        tuple of ReferencePath
            Original complete selector population in caller order.
        """
        return self.entry.reference_paths

    def reasons(self, document: JsonValue, *, subject: Digest) -> tuple[Reason, ...]:
        """Validate the entire subject before traversal and retain located refusals.

        Parameters
        ----------
        document : object
            Complete strict parsed JSON subject, never a selected branch fragment.
        subject : str
            Actual containing content identity for every native field diagnostic.

        Returns
        -------
        tuple of Reason
            Every schema failure in literal pointer order; an empty tuple means
            structural validity only, without trust, domain or scientific acceptance.

        Raises
        ------
        ConfigurationError
            A previously supplied static resource cannot resolve its selected reference.
        """
        validator = Draft202012Validator(
            self.schema, registry=self.resources, format_checker=utc_format_checker()
        )
        try:
            errors: list[ValidationError] = list(validator.iter_errors(document))
        except Unresolvable as error:
            raise configuration_refusal("/registry/entries") from error
        reasons: list[Reason] = []
        for failure in errors:
            pointer = "".join("/" + pointer_member(str(token)) for token in failure.absolute_path)
            if isinstance(failure.cause, InputRefused):
                source = failure.cause.reason
                reasons.append(Reason(source.code, subject, None, pointer, source.detail))
            else:
                reasons.append(
                    Reason(
                        "invalid_schema",
                        subject,
                        None,
                        pointer,
                        "Input violates its selected schema.",
                    )
                )
        return tuple(sorted(reasons, key=lambda reason: utf16_key(reason.pointer or "")))


def bind_resources(
    entry: RegistryEntry,
    schema: Schema,
    *,
    sources: Mapping[str, Schema],
    pointer: str,
    dependencies: tuple[SchemaDependency, ...] | None = None,
) -> StaticSchema:
    """Bind and check every schema reference within the explicit local dependency set.

    Parameters
    ----------
    entry : RegistryEntry
        Known selected schema and its exact static dependency URI declarations.
    schema : Mapping or bool
        Entire already checked raw schema source.
    sources : Mapping
        Independently supplied schemas keyed by their raw digest identity.
    pointer : str
        Actual entry location in caller configuration.
    dependencies : tuple of SchemaDependency or None
        Whole explicitly reachable source pins, including declarations of reached
        selected schema entries. None retains the original direct-only configuration.

    Returns
    -------
    StaticSchema
        Complete offline validator with all fragments and external resources checked.

    Raises
    ------
    ConfigurationError
        A dependency, URI, resource identity or schema fragment is absent or ambiguous.
    """
    resources: Registry[Schema] = Registry()
    declared: set[str] = set()
    selected_dependencies = entry.schema_dependencies if dependencies is None else dependencies
    for index, dependency in enumerate(selected_dependencies):
        uri = dependency.uri
        if not uri or "#" in uri or uri in declared:
            raise configuration_refusal(pointer + "/schema_dependencies/" + str(index))
        declared.add(uri)
        source = sources.get(dependency.schema_ref.digest)
        if source is None:
            raise configuration_refusal(pointer + "/schema_dependencies/" + str(index))
        resource = Resource.from_contents(source, default_specification=DRAFT202012)
        if resource.id() is not None and resource.id() != uri:
            raise configuration_refusal(pointer + "/schema_dependencies/" + str(index))
        resources = resources.with_resource(uri, resource)
    own = Resource.from_contents(schema, default_specification=DRAFT202012)
    own_uri = own.id() or ""
    if own_uri in declared:
        raise configuration_refusal(pointer + "/schema_dependencies")
    resources = resources.with_resource(own_uri, own)
    pending: list[tuple[Schema, str]] = [(schema, own_uri)]
    pending.extend(
        (sources[dependency.schema_ref.digest], dependency.uri)
        for dependency in selected_dependencies
    )
    while pending:
        node, base = pending.pop()
        if isinstance(node, bool):
            continue
        node_id: object = node.get("$id")
        if isinstance(node_id, str):
            base = urljoin(base, node_id)
        for keyword in ("$ref", "$dynamicRef"):
            reference: object = node.get(keyword)
            if not isinstance(reference, str):
                continue
            uri = reference.split("#", 1)[0]
            resolved = urljoin(base, uri) if uri else base.split("#", 1)[0]
            if uri and resolved not in declared and resolved != own_uri:
                raise configuration_refusal(pointer + "/schema_dependencies")
            try:
                resources.resolver(base).lookup(reference)
            except Unresolvable as error:
                raise configuration_refusal(pointer + "/schema_dependencies") from error
        pending.extend((child, base) for child in subschemas(node))
    return StaticSchema(entry, schema, resources)
