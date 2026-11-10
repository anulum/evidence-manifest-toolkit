# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete independently selected registry validation

"""Check closed entries, raw schema identity and protected semantics before artifact use."""

import hashlib
from collections.abc import Mapping
from importlib.resources import files
from types import MappingProxyType
from typing import cast

import rfc8785
from jsonschema import Draft202012Validator
from referencing.jsonschema import Schema

from ._acquisition import acquire_reference, identity_reason
from ._budget import ReferenceBudget
from ._codecs import decode_reference, reference_value
from ._declarations import DECLARED_PATHS
from ._errors import InputRefused
from ._interfaces import Resolver
from ._json import validate_limits
from ._qpu_registry import validate_qpu_registry
from ._reference_paths import configuration_refusal, validate_path
from ._registry_types import SchemaRegistry
from ._registry_wire import entry_value
from ._schema_dependencies import schema_dependency_closure
from ._schema_paths import validate_schema_path
from ._schema_resources import StaticSchema, bind_resources, parse_schema
from ._values import Limits

_PREFIX = "evidence_manifest_toolkit."
_SUFFIX = ".v1"
_SEMANTICS = frozenset(
    _PREFIX + name + _SUFFIX
    for name in (
        "common_json",
        "manifest_common",
        "claim_inventory_common",
        "signed_statement_common",
        "group_certificate_common",
        "trust_snapshot_common",
        "target_descriptor_common",
        "adapter_conformance_common",
        "studio_mapping_common",
    )
)
_CONTROL_NAMES = {"group_certificate", "trust_snapshot", "registry_snapshot"}


def common_schema(name: str, *, limits: Limits) -> Schema:
    """Read a fixed packaged common source without selecting a schema from evidence.

    Parameters
    ----------
    name : str
        Independently known common schema name from the fixed eight-entry catalogue.
    limits : Limits
        Entire operation acquisition bounds.

    Returns
    -------
    Mapping or bool
        Complete previously reviewed raw source parsed under the fixed dialect.

    Raises
    ------
    ConfigurationError
        The selected name or packaged source is unavailable or invalid.
    """
    if _PREFIX + name + _SUFFIX not in DECLARED_PATHS:
        raise configuration_refusal("/registry/entries")
    try:
        data = files("evidence_manifest_toolkit").joinpath("_schemas", name + ".json").read_bytes()
    except OSError as error:
        raise configuration_refusal("/registry/entries") from error
    return parse_schema(data, limits=limits, pointer="/registry/entries")


def _constraints(schema: Schema) -> bytes:
    """Compare complete protected constraints while permitting only root metadata changes.

    Parameters
    ----------
    schema : Mapping or bool
        Whole independently acquired static schema.

    Returns
    -------
    bytes
        JCS of every constraint except root id/comment metadata.
    """
    if isinstance(schema, bool):
        return rfc8785.dumps(schema)
    return rfc8785.dumps(
        {key: value for key, value in schema.items() if key not in ("$id", "$comment")}
    )


def validate_registry(
    registry: SchemaRegistry, *, limits: Limits, budget: ReferenceBudget, resolver: Resolver
) -> Mapping[str, StaticSchema]:
    """Validate complete caller entries before reading artifacts or authenticating them.

    Parameters
    ----------
    registry : SchemaRegistry
        Independently chosen external snapshot reference and complete selected entries.
    limits : Limits
        Entire explicit positive operation bounds.
    budget : ReferenceBudget
        The sole cumulative acquisition budget, retained for later content traversal.
    resolver : Resolver
        Explicit local source for exact pinned dependency resources outside entry bodies.

    Returns
    -------
    Mapping
        Immutable schema-ID dispatch table with complete static dependency bindings.
        This validates configuration; it neither authenticates nor installs the registry.

    Raises
    ------
    ConfigurationError
        Closed entry shape, identity, selector, role or protected semantics are invalid.
    InputRefused
        The complete selected schema population exceeds shared acquisition bounds.
    """
    validate_limits(limits)
    try:
        decode_reference(
            reference_value(registry.snapshot_ref), subject=None, pointer="/registry/snapshot_ref"
        )
    except InputRefused as error:
        raise configuration_refusal("/registry/snapshot_ref") from error
    if not isinstance(registry.entries, tuple) or not registry.entries:
        raise configuration_refusal("/registry/entries")
    root = common_schema("registry_snapshot", limits=limits)
    if isinstance(root, bool):
        raise configuration_refusal("/registry/entries")
    entry_schema = cast(Schema, root["properties"]["entries"]["items"])
    validator = Draft202012Validator(root).evolve(schema=entry_schema)
    selected: dict[str, tuple[Schema, str]] = {}
    sources: dict[str, Schema] = {}
    for index, entry in enumerate(registry.entries):
        pointer = "/registry/entries/" + str(index)
        if not isinstance(entry.reference_paths, tuple) or not isinstance(
            entry.schema_dependencies, tuple
        ):
            raise configuration_refusal(pointer)
        wire = entry_value(entry)
        if not validator.is_valid(wire):
            raise configuration_refusal(pointer)
        if entry.schema_id in selected:
            raise configuration_refusal(pointer + "/schema_id")
        if entry.common_semantics_id not in _SEMANTICS:
            raise configuration_refusal(pointer + "/common_semantics_id")
        if entry.closure_profile_id != "evidence_manifest_toolkit.declared_refs.v1":
            raise configuration_refusal(pointer + "/closure_profile_id")
        reference = entry.schema_ref
        if (
            entry.digest_basis != "raw_bytes"
            or reference.digest_basis != "raw_bytes"
            or entry.media_type != reference.media_type
            or reference.media_type != "application/schema+json"
            or reference.digest != "sha256:" + hashlib.sha256(entry.schema_bytes).hexdigest()
            or reference.byte_length != str(len(entry.schema_bytes))
        ):
            raise configuration_refusal(pointer + "/schema_ref")
        budget.charge(
            reference,
            entry.schema_bytes,
            subject=registry.snapshot_ref.digest,
            pointer=pointer + "/schema_bytes",
        )
        schema = parse_schema(entry.schema_bytes, limits=limits, pointer=pointer + "/schema_bytes")
        if entry.schema_id in DECLARED_PATHS:
            name = entry.schema_id[len(_PREFIX) : -len(_SUFFIX)]
            expected_semantics = "common_json" if name == "registry_snapshot" else name + "_common"
            role = "common_control" if name in _CONTROL_NAMES else "common_evidence"
            if entry.owner != "EVIDENCE-MANIFEST-TOOLKIT" or entry.schema_role != role:
                raise configuration_refusal(pointer + "/owner")
            if entry.common_semantics_id != _PREFIX + expected_semantics + _SUFFIX:
                raise configuration_refusal(pointer + "/common_semantics_id")
            if _constraints(schema) != _constraints(common_schema(name, limits=limits)):
                raise configuration_refusal(pointer + "/schema_bytes")
            declared: set[tuple[str | None, ...]] = set()
            for path in entry.reference_paths:
                if any(step.get("kind") == "index" for step in path.steps):
                    continue
                declared.add(
                    tuple(
                        None if step.get("kind") == "each" else step.get("name")
                        for step in path.steps
                    )
                )
            if not set(DECLARED_PATHS[entry.schema_id]) <= declared:
                raise configuration_refusal(pointer + "/reference_paths")
            if any(path.requirement != "when_present" for path in entry.reference_paths):
                raise configuration_refusal(pointer + "/reference_paths")
        if entry.schema_id not in DECLARED_PATHS and entry.common_semantics_id not in (
            _PREFIX + "common_json" + _SUFFIX,
            _PREFIX + "claim_inventory_common" + _SUFFIX,
        ):
            raise configuration_refusal(pointer + "/common_semantics_id")
        if not isinstance(schema, bool):
            properties: object = schema.get("properties", {})
            if (
                isinstance(properties, dict)
                and "claims" in properties
                and entry.schema_id not in DECLARED_PATHS
            ):
                if entry.common_semantics_id != _PREFIX + "claim_inventory_common" + _SUFFIX:
                    raise configuration_refusal(pointer + "/common_semantics_id")
        identifiers: set[str] = set()
        for path_index, path in enumerate(entry.reference_paths):
            location = pointer + "/reference_paths/" + str(path_index)
            validate_path(path, pointer=location)
            if path.path_id in identifiers:
                raise configuration_refusal(location + "/path_id")
            identifiers.add(path.path_id)
        selected[entry.schema_id] = schema, pointer
        sources[reference.digest] = schema
    validate_qpu_registry(registry, budget=budget)
    for entry in registry.entries:
        schema, pointer = selected[entry.schema_id]
        for dependency_index, dependency in enumerate(entry.schema_dependencies):
            location = pointer + "/schema_dependencies/" + str(dependency_index)
            reference = dependency.schema_ref
            try:
                decode_reference(reference_value(reference), subject=None, pointer=location)
            except InputRefused as error:
                raise configuration_refusal(location + "/schema_ref") from error
            if (
                reference.digest_basis != "raw_bytes"
                or reference.media_type != "application/schema+json"
            ):
                raise configuration_refusal(location + "/schema_ref")
            if reference.digest not in sources:
                data = acquire_reference(
                    reference,
                    resolver=resolver,
                    budget=budget,
                    subject=registry.snapshot_ref.digest,
                    pointer=location + "/schema_ref",
                )
                failure = identity_reason(
                    reference,
                    data,
                    budget=budget,
                    subject=registry.snapshot_ref.digest,
                    pointer=location + "/schema_ref",
                )
                if failure is not None:
                    raise configuration_refusal(location + "/schema_ref")
                sources[reference.digest] = parse_schema(data, limits=limits, pointer=location)
            else:
                cached_data = budget.cached(
                    reference, subject=registry.snapshot_ref.digest, pointer=location
                )
                if cached_data is None:
                    raise configuration_refusal(location + "/schema_ref")
                if (
                    identity_reason(
                        reference,
                        cached_data,
                        budget=budget,
                        subject=registry.snapshot_ref.digest,
                        pointer=location,
                    )
                    is not None
                ):
                    raise configuration_refusal(location + "/schema_ref")
    result: dict[str, StaticSchema] = {}
    for entry in registry.entries:
        schema, pointer = selected[entry.schema_id]
        dependencies = schema_dependency_closure(
            entry, entries=registry.entries, budget=budget, pointer=pointer
        )
        static = bind_resources(
            entry, schema, sources=sources, pointer=pointer, dependencies=dependencies
        )
        for index, path in enumerate(entry.reference_paths):
            validate_schema_path(static, path, pointer=pointer + "/reference_paths/" + str(index))
        result[entry.schema_id] = static
    return MappingProxyType(result)
