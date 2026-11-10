# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — fixed whole successor source validation

"""Validate installed successor formats without registering them in a caller's catalogue."""

import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files
from typing import cast

from jsonschema import Draft202012Validator
from jsonschema.protocols import Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012, Schema

from ._budget import ReferenceBudget
from ._difference import pointer_member, utf16_key
from ._errors import InputRefused
from ._json import JsonValue
from ._reference_paths import configuration_refusal
from ._registry_types import ReferencePath
from ._schema_resources import parse_schema, utc_format_checker
from ._successor_format_bindings import FORMAT_BINDINGS, NATIVE_FORMAT_IDS, RESOURCES
from ._values import BlobRef, Digest, Reason


@dataclass(frozen=True, slots=True)
class FixedFormat:
    """Retain one selected definition and its complete installed schema resource.

    Attributes
    ----------
    source_schema : Mapping or bool
        Entire hash-pinned source, including every local definition.
    definition : Mapping or bool
        Exact independently selected definition within that source.
    reference_paths : tuple of ReferencePath
        All declared selectors in their selected source order. These are internal
        format bindings, without a fabricated caller RegistryEntry or owner role.
    schema_id : str or None
        Exact selected native public ID, or absent for private formats and caller
        namespaces. A private format token never becomes reference schema metadata.
    name : str
        Exact installed binding selected by the owning method, without inferred aliases.
    """

    source_schema: Schema
    definition: Schema
    reference_paths: tuple[ReferencePath, ...]
    schema_id: str | None
    name: str

    def _validator(self) -> Validator:
        """Bind the complete resource offline before selecting its exact definition.

        Returns
        -------
        Validator
            Validator retaining the whole root for all local definition resolution.
        """
        resources: Registry[Schema] = Registry().with_resource(
            "", Resource.from_contents(self.source_schema, default_specification=DRAFT202012)
        )
        return Draft202012Validator(
            self.source_schema, registry=resources, format_checker=utc_format_checker()
        ).evolve(schema=self.definition)

    def validate_configuration(self, value: JsonValue, *, pointer: str) -> None:
        """Refuse the first complete caller-format violation at its literal position.

        Parameters
        ----------
        value : object
            Whole detached independently supplied local configuration.
        pointer : str
            Actual local configuration position; no source filename enters diagnostics.

        Raises
        ------
        ConfigurationError
            A complete field violates the selected closed source format.
        """
        failure = next(self._validator().iter_errors(value), None)
        if failure is not None:
            location = pointer + "".join(
                "/" + pointer_member(str(token)) for token in failure.absolute_path
            )
            raise configuration_refusal(location)

    def reasons(self, document: JsonValue, *, subject: Digest) -> tuple[Reason, ...]:
        """Check full source structure without asserting any semantic acceptance.

        Parameters
        ----------
        document : object
            Complete strict parsed subject, never a branch projection.
        subject : str
            Actual containing identity for every field refusal.

        Returns
        -------
        tuple of Reason
            All located schema and UTC refusals in original literal pointer order.
            Empty means structural validity only, not authority or Clock qualification.
        """
        reasons: list[Reason] = []
        for failure in self._validator().iter_errors(document):
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


def load_fixed_format(
    name: str, *, pointer: str, budget: ReferenceBudget | None = None
) -> FixedFormat:
    """Load a fixed installed source with all dependencies and exact reference selectors.

    Parameters
    ----------
    name : str
        Exact independently selected native ID, private format or caller namespace.
        Unknown values never select a file, executable, caller entry or URI alias.
    pointer : str
        Actual caller configuration/source position for safe diagnostics.
    budget : ReferenceBudget or None
        Sole cumulative operation budget when loading runtime sources. Standalone
        value construction has no operation budget and retains the fixed byte cap.

    Returns
    -------
    FixedFormat
        Entire pinned resource, selected definition and complete internal selectors.
        No caller registry, trust state or semantic verdict is changed.

    Raises
    ------
    ConfigurationError
        The exact fixed binding or whole matching installed resource is unavailable.
    InputRefused
        Runtime source acquisition exceeds the same cumulative operation bounds.
    """
    binding = FORMAT_BINDINGS.get(name)
    if binding is None:
        raise configuration_refusal(pointer)
    resource_name, definition_name, selectors = binding
    byte_length, digest = RESOURCES[resource_name]
    reference = BlobRef(
        "sha256:" + digest, str(byte_length), "application/schema+json", "raw_bytes"
    )
    cached = (
        None
        if budget is None
        else budget.cached(reference, subject=reference.digest, pointer=pointer)
    )
    maximum = byte_length
    if cached is None:
        if budget is not None:
            maximum = min(
                maximum,
                budget.limits.max_blob_bytes,
                budget.limits.max_total_reference_bytes - budget.total_bytes,
            )
            if maximum < byte_length:
                raise InputRefused(
                    Reason(
                        "limit_exceeded",
                        reference.digest,
                        None,
                        pointer,
                        "Reference acquisition bound exceeded.",
                    )
                )
        try:
            resource = files("evidence_manifest_toolkit").joinpath(
                "_schemas", resource_name + ".json"
            )
            with resource.open("rb") as handle:
                raw = handle.read(maximum + 1)
        except OSError as error:
            raise configuration_refusal(pointer) from error
    else:
        raw = cached
    if len(raw) != byte_length or hashlib.sha256(raw).hexdigest() != digest:
        raise configuration_refusal(pointer)
    if budget is not None:
        budget.charge(reference, raw, subject=reference.digest, pointer=pointer)
    root = cast(
        dict[str, Schema],
        json.loads(raw)
        if budget is None
        else parse_schema(raw, limits=budget.limits, pointer=pointer),
    )
    definition = (
        cast(dict[str, Schema], root["$defs"])[definition_name]
        if definition_name
        else cast(Schema, root)
    )
    paths = tuple(
        ReferencePath(
            "fixed-format:" + name + ":" + str(index),
            tuple(
                {"kind": "each"} if member is None else {"kind": "member", "name": member}
                for member in selector
            ),
            "schema_optional",
            "schema_optional",
            "when_present",
        )
        for index, selector in enumerate(selectors)
    )
    return FixedFormat(
        cast(Schema, root),
        definition,
        paths,
        name if name in NATIVE_FORMAT_IDS else None,
        name,
    )
