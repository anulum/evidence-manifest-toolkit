# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected declared-reference closure

"""Traverse only selected roots under pinned schemas and one cumulative acquisition budget."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ._acquisition import acquire_reference, identity_reason
from ._budget import ByteIdentity, ReferenceBudget
from ._codecs import decode_reference
from ._control_context import control_target_schema
from ._difference import utf16_key
from ._errors import InputRefused, ReferenceUnavailable
from ._interfaces import Resolver
from ._json import AcquiredDocument, acquire_document
from ._reference_diagnostics import native_reference_reason
from ._reference_paths import configuration_refusal, select_positions
from ._registry_types import ReferenceRequirement
from ._results import ReferenceObservation
from ._schema_resources import StaticSchema
from ._subject_formats import select_subject_format, subject_format_reasons
from ._successor_formats import FixedFormat
from ._values import BlobRef, Reason


@dataclass(frozen=True, slots=True)
class ClosureRoot:
    """Supply an explicitly selected root without discovering objects in the resolver.

    Attributes
    ----------
    reference : BlobRef
        Exact independently selected root identity and known schema.
    data : bytes
        Entire actually supplied root bytes, retained unchanged.
    expected_schema_id : str or None
        Independently known native caller context, separate from optional reference metadata.
        It supplies no received-schema dispatch or fabricated field in the original reference.
    format_name : str or None
        Exact fixed format independently selected by the owning method. Private
        format names remain separate from the reference's public schema metadata.
    """

    reference: BlobRef
    data: bytes
    expected_schema_id: str | None = None
    format_name: str | None = None


@dataclass(frozen=True, slots=True)
class ClosureResult:
    """Retain graph data and independent refusals for later report composition.

    Attributes
    ----------
    observations : tuple of ReferenceObservation
        Every actual edge, including optional unaccepted positions and repeated targets.
    documents : Mapping
        Complete matching schema-valid subjects with their original numeric token custody.
    bindings : Mapping
        Actual independent structural binding for each admitted document. Private
        format tokens are internal context names, without fabricated public schema IDs.
    reasons : tuple of Reason
        Required-closure failures only; optional failures remain in their edge observations.
    missing_references : tuple of BlobRef
        Exact original genuinely missing required lookup arguments.
    """

    observations: tuple[ReferenceObservation, ...]
    documents: Mapping[ByteIdentity, AcquiredDocument]
    reasons: tuple[Reason, ...]
    missing_references: tuple[BlobRef, ...]
    bindings: Mapping[ByteIdentity, str]


def traverse_closure(
    roots: tuple[ClosureRoot, ...],
    *,
    schemas: Mapping[str, StaticSchema | FixedFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
    requirements: tuple[ReferenceRequirement, ...],
) -> ClosureResult:
    """Validate whole known subjects before expanding their complete declared closure.

    Parameters
    ----------
    roots : tuple of ClosureRoot
        Only explicitly supplied content/context roots; store presence selects nothing.
    schemas : Mapping
        Complete independently validated structural dispatch. Fixed native formats
        supply their own exact selectors without inventing caller registry entries.
    resolver : Resolver
        Caller-owned bounded original-byte lookup interface.
    budget : ReferenceBudget
        Sole operation budget, including schema and dependency acquisitions already charged.
    requirements : tuple of ReferenceRequirement
        Validated policy overrides for exact subjects, known selectors and literal instances.

    Returns
    -------
    ClosureResult
        Complete sorted edge observations, original matching documents and required refusals.
        Common semantic, signature, current-context and domain gates are composed separately.

    Raises
    ------
    ConfigurationError
        An actual local resolver or pinned static schema binding is invalid.
    """
    observations: dict[tuple[str, str, str], ReferenceObservation] = {}
    documents: dict[ByteIdentity, AcquiredDocument] = {}
    bindings: dict[ByteIdentity, str] = {}
    reasons: list[Reason] = []
    missing: list[BlobRef] = []
    visited: dict[tuple[ByteIdentity, str | None], int] = {}
    root_formats: dict[ByteIdentity, str] = {}
    for root in roots:
        if root.format_name is not None:
            root_identity = (
                root.reference.digest,
                root.reference.digest_basis,
                root.reference.byte_length,
            )
            previous = root_formats.get(root_identity)
            if previous is not None and previous != root.format_name:
                raise configuration_refusal("/registry/entries")
            root_formats[root_identity] = root.format_name
    expected_roots: dict[ByteIdentity, set[str]] = {}
    for root in roots:
        if root.expected_schema_id is not None:
            root_identity_key = (
                root.reference.digest,
                root.reference.digest_basis,
                root.reference.byte_length,
            )
            expected_roots.setdefault(root_identity_key, set()).add(root.expected_schema_id)
    pending: list[tuple[ClosureRoot, int, frozenset[ByteIdentity]]] = [
        (root, 0, frozenset()) for root in reversed(roots)
    ]
    while pending:
        root, depth, ancestors = pending.pop()
        reference = root.reference
        identity = reference.digest, reference.digest_basis, reference.byte_length
        schema_id = root.format_name or root.expected_schema_id or reference.schema_id
        if identity in ancestors:
            reasons.append(
                Reason(
                    "cycle_detected",
                    reference.digest,
                    None,
                    None,
                    "Selected content closure is cyclic.",
                )
            )
            continue
        if depth > budget.limits.max_graph_depth:
            reasons.append(
                Reason(
                    "limit_exceeded",
                    reference.digest,
                    None,
                    None,
                    "Reference graph depth bound exceeded.",
                )
            )
            continue
        if visited.get((identity, schema_id), -1) >= depth:
            continue
        visited[(identity, schema_id)] = depth
        try:
            budget.charge(reference, root.data, subject=reference.digest, pointer="")
            failure = identity_reason(
                reference, root.data, budget=budget, subject=reference.digest, pointer=""
            )
            if failure is not None:
                reasons.append(failure)
                continue
            if root.expected_schema_id is not None and reference.schema_id not in (
                None,
                root.expected_schema_id,
            ):
                reasons.append(
                    Reason(
                        "invalid_schema",
                        reference.digest,
                        None,
                        "",
                        "Declared schema conflicts with its independently selected native context.",
                    )
                )
                continue
            if schema_id is None:
                continue
            static = select_subject_format(
                schema_id, formats=schemas, explicit_format=root.format_name is not None
            )
            if static is None:
                reasons.append(
                    Reason(
                        "unknown_schema",
                        reference.digest,
                        None,
                        None,
                        "Selected schema is not known.",
                    )
                )
                continue
            document = documents.get(identity)
            if document is None:
                document = acquire_document(root.data, limits=budget.limits)
            failures = subject_format_reasons(
                static,
                document,
                reference,
                formats=schemas,
                subject=reference.digest,
                pointer="",
                expected_schema_id=root.expected_schema_id,
            )
            if failures:
                reasons.extend(failures)
                continue
            documents[identity] = document
            schema_id = (
                static.entry.schema_id
                if isinstance(static, StaticSchema)
                else static.schema_id or schema_id
            )
            bindings[identity] = schema_id
            selected_requirements = tuple(
                requirement
                for requirement in requirements
                if requirement.subject_digest == reference.digest
                and requirement.schema_id == schema_id
            )
            descendants: list[ClosureRoot] = []
            for path in static.reference_paths:
                try:
                    positions = select_positions(
                        document.value,
                        path,
                        subject_digest=reference.digest,
                        requirements=selected_requirements,
                    )
                except InputRefused as path_error:
                    failure = path_error.reason
                    reasons.append(failure)
                    location = failure.pointer or ""
                    observations[(reference.digest, path.path_id, location)] = ReferenceObservation(
                        reference.digest,
                        path.path_id,
                        location,
                        True,
                        None,
                        "absent" if failure.code == "scope_missing" else "mismatched",
                        (failure,),
                    )
                    continue
                for position in positions:
                    key = reference.digest, path.path_id, position.pointer
                    if not position.present or position.value is None:
                        observations[key] = ReferenceObservation(
                            reference.digest,
                            path.path_id,
                            position.pointer,
                            False,
                            None,
                            "absent" if not position.present else "not_required",
                            (),
                        )
                        continue
                    child: BlobRef | None = None
                    expected_child_schema = control_target_schema(schema_id, position.pointer)
                    try:
                        child = decode_reference(
                            position.value, subject=reference.digest, pointer=position.pointer
                        )
                        try:
                            data = acquire_reference(
                                child,
                                resolver=resolver,
                                budget=budget,
                                subject=reference.digest,
                                pointer=position.pointer,
                            )
                        except ReferenceUnavailable:
                            # acquire_reference preserves the complete original BlobRef on absence.
                            failure = Reason(
                                "reference_unavailable",
                                reference.digest,
                                None,
                                position.pointer,
                                "Required reference unavailable.",
                            )
                            failure = native_reference_reason(
                                failure, schema_id=schema_id, pointer=position.pointer
                            )
                            observations[key] = ReferenceObservation(
                                reference.digest,
                                path.path_id,
                                position.pointer,
                                position.required,
                                child,
                                "unavailable",
                                (failure,),
                            )
                            if position.required:
                                reasons.append(failure)
                                missing.append(child)
                            continue
                        failure = identity_reason(
                            child,
                            data,
                            budget=budget,
                            subject=reference.digest,
                            pointer=position.pointer,
                        )
                        if failure is not None:
                            failure = native_reference_reason(
                                failure, schema_id=schema_id, pointer=position.pointer
                            )
                    except InputRefused as error:
                        failure = error.reason
                        observations[key] = ReferenceObservation(
                            reference.digest,
                            path.path_id,
                            position.pointer,
                            position.required,
                            child,
                            "mismatched",
                            (failure,),
                        )
                        if position.required:
                            reasons.append(failure)
                        continue
                    child_format = root_formats.get(
                        (child.digest, child.digest_basis, child.byte_length)
                    )
                    if (
                        child_format is None
                        and expected_child_schema is None
                        and child.schema_id is None
                    ):
                        candidates = expected_roots.get(
                            (child.digest, child.digest_basis, child.byte_length), set()
                        )
                        if len(candidates) == 1:
                            expected_child_schema = next(iter(candidates))
                    child_schema = child_format or expected_child_schema or child.schema_id
                    if expected_child_schema is not None and child.schema_id not in (
                        None,
                        expected_child_schema,
                    ):
                        failure = Reason(
                            "invalid_schema",
                            reference.digest,
                            None,
                            position.pointer,
                            "Declared schema conflicts with its independently selected native context.",
                        )
                    child_static = (
                        None
                        if child_schema is None
                        else select_subject_format(
                            child_schema, formats=schemas, explicit_format=child_format is not None
                        )
                    )
                    if failure is None and child_schema is not None and child_static is None:
                        failure = Reason(
                            "unknown_schema",
                            reference.digest,
                            None,
                            position.pointer,
                            "Selected schema is not known.",
                        )
                    child_failures: tuple[Reason, ...] = () if failure is None else (failure,)
                    if failure is None and child_static is not None:
                        try:
                            child_document = acquire_document(data, limits=budget.limits)
                            child_failures = subject_format_reasons(
                                child_static,
                                child_document,
                                child,
                                formats=schemas,
                                subject=reference.digest,
                                pointer=position.pointer,
                                expected_schema_id=expected_child_schema,
                            )
                        except InputRefused as source_error:
                            original = source_error.reason
                            child_failures = (
                                Reason(
                                    original.code,
                                    child.digest,
                                    original.claim_id,
                                    original.pointer,
                                    original.detail,
                                ),
                            )
                    observations[key] = ReferenceObservation(
                        reference.digest,
                        path.path_id,
                        position.pointer,
                        position.required,
                        child,
                        "matched" if not child_failures else "mismatched",
                        child_failures,
                    )
                    if child_failures:
                        if position.required:
                            reasons.extend(child_failures)
                    elif position.required:
                        descendants.append(
                            ClosureRoot(child, data, expected_child_schema, child_format)
                        )
            pending.extend(
                (child, depth + 1, ancestors | {identity}) for child in reversed(descendants)
            )
        except InputRefused as error:
            failure = error.reason
            reasons.append(
                Reason(
                    failure.code,
                    reference.digest,
                    failure.claim_id,
                    failure.pointer,
                    failure.detail,
                )
            )
    ordered = sorted(observations, key=lambda key: tuple(utf16_key(part) for part in key))
    return ClosureResult(
        tuple(observations[key] for key in ordered),
        MappingProxyType(documents),
        tuple(reasons),
        tuple(missing),
        MappingProxyType(bindings),
    )
