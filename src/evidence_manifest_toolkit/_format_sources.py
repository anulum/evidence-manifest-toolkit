# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected fixed-format source acquisition

"""Acquire selected native/private sources and their complete bounded reference closure."""

from collections.abc import Mapping
from dataclasses import dataclass, replace

from ._budget import ReferenceBudget
from ._closure import ClosureResult, ClosureRoot, traverse_closure
from ._codecs import decode_reference
from ._context_sources import ContextSource, acquire_context_source
from ._errors import InputRefused
from ._interfaces import Resolver
from ._reference_paths import configuration_refusal, select_positions
from ._subject_formats import SubjectFormat, subject_format_reasons
from ._successor_format_bindings import NATIVE_FORMAT_IDS
from ._successor_formats import FixedFormat, load_fixed_format
from ._values import BlobRef, Digest


@dataclass(frozen=True, slots=True)
class FixedSource:
    """Retain whole acquisition and its independently selected structural format.

    Attributes
    ----------
    source : ContextSource
        Original Ref, bounded raw bytes, complete valid document or actual refusals.
    format : FixedFormat
        Entire installed resource, exact definition and complete declared selectors.
        Structural validity never qualifies any authority, Clock or source fact.
    """

    source: ContextSource
    format: FixedFormat


def native_format_lookup(
    formats: Mapping[str, SubjectFormat], *, budget: ReferenceBudget
) -> Mapping[str, SubjectFormat]:
    """Select the complete installed Common-native dispatch without registering caller entries.

    Parameters
    ----------
    formats : Mapping
        Existing independently validated caller/operation structural lookup.
    budget : ReferenceBudget
        SAME invocation budget for the whole pinned native resource. Multiple
        definitions reuse its actual charged bytes; none receives a separate allowance.

    Returns
    -------
    Mapping
        Internal lookup containing the ten exact source-selected native definitions.
        This selects structural data only; each full native semantic method remains
        independently required. Private tokens and URI-prefix aliases are not inserted.

    Raises
    ------
    ConfigurationError
        A caller entry or incompatible binding collides with a reserved native definition,
        or the whole installed source resource is missing/corrupted.
    InputRefused
        Loading the complete native resource exceeds the shared operation bounds.
    """
    selected = dict(formats)
    for name in sorted(NATIVE_FORMAT_IDS):
        binding = load_fixed_format(name, pointer="/registry/entries", budget=budget)
        previous = selected.get(name)
        if previous is not None and previous != binding:
            raise configuration_refusal("/registry/entries")
        selected[name] = binding
    return selected


def validate_fixed_source(
    source: ContextSource,
    *,
    format_name: str,
    formats: Mapping[str, SubjectFormat],
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> FixedSource:
    """Validate an already acquired whole source without repeating its physical read.

    Parameters
    ----------
    source : ContextSource
        Original complete acquired source and its original typed acquisition refusals.
    format_name : str
        Exact owning-method selection; received schema or format fields select no code.
    formats : Mapping
        Independently supplied known schemas for any actual reference metadata assertion.
    budget : ReferenceBudget
        Sole operation budget, including the whole installed source resource.
    subject : str
        Actual parent identity for reference metadata diagnostics.
    pointer : str
        Actual containing reference position.

    Returns
    -------
    FixedSource
        Complete source and fixed format, retaining source absence and all original metadata.
        Private names are never inserted into BlobRef.schema_id or the caller registry.

    Raises
    ------
    ConfigurationError
        The independently selected installed binding is unavailable or corrupted.
    InputRefused
        Whole fixed-resource loading exceeds the same cumulative operation budget.
    """
    selected = load_fixed_format(format_name, pointer=pointer, budget=budget)
    if source.document is None:
        return FixedSource(replace(source, expected_schema_id=selected.schema_id), selected)
    failures = subject_format_reasons(
        selected,
        source.document,
        source.reference,
        formats=formats,
        subject=subject,
        pointer=pointer,
    )
    lexical_failures = []
    if not failures:
        for path in selected.reference_paths:
            try:
                positions = select_positions(
                    source.document.value,
                    path,
                    subject_digest=source.reference.digest,
                    requirements=(),
                )
                for position in positions:
                    if position.present and position.value is not None:
                        decode_reference(
                            position.value,
                            subject=source.reference.digest,
                            pointer=position.pointer,
                        )
            except InputRefused as error:
                lexical_failures.append(error.reason)
    failures = failures + tuple(lexical_failures)
    return FixedSource(
        replace(
            source,
            expected_schema_id=selected.schema_id,
            document=None if failures else source.document,
            reasons=source.reasons + failures,
        ),
        selected,
    )


def acquire_fixed_source(
    reference: BlobRef,
    *,
    format_name: str,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> FixedSource:
    """Read only an explicitly selected whole source under the operation's existing bounds.

    Parameters
    ----------
    reference : BlobRef
        Entire original caller/source argument, preserving absent optional schema metadata.
    format_name : str
        Exact installed native/private binding independently selected by the owning method.
    formats : Mapping
        Known caller schemas and selected installed fixed format data.
    resolver : Resolver
        Actual bounded offline byte source, without hidden store discovery or callbacks.
    budget : ReferenceBudget
        Same cumulative schema/content/context budget for the whole operation.
    subject : str
        Actual containing parent identity.
    pointer : str
        Actual reference position.

    Returns
    -------
    FixedSource
        Whole source, exact static format and actual original refusals; no semantic verdict.

    Raises
    ------
    ConfigurationError
        Local resolver configuration or the fixed installed source binding is invalid.
    InputRefused
        An actual shared source or whole static-resource bound is violated.
    """
    source = acquire_context_source(
        reference,
        expected_control=None,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer=pointer,
    )
    return validate_fixed_source(
        source,
        format_name=format_name,
        formats=formats,
        budget=budget,
        subject=subject,
        pointer=pointer,
    )


def close_fixed_sources(
    sources: tuple[FixedSource, ...],
    *,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
    additional_roots: tuple[ClosureRoot, ...] = (),
) -> ClosureResult:
    """Traverse all selected complete fixed-source roots without mutating caller entries.

    Parameters
    ----------
    sources : tuple of FixedSource
        Only actual owning-method selections, retaining missing or invalid source evidence.
    formats : Mapping
        Original known structural dispatch, copied only into an internal operation lookup.
    resolver : Resolver
        Original bounded offline source; unused objects never become roots or receipts.
    budget : ReferenceBudget
        Sole already-charged operation budget, reused across all roots and every edge.
    additional_roots : tuple of ClosureRoot
        Entire independently selected configuration roots. Their original optional
        schema metadata is checked without inventing private format IDs.

    Returns
    -------
    ClosureResult
        Complete selected graph and every actual source refusal/missing original argument.
        Methods still enforce null/requiredness/identity/class/time/parent predicates.

    Raises
    ------
    ConfigurationError
        A caller entry or incompatible fixed binding would shadow a selected private/native key.
    """
    selected = dict(formats)
    roots: list[ClosureRoot] = list(additional_roots)
    for item in sources:
        name = item.format.name
        existing = selected.get(name)
        if existing is not None and existing != item.format:
            raise configuration_refusal("/registry/entries")
        selected[name] = item.format
        source = item.source
        if source.document is not None and source.raw_bytes is not None:
            roots.append(ClosureRoot(source.reference, source.raw_bytes, format_name=name))
    result = traverse_closure(
        tuple(roots),
        schemas=selected,
        resolver=resolver,
        budget=budget,
        requirements=(),
    )
    return replace(
        result,
        reasons=tuple(reason for item in sources for reason in item.source.reasons)
        + result.reasons,
        missing_references=tuple(
            item.source.reference for item in sources if item.source.raw_bytes is None
        )
        + result.missing_references,
    )
