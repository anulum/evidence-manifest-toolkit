# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole native execution release and comparison source graph

"""Acquire actual selected native records without treating source shape as an executed run."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._budget import ReferenceBudget
from ._closure import ClosureResult
from ._codecs import decode_reference
from ._context_sources import acquire_context_source
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource, acquire_fixed_source, close_fixed_sources
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._native_launch_sources import NativeLaunchSource, acquire_native_launch_source
from ._native_record_formats import NativeRunRecord, native_record_format
from ._native_rule_bindings import NativeRuleBindings
from ._subject_formats import SubjectFormat, subject_format_reasons


@dataclass(frozen=True, slots=True)
class ReproductionRunSources:
    """Retain every whole native record and the complete connected source closure.

    Attributes
    ----------
    execution, request, release, comparison, comparison_request, raw_comparison : FixedSource
        Entire execution observation/request, release and comparison observations,
        comparison request and raw evidence. Their order is not an execution claim.
    access : tuple of FixedSource
        Entire ordered execution, release and comparison access records; equal
        references retain their original separate uses without extra physical reads.
    comparator : FixedSource
        Entire actual comparator binding, which may name a different process from
        the execution runner. Exact expected seat/vendor/policy still need checking.
    comparator_launch : NativeLaunchSource
        Whole comparator launch source under the independently selected known method.
        Source correspondence supplies no observed vendor or independent run proof.
    closure : ClosureResult
        Complete graph with the selecting body and SAME cumulative source budget.
        Matching sources do not qualify code, identity, chronology, isolation or outcome.
    """

    execution: FixedSource
    request: FixedSource
    release: FixedSource
    comparison: FixedSource
    comparison_request: FixedSource
    raw_comparison: FixedSource
    access: tuple[FixedSource, ...]
    comparator: FixedSource
    comparator_launch: NativeLaunchSource
    closure: ClosureResult


def acquire_reproduction_run_sources(
    body: FixedSource,
    *,
    bindings: NativeRuleBindings,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> ReproductionRunSources:
    """Read every whole execution/release/comparison record selected by the actual body.

    Parameters
    ----------
    body : FixedSource
        Entire already checked independent validation body.
    bindings : NativeRuleBindings
        Whole independently selected known launcher and native method declarations.
    formats : Mapping
        Original independently selected structural schemas, never mutated.
    resolver : Resolver
        Sole bounded source; received paths and commands remain inert data.
    budget : ReferenceBudget
        SAME invocation limits, cache, metadata and graph accounting.

    Returns
    -------
    ReproductionRunSources
        Full closed native records and every source observation. Semantic joins,
        actual run, independent comparison and method qualification remain separate.

    Raises
    ------
    ReferenceUnavailable
        An exact original record or descendant is absent.
    InputRefused
        Whole record shape, reference metadata, byte identity, cycle or quota fails.
    ConfigurationError
        The fixed installed native data grammar is unavailable.
    """

    def acquire(parent: FixedSource, field: str, kind: NativeRunRecord) -> FixedSource:
        """Read an exact whole reference with the independently selected fixed definition."""
        subject = parent.source.reference.digest
        value = cast(dict[str, JsonValue], cast(AcquiredDocument, parent.source.document).value)
        pointer = "/" + field
        reference = decode_reference(value[field], subject=subject, pointer=pointer)
        grammar = native_record_format(kind, budget=budget, subject=subject, pointer=pointer)
        source = acquire_context_source(
            reference,
            expected_control=None,
            resolver=resolver,
            budget=budget,
            subject=subject,
            pointer=pointer,
        )
        if source.raw_bytes is None:
            raise ReferenceUnavailable(reference)
        if source.document is None:
            raise InputRefused(source.reasons[0])
        reasons = subject_format_reasons(
            grammar, source.document, reference, formats=formats, subject=subject, pointer=pointer
        )
        if reasons:
            raise InputRefused(reasons[0])
        return FixedSource(source, grammar)

    execution = acquire(body, "actual_run_provenance_ref", "execution_observation")
    request = acquire(execution, "execution_request_ref", "execution_request")
    release = acquire(body, "comparison_release_order_ref", "release_observation")
    comparison = acquire(body, "whole_comparison_evidence_ref", "comparison_observation")
    raw = acquire(comparison, "whole_raw_comparison_inputs_outputs_ref", "comparison_raw_evidence")
    comparison_request = acquire(raw, "comparison_request_ref", "comparison_request")
    raw_value = cast(dict[str, JsonValue], cast(AcquiredDocument, raw.source.document).value)
    comparator_reference = decode_reference(
        raw_value["comparator_binding_ref"],
        subject=raw.source.reference.digest,
        pointer="/comparator_binding_ref",
    )
    comparator = acquire_fixed_source(
        comparator_reference,
        format_name="evidence_manifest_toolkit.identity_binding.v2",
        formats=formats,
        resolver=resolver,
        budget=budget,
        subject=raw.source.reference.digest,
        pointer="/comparator_binding_ref",
    )
    if comparator.source.raw_bytes is None:
        raise ReferenceUnavailable(comparator_reference)
    if comparator.source.document is None:
        raise InputRefused(comparator.source.reasons[0])
    comparator_launch = acquire_native_launch_source(
        comparator, method=bindings.launcher, formats=formats, resolver=resolver, budget=budget
    )
    access = (
        acquire(execution, "actual_access_order_source_ref", "access_observation"),
        acquire(release, "actual_access_order_source_ref", "access_observation"),
        acquire(raw, "access_observation_ref", "access_observation"),
    )
    roots = (
        body,
        execution,
        request,
        release,
        comparison,
        raw,
        comparison_request,
        comparator,
        *access,
    )
    closure = close_fixed_sources(roots, formats=formats, resolver=resolver, budget=budget)
    if closure.missing_references:
        raise ReferenceUnavailable(closure.missing_references[0])
    if closure.reasons:
        raise InputRefused(closure.reasons[0])
    return ReproductionRunSources(
        execution,
        request,
        release,
        comparison,
        comparison_request,
        raw,
        access,
        comparator,
        comparator_launch,
        closure,
    )
