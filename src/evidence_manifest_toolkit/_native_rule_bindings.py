# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole selected native method binding sources

"""Acquire entire selected method declarations without accepting their qualification or execution."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._budget import ReferenceBudget
from ._closure import ClosureResult
from ._codecs import decode_reference
from ._context_sources import acquire_context_source
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource, close_fixed_sources
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._native_installation import match_native_installation
from ._native_method_formats import NativeMethodRole, native_method_format
from ._native_method_sources import NativeMethodSources, acquire_launch_method_sources
from ._subject_formats import SubjectFormat, subject_format_reasons


@dataclass(frozen=True, slots=True)
class NativeRuleBindings:
    """Retain every whole selected binding and the complete original source graph.

    Attributes
    ----------
    launcher, possession, execution, comparison : FixedSource
        Entire original declarations, bytes and exact independently selected fields.
        Structural consistency is not implementation/environment/qualification,
        observed identity, key possession, Clock, custody, run or comparison acceptance.
    closure : ClosureResult
        Complete rule and declaration graph under the SAME resolver and cumulative quota.
        No unavailable source or failed metadata edge is removed or weakened.
    launcher_implementation : NativeMethodSources or None
        Whole known installed code, selected environment and original unadmitted
        qualification data; absent for an unsupported observer or other contract.
    """

    launcher: FixedSource
    possession: FixedSource
    execution: FixedSource
    comparison: FixedSource
    closure: ClosureResult
    launcher_implementation: NativeMethodSources | None = None

    @property
    def roots(self) -> tuple[FixedSource, ...]:
        """Return every complete selected declaration for the original connected Clock graph.

        Returns
        -------
        tuple of FixedSource
            Whole launcher, possession, execution and comparison sources with their
            independently selected formats. No graph depth or quota is reset.
        """
        return (self.launcher, self.possession, self.execution, self.comparison) + (
            ()
            if self.launcher_implementation is None
            else (self.launcher_implementation.installation.descriptor,)
        )


def acquire_native_rule_bindings(
    identity: FixedSource,
    validation: FixedSource,
    *,
    other_rules: tuple[FixedSource, ...] = (),
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> NativeRuleBindings:
    """Read and close all four whole native-method declarations from the selected rules.

    Parameters
    ----------
    identity, validation : FixedSource
        Whole independently selected sources after their original structural/class joins.
        Received record fields select no procedure.
    other_rules : tuple of FixedSource
        Entire other selected rule roots, including the optional foreign rule. All join
        the SAME connected closure; parent-to-declaration depth never starts over.
    formats : Mapping
        Original independently supplied/native structural lookup, never mutated.
    resolver : Resolver
        Sole bounded offline source for each exact full original reference.
    budget : ReferenceBudget
        SAME operation budget, including actual Clock/receipt/record acquisition.

    Returns
    -------
    NativeRuleBindings
        All complete declarations and source observations. A valid grammar or Ref does
        not establish any executed method or permit final class/state/report admission.

    Raises
    ------
    ReferenceUnavailable
        An exact required method source or actual selected descendant is absent.
    InputRefused
        Original source/schema/metadata/lexeme/cycle/depth or cumulative quota fails.
    ConfigurationError
        The fixed installed data resource is unavailable or conflicts with dispatch.
    """
    selections: tuple[tuple[FixedSource, NativeMethodRole, str], ...] = (
        (identity, "launcher", "launcher_or_observer_procedure_ref"),
        (identity, "possession", "actual_key_possession_rule_ref"),
        (validation, "execution", "run_and_seal_before_comparison_procedure_ref"),
        (validation, "comparison", "comparison_rule_ref"),
    )
    roots: list[FixedSource] = []
    for parent, role, field in selections:
        subject = parent.source.reference.digest
        value = cast(dict[str, JsonValue], cast(AcquiredDocument, parent.source.document).value)
        reference = decode_reference(value[field], subject=subject, pointer="/" + field)
        source = acquire_context_source(
            reference,
            expected_control=None,
            resolver=resolver,
            budget=budget,
            subject=subject,
            pointer="/" + field,
        )
        if source.raw_bytes is None:
            raise ReferenceUnavailable(reference)
        if source.document is None:
            raise InputRefused(source.reasons[0])
        grammar = native_method_format(role, budget=budget, subject=subject, pointer="/" + field)
        failures = subject_format_reasons(
            grammar,
            source.document,
            reference,
            formats=formats,
            subject=subject,
            pointer="/" + field,
        )
        if failures:
            raise InputRefused(failures[0])
        roots.append(FixedSource(source, grammar))
    selected_inputs = acquire_launch_method_sources(roots[0], resolver=resolver, budget=budget)
    complete_roots = (identity, validation, *other_rules, *roots)
    closure = close_fixed_sources(
        complete_roots,
        formats=formats,
        resolver=resolver,
        budget=budget,
    )
    if closure.missing_references:
        raise ReferenceUnavailable(closure.missing_references[0])
    if closure.reasons:
        raise InputRefused(closure.reasons[0])
    implementation = (
        None
        if selected_inputs is None
        else NativeMethodSources(
            selected_inputs,
            match_native_installation(
                selected_inputs.implementation_reference,
                selected_inputs.implementation_bytes,
                subject=selected_inputs.declaration_reference.digest,
                budget=budget,
            ),
        )
    )
    return NativeRuleBindings(roots[0], roots[1], roots[2], roots[3], closure, implementation)
