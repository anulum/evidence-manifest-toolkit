# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — entire independently selected reproduction record sources

"""Acquire full earlier reproduction sources under the same actual invocation budget."""

from collections.abc import Mapping
from dataclasses import replace

from ._budget import ReferenceBudget
from ._content import CompleteContent
from ._format_sources import (
    native_format_lookup,
)
from ._immutable import FrozenJson
from ._interfaces import Resolver
from ._method_rule_sources import MethodRuleSources
from ._native_launch_sources import acquire_native_launch_source
from ._native_possession_equation import check_native_possession_equation
from ._reproduction_native import check_reproduction_native
from ._reproduction_record_relations import ReproductionRecordSources, reproduction_relation_reasons
from ._reproduction_run_relations import reproduction_run_reasons
from ._reproduction_run_sources import acquire_reproduction_run_sources
from ._reproduction_source_graph import acquire_reproduction_source
from ._subject_formats import SubjectFormat


def acquire_reproduction_records(
    content: CompleteContent,
    *,
    policy: Mapping[str, FrozenJson],
    rules: MethodRuleSources,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> tuple[ReproductionRecordSources, ...]:
    """Read each whole native reproduction package and all selected earlier source graphs.

    Parameters
    ----------
    content : CompleteContent
        Entire actual ordinary C0 after its required signature-scope checks. A waiver
        changes no native record/source/identity or actual reproduction predicate.
    policy : Mapping
        Entire independently paired successor policy; it selects no received executable.
    rules : MethodRuleSources
        Complete selected identity/validation/optional foreign method sources.
    formats : Mapping
        Whole original structural lookup, without adding entries to the caller registry.
    resolver : Resolver
        Sole bounded byte source for the actual original full references.
    budget : ReferenceBudget
        SAME invocation quota, including earlier content/Clock/class/method acquisitions.

    Returns
    -------
    tuple of ReproductionRecordSources
        Every complete source population, declared relation failures and actual selected
        runner equations. No record, key custody or Clock/run authority is admitted.

    Raises
    ------
    ReferenceUnavailable
        Exact original selected record/body/identity/subject/policy or descendant is missing.
    InputRefused
        Original schema, metadata, byte identity, graph cycle or operation bound fails.
    """
    selected = tuple(
        (index, claim)
        for index, claim in enumerate(content.content_claim_obligations)
        if claim.validation_status == "independently_reproduced"
    )
    if not selected:
        return ()
    installed = native_format_lookup(formats, budget=budget)

    results: list[ReproductionRecordSources] = []
    for index, claim in selected:
        complete = acquire_reproduction_source(
            claim,
            index,
            containing_subject=content.content_ref,
            formats=installed,
            resolver=resolver,
            budget=budget,
        )
        record, body, producer, runner = (
            complete.record,
            complete.body,
            complete.producer,
            complete.runner,
        )
        reasons = reproduction_relation_reasons(
            complete, content=content, policy=policy, rules=rules
        )
        launches = (
            (
                acquire_native_launch_source(
                    producer,
                    method=rules.native_bindings.launcher,
                    formats=installed,
                    resolver=resolver,
                    budget=budget,
                ),
                acquire_native_launch_source(
                    runner,
                    method=rules.native_bindings.launcher,
                    formats=installed,
                    resolver=resolver,
                    budget=budget,
                ),
            )
            if not reasons
            else None
        )
        native = (
            check_reproduction_native(
                record, body, producer, runner, formats=installed, resolver=resolver, budget=budget
            )
            if not reasons
            else None
        )
        run = (
            acquire_reproduction_run_sources(
                body,
                bindings=rules.native_bindings,
                formats=installed,
                resolver=resolver,
                budget=budget,
            )
            if not reasons
            else None
        )
        if run is not None:
            reasons += reproduction_run_reasons(
                run, record=record, body=body, runner=runner, rules=rules
            )
        possession = (
            (
                check_native_possession_equation(
                    producer,
                    identity_rule=rules.identity,
                    method=rules.native_bindings.possession,
                    role="producer",
                    expected_request=None,
                    formats=installed,
                    resolver=resolver,
                    budget=budget,
                ),
                check_native_possession_equation(
                    runner,
                    identity_rule=rules.identity,
                    method=rules.native_bindings.possession,
                    role="runner",
                    expected_request=run.request.source.reference,
                    formats=installed,
                    resolver=resolver,
                    budget=budget,
                ),
            )
            if run is not None and not reasons
            else ()
        )
        results.append(
            replace(
                complete,
                reasons=reasons,
                native_evidence=native,
                native_launch_sources=launches,
                run_sources=run,
                possession_equations=possession,
            )
        )
    return tuple(results)
