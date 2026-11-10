# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete successor source and conditional Clock details

"""Retain actual source initialization without converting it into legacy or native authority."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._budget import ReferenceBudget
from ._clock_method_calculate import ClockMethodCalculation, calculate_clock_methods
from ._clock_method_sources import acquire_clock_methods
from ._clock_method_types import ClockMethodInputs
from ._clock_subject import BoundClockSubject
from ._content import CompleteContent
from ._errors import InputRefused
from ._format_sources import native_format_lookup
from ._interfaces import Resolver
from ._method_rule_sources import MethodRuleSources
from ._native_method_sources import compare_native_method_environment
from ._native_rule_bindings import NativeRuleBindings
from ._policy_selection import PolicySelection
from ._protected_receipt_math import ProtectedReceiptMath, check_protected_receipt_math
from ._protected_use_intervals import check_protected_use_intervals
from ._reproduction_history import ReproductionHistory, acquire_reproduction_history
from ._reproduction_record_relations import ReproductionRecordSources
from ._reproduction_record_sources import acquire_reproduction_records
from ._signature_obligations import SignatureObligationCheck, check_signature_obligations
from ._signature_rule_source import SignatureRuleSource, acquire_signature_rule
from ._software_intervals import check_software_intervals
from ._software_receipts import SoftwareReceiptCheck, check_software_receipt
from ._subject_formats import SubjectFormat
from ._successor_envelopes import SuccessorEnvelope
from ._trust_types import VerificationPolicy
from ._values import Reason, Utc


@dataclass(frozen=True, slots=True)
class SuccessorSourceDetails:
    """Keep actual mathematical/source outcomes and complete conditional Clock data.

    Attributes
    ----------
    software_receipts : tuple of SoftwareReceiptCheck
        Every actual selected software receipt correspondence and signature outcome.
    protected_receipts : tuple of ProtectedReceiptMath
        Whole selected protected sources and actual native key/message equations;
        none supplies authenticated authority, custody, identity or Clock acceptance.
    signature_rule : SignatureRuleSource or None
        Whole matching rule, absent when an earlier actual source/math check failed.
    clock_methods : ClockMethodInputs or None
        All three entire raw method records and their full actual provenance bytes.
    clock_calculation : ClockMethodCalculation or None
        Full conditional eight-term/sample/H/E calculation. None means it did not run;
        a value supplies no actual physical/model/class/Clock acceptance verdict.
    signature_obligations : SignatureObligationCheck or None
        Actual unsigned/software claim and purpose coverage after the complete preceding
        source/math checks; separate record and native class obligations remain.
    reproduction_records : tuple of ReproductionRecordSources
        Entire actual reproduction package/body/identity graphs and their located
        relation refusals. Source consistency is not native reproduction admission.
    reproduction_history : ReproductionHistory or None
        Entire actual causal parent/record graph and structural transitions, absent
        after an earlier failure, legacy selection or empty record population.
    native_method_bindings : NativeRuleBindings or None
        Whole four selected declarations from the original connected rule/Clock graph,
        retained after preceding obligations succeed without a second acquisition. This is data consistency, not identity, run,
        Clock, qualification, class or final report admission.
    """

    software_receipts: tuple[SoftwareReceiptCheck, ...]
    protected_receipts: tuple[ProtectedReceiptMath, ...]
    signature_rule: SignatureRuleSource | None
    clock_methods: ClockMethodInputs | None
    clock_calculation: ClockMethodCalculation | None
    signature_obligations: SignatureObligationCheck | None
    reproduction_records: tuple[ReproductionRecordSources, ...]
    reproduction_history: ReproductionHistory | None = None
    native_method_bindings: NativeRuleBindings | None = None


def acquire_successor_source_details(
    selection: PolicySelection,
    *,
    clock: BoundClockSubject | None,
    content: CompleteContent,
    envelopes: tuple[SuccessorEnvelope, ...],
    evaluation_time: Utc,
    policy: VerificationPolicy,
    resolver: Resolver,
    budget: ReferenceBudget,
    formats: Mapping[str, SubjectFormat],
) -> SuccessorSourceDetails:
    """Retain whole reproduction sources for every selected class after preceding checks.

    Parameters
    ----------
    selection : PolicySelection
        Complete original caller-paired ordinary/enclosing policy and class sources.
    clock : BoundClockSubject or None
        Whole actual matching invocation/native E, absent for legacy/unavailable sources.
    content : CompleteContent
        Entire prepared subject and all original claim obligations.
    envelopes : tuple of SuccessorEnvelope
        Whole explicitly supplied ordered successor receipt population.
    evaluation_time : Utc
        Original fixed caller UTC, never advanced after context freeze.
    policy : VerificationPolicy
        Complete independent caller scope and policy reference.
    resolver : Resolver
        Sole original bounded source.
    budget : ReferenceBudget
        SAME original cumulative quota including every prior source/provider input.
    formats : Mapping
        Entire original independently validated structural dispatch for this invocation.

    Returns
    -------
    SuccessorSourceDetails
        Actual entire selected receipt/rule/method/calculation data. Legacy receives
        genuinely absent successor data, with no manufactured TrustContext or state.

    Raises
    ------
    ConfigurationError
        Original policy/method/provider configuration is invalid.
    InputRefused
        A real source/reference/schema/quota or conditional whole error/window fails,
        or a selected software/protected source window does not cover use through native entry.
    ReferenceUnavailable
        An exact required whole original source is absent.
    """
    receipts = (
        tuple(
            check_software_receipt(
                envelope,
                sources=selection.software_sources,
                content_reference=content.content_ref,
                actual_claim_ids=tuple(
                    claim.claim_id for claim in content.content_claim_obligations
                ),
                policy=selection.declaration,
                evaluation_time=evaluation_time,
            )
            for envelope in envelopes
        )
        if selection.software_sources is not None and selection.declaration is not None
        else ()
    )
    protected_receipts = (
        tuple(
            check_protected_receipt_math(source, resolver=resolver, budget=budget)
            for source in selection.protected_statements.receipts
        )
        if selection.protected_statements is not None
        else ()
    )
    signature = None
    methods = None
    calculation = None
    obligations = None
    records: tuple[ReproductionRecordSources, ...] = ()
    if (
        not any(receipt.reasons for receipt in receipts)
        and not any(receipt.reasons for receipt in protected_receipts)
        and clock is not None
        and selection.successor is not None
        and selection.artifact_source.document is not None
    ):
        if (
            selection.protected_sources is not None
            and selection.protected_sources.base.reference
            != clock.sources.configurations["base_policy"].reference
        ):
            raise InputRefused(
                Reason(
                    "policy_unavailable",
                    policy.policy_ref.digest,
                    None,
                    "/authority_rule_ref",
                    "Protected control rule sources conflict.",
                )
            )
        signature = acquire_signature_rule(
            selection.successor,
            policy=policy,
            final_policy=selection.artifact_source.document,
            base_policy_reference=clock.sources.configurations["base_policy"].reference,
            content=content,
            resolver=resolver,
            budget=budget,
        )
        methods = acquire_clock_methods(
            clock,
            conditions_reference=signature.conditions.reference,
            policy_reference=policy.policy_ref,
            formats=formats,
            resolver=resolver,
            budget=budget,
        )
        calculation = calculate_clock_methods(
            methods,
            clock=clock,
            policy_reference=policy.policy_ref,
            signature_rule=signature.declaration,
            budget=budget,
        )
        if selection.software_sources is not None:
            check_software_intervals(
                receipts,
                sources=selection.software_sources,
                interval=calculation.use.whole,
                origin=clock.native_entry.origin,
                policy_reference=policy.policy_ref,
            )
        if selection.protected_sources is not None:
            check_protected_use_intervals(
                selection.protected_sources,
                receipts=()
                if selection.protected_statements is None
                else selection.protected_statements.receipts,
                interval=calculation.use.whole,
                origin=clock.native_entry.origin,
                policy_reference=policy.policy_ref,
            )
        implementation = cast(
            MethodRuleSources, selection.method_rules
        ).native_bindings.launcher_implementation
        if implementation is not None:
            compare_native_method_environment(
                implementation, clock.native_entry.observation.environment_json, budget=budget
            )
        if selection.successor["profile_class"] in (
            "unsigned_declared",
            "software_local_unprotected",
        ):
            obligations = check_signature_obligations(
                content, policy=policy, rule=signature, receipts=receipts
            )
        if selection.protected_sources is not None or (
            obligations is not None and not obligations.ordinary_reasons
        ):
            records = acquire_reproduction_records(
                content,
                policy=selection.successor,
                rules=cast(MethodRuleSources, selection.method_rules),
                formats=formats,
                resolver=resolver,
                budget=budget,
            )
    history = (
        acquire_reproduction_history(
            content,
            records,
            formats=native_format_lookup(formats, budget=budget),
            resolver=resolver,
            budget=budget,
        )
        if records and not any(record.reasons for record in records)
        else None
    )
    native_bindings = (
        selection.method_rules.native_bindings
        if calculation is not None
        and (
            selection.protected_sources is not None
            or (obligations is not None and not obligations.reasons)
        )
        and not any(record.reasons for record in records)
        and selection.method_rules is not None
        else None
    )
    return SuccessorSourceDetails(
        receipts,
        protected_receipts,
        signature,
        methods,
        calculation,
        obligations,
        records,
        history,
        native_bindings,
    )
