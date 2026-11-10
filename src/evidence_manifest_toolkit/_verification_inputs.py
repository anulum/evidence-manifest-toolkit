# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole verification source acquisition

"""Acquire the original caller selection and complete content without manufacturing acceptance."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._budget import ReferenceBudget
from ._caller_config import validate_policy_argument, validate_verification_trust
from ._clock_method_calculate import ClockMethodCalculation
from ._clock_method_types import ClockMethodInputs
from ._clock_subject import BoundClockSubject, bind_clock_subject
from ._content import CompleteContent, prepare_content
from ._context_sources import ContextSource
from ._entry_binding import BoundNativeEntry, bind_native_entry
from ._entry_observation import NativeEntryCapture
from ._envelopes import ParsedEnvelope, parse_envelope
from ._interfaces import Resolver
from ._invocation_wire import CallerTrust, SuccessorTrust
from ._json import validate_limits
from ._native_rule_bindings import NativeRuleBindings
from ._policy_selection import PolicySelection, acquire_policy_selection
from ._policy_source import PolicyDeclaration
from ._protected_receipt_math import ProtectedReceiptMath
from ._reference_paths import configuration_refusal
from ._registry import validate_registry
from ._registry_types import SchemaRegistry
from ._reproduction_history import ReproductionHistory
from ._reproduction_record_relations import ReproductionRecordSources
from ._schema_resources import StaticSchema
from ._signature_obligations import SignatureObligationCheck
from ._signature_provider import initialize_verifier
from ._signature_rule_source import SignatureRuleSource
from ._software_receipts import SoftwareReceiptCheck
from ._successor_content import prepare_successor_content
from ._successor_envelopes import SuccessorEnvelope, parse_successor_envelope
from ._successor_source_details import acquire_successor_source_details
from ._trust_types import TrustContext, VerificationPolicy
from ._values import Limits

if TYPE_CHECKING:
    from ._native_signature import NativeVerifier


@dataclass(frozen=True, slots=True)
class VerificationInputs:
    """Retain entire operation sources for subsequent independent gate composition.

    Attributes
    ----------
    schemas : Mapping
        Complete independently validated registry with protected common constraints.
    budget : ReferenceBudget
        Sole cumulative budget, retained for current/history/control/clock acquisition.
    policy_source : ContextSource
        Exact selected policy reference, actual bounded bytes/document or located absence.
    policy_declaration : PolicyDeclaration or None
        Complete parsed declaration, absent if actual policy bytes could not be interpreted.
    content : CompleteContent
        Whole canonical subject, native semantics and every selected required reference edge.
    envelopes : tuple of ParsedEnvelope
        Entire explicitly supplied receipts in caller order; no hidden store discovery.
    policy_selection : PolicySelection
        Both complete ordinary/enclosing policy sources and any selected successor
        Clock/configuration graph, retained for full operation admission and presentation.
    successor_envelopes : tuple of SuccessorEnvelope
        Complete V2 ordinary receipts under the independently paired successor route,
        without reinterpreting them as legacy statements or granting signing authority.
    native_entry : BoundNativeEntry or None
        Actual E and whole selected native code/boot/process/environment sources for a V2
        invocation. Legacy uses None; binding alone supplies no accepted Clock or authority.
    clock_subject : BoundClockSubject or None
        Whole matching Clock invocation and actual entry chronology, when its complete
        sources are available. Source consistency supplies no physical bound or authority.
    software_receipts : tuple of SoftwareReceiptCheck
        Entire actual software receipt targets and maintained-provider mathematical checks.
        Matching is not full rule, identity, custody, Clock or native authority admission.
    protected_receipts : tuple of ProtectedReceiptMath
        Whole selected native key source and exact V2 mathematical checks, without
        authenticated certificate, issuer, custody, Clock or protected state admission.
    signature_rule : SignatureRuleSource or None
        Complete fixed native rule and exact independent scope/source joins after a
        matching Clock subject. Parsing applies no exception or class/Clock admission.
        Legacy and unavailable subjects retain None without inventing a rule source.
    clock_methods : ClockMethodInputs or None
        All three whole raw model/use records after actual preceding source checks.
    clock_calculation : ClockMethodCalculation or None
        Complete conditional N/sample/H/E arithmetic and full window consistency,
        without a physical source/model/calibration or accepted Clock verdict.
    signature_obligations : SignatureObligationCheck or None
        Complete actual unsigned/software content coverage and unwaived record signature
        obligations, without admitting a class or replacing protected verification.
    reproduction_records : tuple of ReproductionRecordSources
        Complete actual package/body/identity/source graphs after applicable ordinary
        signature checks; all original native run/class/Clock requirements remain.
    reproduction_history : ReproductionHistory or None
        Whole actual causal parent sources and exact structural transitions, never
        an inferred native authority, Clock, independent run or class acceptance.
    native_method_bindings : NativeRuleBindings or None
        Entire four selected method declarations and their original bounded graph,
        retained from actual acquisition for later class/state/report composition.
        No source qualification, execution, identity or authority follows from shape.
    """

    schemas: Mapping[str, StaticSchema]
    budget: ReferenceBudget
    policy_source: ContextSource
    policy_declaration: PolicyDeclaration | None
    content: CompleteContent
    envelopes: tuple[ParsedEnvelope, ...]
    policy_selection: PolicySelection
    successor_envelopes: tuple[SuccessorEnvelope, ...]
    native_entry: BoundNativeEntry | None
    clock_subject: BoundClockSubject | None
    software_receipts: tuple[SoftwareReceiptCheck, ...]
    protected_receipts: tuple[ProtectedReceiptMath, ...]
    signature_rule: SignatureRuleSource | None
    clock_methods: ClockMethodInputs | None
    clock_calculation: ClockMethodCalculation | None
    signature_obligations: SignatureObligationCheck | None
    reproduction_records: tuple[ReproductionRecordSources, ...]
    reproduction_history: ReproductionHistory | None = None
    native_method_bindings: NativeRuleBindings | None = None


@dataclass(frozen=True, slots=True)
class LegacyVerificationInvocation:
    """Bind complete legacy sources to their actual independently selected method.

    Attributes
    ----------
    inputs : VerificationInputs
        Whole acquired operation sources and the sole unchanged reference budget.
    trust : TrustContext
        Original validated legacy caller, never reconstructed from a V2 declaration.
    verifier : NativeVerifier
        Actual maintained provider initialized at the original legacy boundary.
    """

    inputs: VerificationInputs
    trust: TrustContext
    verifier: NativeVerifier


@dataclass(frozen=True, slots=True)
class SuccessorVerificationInvocation:
    """Retain the whole explicit V2 selection without manufacturing a legacy verifier.

    Attributes
    ----------
    inputs : VerificationInputs
        Entire selected policy/content/Clock sources and original cumulative budget.
    trust : successor context
        Complete revalidated frozen caller, preserving every class-specific field.
        Source acquisition alone grants no operational state or native qualification.
    """

    inputs: VerificationInputs
    trust: SuccessorTrust


type VerificationInvocation = LegacyVerificationInvocation | SuccessorVerificationInvocation


def acquire_verification_inputs(
    content_json: bytes,
    *,
    schema_id: str,
    envelopes: tuple[bytes, ...],
    registry: SchemaRegistry,
    resolver: Resolver,
    limits: Limits,
    policy: VerificationPolicy,
    trust: CallerTrust,
    native_entry: NativeEntryCapture | None,
) -> VerificationInvocation:
    """Acquire whole verification inputs under one source budget and the original caller law.

    Parameters
    ----------
    content_json : bytes
        Complete original document, never a projected claim or digest-only substitute.
    schema_id : str
        Independently selected content schema, without received implementation dispatch.
    envelopes : tuple of bytes
        All actual explicitly supplied detached receipt bytes in their original order.
    registry : SchemaRegistry
        Complete independently selected static catalogue and raw schema/dependency bytes.
    resolver : Resolver
        Actual bounded offline source; presence in its store selects no hidden envelopes.
    limits : Limits
        All six original positive acquisition/depth/count bounds for this whole operation.
    policy : VerificationPolicy
        Exact selected policy reference and complete required claim/purpose/path populations.
    trust : TrustContext or successor context
        Entire explicit caller class, current/archive selection and fixed UTC. Source
        acceptance remains an independent method obligation rather than an artifact bit.
    native_entry : native capture or None
        Actual V2 E captured at the public operation entry before source traversal;
        None only for the legacy method, without inventing a native sample.

    Returns
    -------
    LegacyVerificationInvocation or SuccessorVerificationInvocation
        Entire actual sources paired with the explicit original caller. Legacy initializes
        its verifier at the original boundary. Compatible actual software receipts select
        the provider only for their mathematical check; unsigned and source-only routes
        initialize none. A declaration supplies no authority, Clock or current verdict.

    Raises
    ------
    ConfigurationError
        Limits, closed caller configuration, selected static registry, local policy grammar
        or native verifier initialization is invalid.
    InputRefused
        Strict content/envelope acquisition or an explicit shared bound is violated.
    """
    validate_limits(limits)
    if not isinstance(registry, SchemaRegistry):
        raise configuration_refusal("/registry")
    if not isinstance(schema_id, str) or not schema_id:
        raise configuration_refusal("/schema_id")
    if not isinstance(envelopes, tuple) or any(not isinstance(data, bytes) for data in envelopes):
        raise configuration_refusal("/envelopes")
    checked_trust = validate_verification_trust(trust)
    budget = ReferenceBudget(limits)
    schemas = validate_registry(registry, limits=limits, budget=budget, resolver=resolver)
    validate_policy_argument(policy, schemas=schemas)
    if isinstance(checked_trust, TrustContext):
        verifier = initialize_verifier()
        inputs = _acquire_selected_inputs(
            content_json,
            schema_id=schema_id,
            envelopes=envelopes,
            registry=registry,
            schemas=schemas,
            resolver=resolver,
            budget=budget,
            policy=policy,
            trust=checked_trust,
            native_entry=None,
        )
        return LegacyVerificationInvocation(inputs, checked_trust, verifier)
    inputs = _acquire_selected_inputs(
        content_json,
        schema_id=schema_id,
        envelopes=envelopes,
        registry=registry,
        schemas=schemas,
        resolver=resolver,
        budget=budget,
        policy=policy,
        trust=checked_trust,
        native_entry=native_entry,
    )
    return SuccessorVerificationInvocation(inputs, checked_trust)


def _acquire_selected_inputs(
    content_json: bytes,
    *,
    schema_id: str,
    envelopes: tuple[bytes, ...],
    registry: SchemaRegistry,
    schemas: Mapping[str, StaticSchema],
    resolver: Resolver,
    budget: ReferenceBudget,
    policy: VerificationPolicy,
    trust: CallerTrust,
    native_entry: NativeEntryCapture | None,
) -> VerificationInputs:
    """Acquire whole paired sources and actual required software receipt correspondence.

    Parameters
    ----------
    content_json : bytes
        Complete original content source, never a projected subject.
    schema_id : str
        Independently selected content schema after configuration validation.
    envelopes : tuple of bytes
        Original explicitly supplied receipts in order.
    registry : SchemaRegistry
        Complete original caller registry without inserted native/private entries.
    schemas : Mapping
        Entire validated static structural dispatch for that caller registry.
    resolver : Resolver
        Original bounded source with no authority or executable discovery.
    budget : ReferenceBudget
        SAME invocation budget, including prior schema reads and every later source.
    policy : VerificationPolicy
        Entire validated original claim/purpose/reference selection.
    trust : TrustContext or successor context
        Complete independent caller for exact whole policy and method pairing.
    native_entry : native capture or None
        Actual operation entry observation, never recomputed after traversal.

    Returns
    -------
    VerificationInputs
        Complete actual sources, semantic observations and any software receipt math.
        No legacy state, authority or Clock qualification is fabricated for a V2 route.

    Raises
    ------
    ConfigurationError
        Whole policy/caller pairing, fixed selected source or a required provider is invalid.
    InputRefused
        Original content/envelope/source or shared operation bounds are violated.
    ReferenceUnavailable
        A required successor policy source is absent, preserving its exact argument.
    """
    selected_policy = acquire_policy_selection(
        policy,
        content_json=content_json,
        schema_id=schema_id,
        trust=trust,
        envelopes=envelopes,
        registry=registry,
        schemas=schemas,
        resolver=resolver,
        budget=budget,
    )
    bound_entry = (
        bind_native_entry(
            native_entry,
            trust=trust,
            policy_reference=policy.policy_ref,
            resolver=resolver,
            budget=budget,
        )
        if not isinstance(trust, TrustContext)
        else None
    )
    prepared = selected_policy.protected_statements
    content = (
        prepared.content
        if prepared is not None
        else prepare_content(
            content_json,
            schema_id=schema_id,
            schemas=schemas,
            resolver=resolver,
            budget=budget,
            requirements=policy.required_reference_paths,
        )
    )
    parsed = (
        tuple(parse_envelope(data, limits=budget.limits) for data in envelopes)
        if selected_policy.successor is None
        else ()
    )
    successor_parsed = (
        tuple(receipt.envelope for receipt in prepared.receipts)
        if prepared is not None
        else tuple(
            parse_successor_envelope(data, context="ordinary_statement", budget=budget)
            for data in envelopes
        )
        if selected_policy.successor is not None
        else ()
    )
    clock_subject = (
        bind_clock_subject(
            selected_policy.clock_sources,
            trust=trust,
            content_reference=content.content_ref,
            envelopes=envelopes,
            registry=registry,
            limits=budget.limits,
            final_policy=selected_policy.artifact_source.document,
            policy_reference=policy.policy_ref,
            budget=budget,
            native_entry=bound_entry,
        )
        if not isinstance(trust, TrustContext)
        and bound_entry is not None
        and selected_policy.clock_sources is not None
        and selected_policy.artifact_source.document is not None
        else None
    )
    details = acquire_successor_source_details(
        selected_policy,
        clock=clock_subject,
        content=content,
        envelopes=successor_parsed,
        evaluation_time=trust.evaluation_time,
        policy=policy,
        resolver=resolver,
        budget=budget,
        formats=schemas,
    )
    if selected_policy.successor is not None:
        content = prepare_successor_content(
            content_json,
            schema_id=schema_id,
            schemas=schemas,
            history=details.reproduction_history,
            resolver=resolver,
            budget=budget,
            policy=policy,
        )
    return VerificationInputs(
        schemas,
        budget,
        selected_policy.source,
        selected_policy.declaration,
        content,
        parsed,
        selected_policy,
        successor_parsed,
        bound_entry,
        clock_subject,
        details.software_receipts,
        details.protected_receipts,
        details.signature_rule,
        details.clock_methods,
        details.clock_calculation,
        details.signature_obligations,
        details.reproduction_records,
        details.reproduction_history,
        details.native_method_bindings,
    )
