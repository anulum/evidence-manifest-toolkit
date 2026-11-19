# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole explicit offline common verification

"""Verify complete selected common evidence without installing trust or accepting domain claims."""

from dataclasses import dataclass

from ._entry_observation import capture_verifier_entry
from ._errors import InputRefused
from ._interfaces import Resolver
from ._invocation_wire import CallerTrust
from ._receipt_authority import receipt_authority
from ._reference_paths import configuration_refusal
from ._registry_types import SchemaRegistry
from ._results import VerificationReport
from ._successor_trust import (
    DelegatedTrustContextV2,
    SoftwareTrustContextV2,
    UnsignedTrustContextV2,
)
from ._trust_state import select_trust_state
from ._trust_types import VerificationPolicy
from ._values import Limits
from ._verification_inputs import (
    LegacyVerificationInvocation,
    VerificationInvocation,
    acquire_verification_inputs,
)
from ._verification_report import compose_verification_report


@dataclass(frozen=True, slots=True)
class VerificationExecution:
    """Keep a completed report with its original complete source and quota context.

    Attributes
    ----------
    report : VerificationReport
        All fifteen original fields from the actual completed verification method.
    invocation : VerificationInvocation
        Whole original inputs and caller, including the SAME ReferenceBudget and
        retained actual native/Clock/policy/record sources. This object owns no resolver.
    """

    report: VerificationReport
    invocation: VerificationInvocation


def verify(
    content_json: bytes,
    *,
    schema_id: str,
    envelopes: tuple[bytes, ...],
    registry: SchemaRegistry,
    resolver: Resolver,
    limits: Limits,
    policy: VerificationPolicy,
    trust: CallerTrust,
) -> VerificationReport:
    """Evaluate whole common content, required closure and independently selected authority.

    Parameters
    ----------
    content_json : bytes
        Entire original strict JSON source; no claim projection or byte identity is invented.
    schema_id : str
        Explicit independently selected content schema, not an artifact code selector.
    envelopes : tuple of bytes
        All actual explicitly supplied detached receipts in original order.
    registry : SchemaRegistry
        Complete independently selected raw schema catalogue, selectors and native roles.
    resolver : Resolver
        Actual bounded offline source; no URL, executable or hidden receipt discovery.
    limits : Limits
        All six original positive bounds shared by every source and control acquisition.
    policy : VerificationPolicy
        Whole independently selected policy and complete exact claim/purpose/selector scope.
    trust : TrustContext or successor context
        Entire explicit caller paired with its whole independently selected policy before
        authority acquisition. The current state method still requires the original legacy
        caller; a V2 carrier is not converted into bootstrap/current/floor fields.

    Returns
    -------
    VerificationReport
        All fifteen original fields with separate common/domain/current results, complete
        observations and actual reasons. No snapshot, floor, key or source record is changed.

    Raises
    ------
    ConfigurationError
        Caller/local policy/registry or the maintained local verifier cannot be configured.
    InputRefused
        Strict source, native envelope or an explicit operation bound is violated.
    ReferenceUnavailable
        Required bootstrap/current/archive source cannot be acquired, retaining its exact
        original full reference. Missing selected graph/control links remain report observations.
    """
    return execute_verification(
        content_json,
        schema_id=schema_id,
        envelopes=envelopes,
        registry=registry,
        resolver=resolver,
        limits=limits,
        policy=policy,
        trust=trust,
    ).report


def execute_verification(
    content_json: bytes,
    *,
    schema_id: str,
    envelopes: tuple[bytes, ...],
    registry: SchemaRegistry,
    resolver: Resolver,
    limits: Limits,
    policy: VerificationPolicy,
    trust: CallerTrust,
) -> VerificationExecution:
    """Retain one actual whole verification invocation until its complete outputs are rendered.

    Parameters
    ----------
    content_json : bytes
        Entire original strict JSON subject, without a claim projection.
    schema_id : str
        Independently selected content schema.
    envelopes : tuple of bytes
        All actual explicitly supplied receipts in original order.
    registry : SchemaRegistry
        Whole independently selected structural and native source catalogue.
    resolver : Resolver
        Original bounded source, retained by its caller through rendering.
    limits : Limits
        Original six cumulative operation bounds; no second rendering budget.
    policy : VerificationPolicy
        Entire original independently selected policy and exact scope.
    trust : TrustContext or successor context
        Whole explicit caller with its unchanged class-specific acquisition method.

    Returns
    -------
    VerificationExecution
        Original completed report paired with the same actual invocation and budget.
        No resolver ownership, class acceptance or current authority is inferred. An
        unsigned V2 caller receives the report composed without any authority state.

    Raises
    ------
    ConfigurationError
        Original caller, policy, registry, provider or class method is unavailable. A
        software or delegated V2 caller is refused at ``/trust``; its route is not built.
    InputRefused
        Original source, signature, schema, operation quota or native check fails.
    ReferenceUnavailable
        A required original whole source is unavailable.
    """
    native_entry = (
        capture_verifier_entry()
        if isinstance(
            trust, (UnsignedTrustContextV2, SoftwareTrustContextV2, DelegatedTrustContextV2)
        )
        else None
    )
    invocation = acquire_verification_inputs(
        content_json,
        schema_id=schema_id,
        envelopes=envelopes,
        registry=registry,
        resolver=resolver,
        limits=limits,
        policy=policy,
        trust=trust,
        native_entry=native_entry,
    )
    if not isinstance(invocation, LegacyVerificationInvocation):
        for receipt in invocation.inputs.software_receipts:
            if receipt.reasons:
                raise InputRefused(receipt.reasons[0])
        for protected_receipt in invocation.inputs.protected_receipts:
            if protected_receipt.reasons:
                raise InputRefused(protected_receipt.reasons[0])
        obligations = invocation.inputs.signature_obligations
        if obligations is not None and obligations.reasons:
            raise InputRefused(obligations.reasons[0])
        for record in invocation.inputs.reproduction_records:
            if record.reasons:
                raise InputRefused(record.reasons[0])
        if not isinstance(invocation.trust, UnsignedTrustContextV2):
            raise configuration_refusal("/trust")
        unsigned = compose_verification_report(
            invocation.inputs,
            state=None,
            receipts=(),
            policy=policy,
            trust=invocation.trust,
            registry=registry,
        )
        return VerificationExecution(unsigned, invocation)
    inputs = invocation.inputs
    checked_trust = invocation.trust
    state = select_trust_state(
        checked_trust,
        registry=registry,
        schemas=inputs.schemas,
        resolver=resolver,
        budget=inputs.budget,
        verifier=invocation.verifier,
    )
    actual_claims = tuple(claim.claim_id for claim in inputs.content.content_claim_obligations)
    receipts = tuple(
        receipt_authority(
            envelope,
            content_reference=inputs.content.content_ref,
            actual_claim_ids=actual_claims,
            state=state,
            trust=checked_trust,
            policy=inputs.policy_declaration,
            resolver=resolver,
            budget=inputs.budget,
            verifier=invocation.verifier,
        )
        for envelope in inputs.envelopes
    )
    report = compose_verification_report(
        inputs,
        state=state,
        receipts=receipts,
        policy=policy,
        trust=checked_trust,
        registry=registry,
    )
    return VerificationExecution(report, invocation)
