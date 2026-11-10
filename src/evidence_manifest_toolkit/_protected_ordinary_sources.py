# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete ordinary protected statement sources

"""Match actual ordinary sources without authenticating a signature or protected authority."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._acquisition import acquire_reference
from ._budget import ReferenceBudget
from ._closure import ClosureResult
from ._codecs import decode_reference
from ._content import CompleteContent, prepare_content
from ._context_sources import ContextSource
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource, close_fixed_sources, native_format_lookup
from ._immutable import thaw_json
from ._interfaces import Resolver
from ._json import acquire_document
from ._policy_source import PolicyDeclaration
from ._protected_control_sources import ProtectedControlSources
from ._protected_ordinary_bounds import match_protected_ordinary_certificate
from ._schema_resources import StaticSchema
from ._successor_envelopes import SuccessorEnvelope, parse_successor_envelope
from ._successor_formats import load_fixed_format
from ._trust_types import VerificationPolicy
from ._values import BlobRef, Reason, Utc


@dataclass(frozen=True, slots=True)
class ProtectedOrdinarySource:
    """Retain the complete actual receipt, certificate and unprojected scope source.

    Attributes
    ----------
    envelope : SuccessorEnvelope
        Whole actual receipt and exact native message, without a verified signature flag.
    certificate, statement : FixedSource
        Entire selected certificate and actual inline native statement source.
    scope_reference, scope_bytes : BlobRef, bytes
        Full original scope argument and matching bounded bytes. Presence supplies no
        installed scope interpretation, group/identity/custody or signing authority.
    closure : ClosureResult
        Every whole native statement reference under the SAME cumulative budget.
    """

    envelope: SuccessorEnvelope
    certificate: FixedSource
    statement: FixedSource
    scope_reference: BlobRef
    scope_bytes: bytes
    closure: ClosureResult


@dataclass(frozen=True, slots=True)
class PreparedProtectedSources:
    """Keep one actual C0 preparation with its matching ordinary receipt source population.

    Attributes
    ----------
    content : CompleteContent
        Whole original subject, semantics and required reference observations, reused
        by the actual verification invocation without another budget or preparation.
    receipts : tuple of ProtectedOrdinarySource
        Original ordered source matches. None is an admitted or mathematically verified
        receipt; complete native/class/Clock/record predicates remain required.
    """

    content: CompleteContent
    receipts: tuple[ProtectedOrdinarySource, ...]

    @property
    def roots(self) -> tuple[FixedSource, ...]:
        """Return actual whole statements for the original complete Clock source closure.

        Returns
        -------
        tuple of FixedSource
            Every original inline statement, without a fabricated acceptance result.
        """
        return tuple(receipt.statement for receipt in self.receipts)


def acquire_protected_ordinary_sources(
    content_json: bytes,
    *,
    schema_id: str,
    envelopes: tuple[bytes, ...],
    protected: ProtectedControlSources,
    declaration: PolicyDeclaration,
    evaluation_time: Utc,
    policy: VerificationPolicy,
    schemas: Mapping[str, StaticSchema],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> PreparedProtectedSources:
    """Match a nonempty protected population to its whole actual C0 and selected state.

    Parameters
    ----------
    content_json, schema_id : bytes, str
        Entire original source and independently selected content schema.
    envelopes : tuple of bytes
        Actual nonempty explicit ordinary population, never a store discovery.
    protected : ProtectedControlSources
        Complete independently selected grant/snapshot/certificate/control sources.
    declaration : PolicyDeclaration
        Whole ordinary policy's literal principal, role, segment and purpose requirements.
    evaluation_time : Utc
        Original declared caller coordinate, not independently qualified Clock evidence.
    policy : VerificationPolicy
        Entire original claim/purpose/reference population, without a signature waiver.
    schemas : Mapping
        Complete original caller structural lookup.
    resolver : Resolver
        Sole original bounded source.
    budget : ReferenceBudget
        SAME invocation quota, reused for C0, native statements and all source edges.

    Returns
    -------
    PreparedProtectedSources
        Entire actual C0 and receipt source matches. No source match satisfies a native
        signature, record signature, identity/custody, actual Clock or authority predicate.

    Raises
    ------
    InputRefused
        Original content/schema/quota or exact whole target/state/certificate/scope fails.
    ReferenceUnavailable
        An exact original selected required source is missing.
    """
    installed = native_format_lookup(schemas, budget=budget)
    content = prepare_content(
        content_json,
        schema_id=schema_id,
        schemas=schemas,
        resolver=resolver,
        budget=budget,
        requirements=policy.required_reference_paths,
        formats=installed,
    )
    if content.closure.missing_references:
        raise ReferenceUnavailable(content.closure.missing_references[0])
    if content.reasons:
        raise InputRefused(content.reasons[0])
    receipts: list[ProtectedOrdinarySource] = []

    for raw in envelopes:
        envelope = parse_successor_envelope(raw, context="ordinary_statement", budget=budget)
        certificate = match_protected_ordinary_certificate(
            envelope,
            content=content,
            protected=protected,
            declaration=declaration,
            evaluation_time=evaluation_time,
            policy=policy,
        )
        native = envelope.statement
        fixed = FixedSource(
            ContextSource(
                native.reference,
                native.canonical_bytes,
                acquire_document(native.canonical_bytes, limits=budget.limits),
                "evidence_manifest_toolkit.signed_statement.v2",
                (),
            ),
            load_fixed_format(
                "evidence_manifest_toolkit.signed_statement.v2", pointer="/envelopes", budget=budget
            ),
        )
        closure = close_fixed_sources((fixed,), formats=installed, resolver=resolver, budget=budget)
        if closure.missing_references:
            raise ReferenceUnavailable(closure.missing_references[0])
        if closure.reasons:
            raise InputRefused(closure.reasons[0])
        scope_reference = decode_reference(
            thaw_json(native.value["scope_ref"]),
            subject=envelope.reference.digest,
            pointer="/statement/scope_ref",
        )
        scope_bytes = acquire_reference(
            scope_reference,
            resolver=resolver,
            budget=budget,
            subject=envelope.reference.digest,
            pointer="/statement/scope_ref",
        )
        receipts.append(
            ProtectedOrdinarySource(
                envelope, certificate, fixed, scope_reference, scope_bytes, closure
            )
        )
    for identifier in policy.required_claim_ids:
        for purpose in policy.required_purposes:
            if not any(
                receipt.envelope.statement.value["purpose"] == purpose
                and identifier
                in cast(tuple[str, ...], receipt.envelope.statement.value["claim_ids"])
                for receipt in receipts
            ):
                raise InputRefused(
                    Reason(
                        "scope_missing",
                        content.content_ref.digest,
                        identifier,
                        "/claims",
                        "Required signed claim and purpose scope is unavailable.",
                    )
                )
    for purpose in policy.required_purposes:
        if not any(receipt.envelope.statement.value["purpose"] == purpose for receipt in receipts):
            raise InputRefused(
                Reason(
                    "scope_missing",
                    content.content_ref.digest,
                    None,
                    None,
                    "Required signed purpose is unavailable.",
                )
            )
    for claim in content.content_claim_obligations:
        if claim.signature_required and not any(
            claim.claim_id in cast(tuple[str, ...], receipt.envelope.statement.value["claim_ids"])
            for receipt in receipts
        ):
            raise InputRefused(
                Reason(
                    "signature_required",
                    content.content_ref.digest,
                    claim.claim_id,
                    "/claims",
                    "The required evidence signature is unavailable.",
                )
            )
    return PreparedProtectedSources(content, tuple(receipts))
