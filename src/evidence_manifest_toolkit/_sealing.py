# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — full immutable known-schema construction

"""Construct complete known-schema content and optional current-authorized detached receipts."""

from ._budget import ReferenceBudget
from ._caller_config import validate_trust_argument
from ._content import prepare_content
from ._errors import InputRefused, ReferenceUnavailable
from ._interfaces import Resolver, Signer
from ._invocation_wire import CallerTrust
from ._json import validate_limits
from ._reference_paths import configuration_refusal
from ._registry import validate_registry
from ._registry_types import SchemaRegistry
from ._results import SealResult
from ._signature_provider import initialize_verifier
from ._signer_response import sign_statement
from ._signing_authority import signing_public_key
from ._signing_request import construct_statement, validate_signing_request
from ._trust_types import SigningRequest
from ._values import Limits, Reason


def seal(
    content_json: bytes,
    *,
    schema_id: str,
    registry: SchemaRegistry,
    resolver: Resolver,
    limits: Limits,
    signing: SigningRequest | None = None,
    signer: Signer | None = None,
    trust: CallerTrust | None = None,
) -> SealResult:
    """Construct the whole immutable subject after its required native source checks.

    Parameters
    ----------
    content_json : bytes
        Entire original content; no identity, verdict, future link or timestamp is inserted.
    schema_id : str
        Independently selected known schema, never chosen by artifact fields.
    registry : SchemaRegistry
        Complete pinned static schemas, dependencies, common roles and closure selectors.
    resolver : Resolver
        Actual bounded source for the selected required references.
    limits : Limits
        All six explicit positive bounds shared by every selected read and graph root.
    signing : SigningRequest or None
        Exact context-specific statement fields, excluding all computed identities.
    signer : Signer or None
        Actual caller-owned adapter, invoked only after full current authority checks.
    trust : TrustContext or None
        Independently accepted current caller selection; provenance of its prior approval
        is an external caller precondition, not a received configuration Boolean.

    Returns
    -------
    SealResult
        All three immutable fields: whole canonical bytes, their complete content reference,
        and the independently verified detached envelope or None for unsigned construction.
        Construction establishes no domain or current evidence-acceptance verdict.

    Raises
    ------
    ConfigurationError
        Limits, schema registry, partial signing configuration or verifier setup is invalid.
    InputRefused
        Complete content, required closure, native semantics or current authority fails.
    ReferenceUnavailable
        A required original full reference or typed digest cannot be read.
    SignerUnavailable
        The eligible caller adapter fails to supply a verified exact-message raw64 signature.
        No unsigned retry or output publication occurs.
    """
    validate_limits(limits)
    if not isinstance(registry, SchemaRegistry):
        raise configuration_refusal("/registry")
    if not isinstance(schema_id, str) or not schema_id:
        raise configuration_refusal("/schema_id")
    options = (signing is not None, signer is not None, trust is not None)
    if any(options) and not all(options):
        raise configuration_refusal("/signing")
    checked_trust = (
        None if trust is None else validate_trust_argument(trust, signed_construction=True)
    )
    fields = None if signing is None else validate_signing_request(signing, limits=limits)
    budget = ReferenceBudget(limits)
    schemas = validate_registry(registry, limits=limits, budget=budget, resolver=resolver)
    if schema_id not in schemas:
        raise InputRefused(
            Reason(
                "unknown_schema",
                None,
                None,
                None,
                "Selected schema is not known.",
            )
        )
    content = prepare_content(
        content_json,
        schema_id=schema_id,
        schemas=schemas,
        resolver=resolver,
        budget=budget,
        requirements=(),
    )
    if content.closure.missing_references:
        raise ReferenceUnavailable(content.closure.missing_references[0])
    if content.reasons:
        raise InputRefused(content.reasons[0])
    if fields is None or signer is None or checked_trust is None:
        return SealResult(content.canonical_content, content.content_ref, None)
    statement = construct_statement(fields, content=content)
    verifier = initialize_verifier()
    public_key = signing_public_key(
        statement,
        content=content,
        trust=checked_trust,
        registry=registry,
        schemas=schemas,
        resolver=resolver,
        budget=budget,
        verifier=verifier,
    )
    envelope = sign_statement(
        statement,
        signer=signer,
        expected_public_key=public_key,
        verifier=verifier,
    )
    return SealResult(content.canonical_content, content.content_ref, envelope)
