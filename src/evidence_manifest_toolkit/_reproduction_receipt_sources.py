# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete parsed validation receipt source closure

"""Retain each whole native statement, explicit certificate and bounded source graph."""

from collections.abc import Mapping
from dataclasses import dataclass

from ._budget import ReferenceBudget
from ._closure import ClosureResult
from ._codecs import decode_reference
from ._context_sources import ContextSource
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource, acquire_fixed_source, close_fixed_sources
from ._immutable import thaw_json
from ._interfaces import Resolver
from ._json import acquire_document
from ._subject_formats import SubjectFormat
from ._successor_envelopes import SuccessorEnvelope
from ._successor_formats import load_fixed_format


@dataclass(frozen=True, slots=True)
class ValidationReceiptSources:
    """Retain the entire earlier receipt and its explicitly selected source graph.

    Attributes
    ----------
    envelope : SuccessorEnvelope
        Original whole ordered receipt and exact native message.
    statement : FixedSource
        Entire actual inline statement under its independently installed native format.
    certificate : FixedSource or None
        Whole protected runner leaf source, absent for the unprotected mathematical route.
    closure : ClosureResult
        All selected statement/certificate reference edges with actual byte identities.
        Source presence proves no historical authorization, scope, custody or Clock bound.
    """

    envelope: SuccessorEnvelope
    statement: FixedSource
    certificate: FixedSource | None
    closure: ClosureResult


def acquire_validation_receipt_sources(
    envelope: SuccessorEnvelope,
    *,
    protected: bool,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> ValidationReceiptSources:
    """Close the parsed native source graph before using any certificate key bytes.

    Parameters
    ----------
    envelope : SuccessorEnvelope
        Actual whole ordinary receipt with target and claim-inventory correspondence.
    protected : bool
        Original selected record class, never a class inferred from a signature.
    formats : Mapping
        Complete already installed native and original structural bindings.
    resolver : Resolver
        Sole original bounded source; no store discovery or network fallback.
    budget : ReferenceBudget
        SAME invocation allowance and immutable whole-byte cache.

    Returns
    -------
    ValidationReceiptSources
        Whole statement, actual protected certificate and source graph. Complete earlier
        state/issuer/scope/time, key custody and independent validation remain required.

    Raises
    ------
    ReferenceUnavailable
        An exact selected certificate or required native descendant is unavailable.
    InputRefused
        A native format, whole reference identity, metadata, cycle or original bound fails.
    ConfigurationError
        The installed source method or resolver configuration is invalid.
    """
    native = envelope.statement
    statement = FixedSource(
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
    certificate = None
    if protected:
        reference = decode_reference(
            thaw_json(native.value["authorization_ref"]),
            subject=envelope.reference.digest,
            pointer="/statement/authorization_ref",
        )
        certificate = acquire_fixed_source(
            reference,
            format_name="evidence_manifest_toolkit.delegated_certificate.v2",
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=envelope.reference.digest,
            pointer="/statement/authorization_ref",
        )
        if certificate.source.raw_bytes is None:
            raise ReferenceUnavailable(reference)
        if certificate.source.document is None:
            raise InputRefused(certificate.source.reasons[0])
    roots = (statement,) + (() if certificate is None else (certificate,))
    closure = close_fixed_sources(roots, formats=formats, resolver=resolver, budget=budget)
    if closure.missing_references:
        raise ReferenceUnavailable(closure.missing_references[0])
    if closure.reasons:
        raise InputRefused(closure.reasons[0])
    return ValidationReceiptSources(envelope, statement, certificate, closure)
