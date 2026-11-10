# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole independently selected signature-obligation source

"""Bind complete signature rule sources and exact unsigned scope under the original budget."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import cast

from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._content import CompleteContent
from ._context_sources import ContextSource, acquire_context_source
from ._errors import InputRefused, ReferenceUnavailable
from ._immutable import FrozenJson, freeze_json, thaw_json
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._policy_literals import CLOCK_FIELD
from ._policy_source import parse_policy_source
from ._signature_rule_values import (
    EXCEPTION_FIELDS,
    RULE_FIELDS,
    check_rule_header,
    rule_configuration_refusal,
    rule_object,
    rule_population,
    rule_references,
)
from ._trust_types import VerificationPolicy
from ._values import BlobRef, Digest, Reason


@dataclass(frozen=True, slots=True)
class SignatureRuleSource:
    """Retain the entire selected method and every actual original source.

    Attributes
    ----------
    source, base_policy, conditions : ContextSource
        Complete identity-matching raw rule, earlier policy and limitations sources.
    provenance : tuple of ContextSource
        Every independently selected whole provenance body, in original order.
    declaration : Mapping
        Entire immutable closed method record. Scope/source consistency supplies no
        physical Clock, authority, waiver application or current eligibility verdict.
    """

    source: ContextSource
    base_policy: ContextSource
    conditions: ContextSource
    provenance: tuple[ContextSource, ...]
    declaration: Mapping[str, FrozenJson]


def _conflict(subject: Digest, pointer: str) -> InputRefused:
    """Locate a complete rule/source/scope conflict without echoing artifact content.

    Parameters
    ----------
    subject : str
        Actual whole acquired raw rule identity.
    pointer : str
        Actual affected rule field.

    Returns
    -------
    InputRefused
        Original policy-unavailable reason, without fabricated signature or root failure.
    """
    return InputRefused(
        Reason(
            "policy_unavailable", subject, None, pointer, "Signature-obligation sources conflict."
        )
    )


def _source(
    reference: BlobRef,
    *,
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> ContextSource:
    """Acquire one complete JSON source with its original metadata and typed failures.

    Parameters
    ----------
    reference : BlobRef
        Original full reference, with no inferred schema metadata.
    resolver : Resolver
        Sole explicit bounded source.
    budget : ReferenceBudget
        SAME cumulative invocation budget.
    subject : str
        Actual containing source identity.
    pointer : str
        Actual containing reference position.

    Returns
    -------
    ContextSource
        Whole matching source after strict JSON acquisition, without authenticating it.

    Raises
    ------
    ConfigurationError
        The explicit resolver configuration is invalid.
    ReferenceUnavailable
        The exact original selected reference is absent.
    InputRefused
        Original malformed JSON, identity, metadata or quota check fails.
    """
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
    return source


def acquire_signature_rule(
    successor: Mapping[str, FrozenJson],
    *,
    policy: VerificationPolicy,
    final_policy: AcquiredDocument,
    base_policy_reference: BlobRef,
    content: CompleteContent,
    resolver: Resolver,
    budget: ReferenceBudget,
) -> SignatureRuleSource:
    """Bind the fixed whole rule, original policy and actual exact exception scope.

    Parameters
    ----------
    successor : Mapping
        Whole independently selected and class-paired authority policy.
    policy : VerificationPolicy
        Complete original claim, purpose and required-reference selection.
    final_policy : AcquiredDocument
        Entire ordinary final policy P, with no omitted source members.
    base_policy_reference : BlobRef
        Exact whole earlier policy selected by the matching frozen Clock subject.
        Equal JSON under a different raw identity or one-sided basis does not match.
    content : CompleteContent
        Whole actual prepared content and every native claim obligation.
    resolver : Resolver
        Actual original offline source; no hidden code/provider discovery.
    budget : ReferenceBudget
        SAME operation budget including all prior schemas, sources and receipts.

    Returns
    -------
    SignatureRuleSource
        Full immutable source/scope bindings. A null exception waives nothing, and a
        scoped exception still needs complete class/Clock/runtime admission before use.

    Raises
    ------
    ConfigurationError
        Closed raw grammar, source metadata, method or original policy is invalid.
    ReferenceUnavailable
        An actual whole selected raw source is absent.
    InputRefused
        A real source/identity/quota/UTC or full scope/policy/class join fails.
    """
    subject = policy.policy_ref.digest
    pointer = "/signature_obligation_rule_ref"
    reference = decode_reference(
        thaw_json(successor["signature_obligation_rule_ref"]), subject=subject, pointer=pointer
    )
    if (
        reference.media_type != "application/json"
        or reference.digest_basis != "raw_bytes"
        or reference.schema_id is not None
    ):
        raise rule_configuration_refusal(subject, pointer)
    source = _source(reference, resolver=resolver, budget=budget, subject=subject, pointer=pointer)
    value = rule_object(
        cast(AcquiredDocument, source.document).value,
        RULE_FIELDS,
        subject=reference.digest,
        pointer="",
    )
    check_rule_header(value, subject=reference.digest)
    for field, expected in (
        ("profile_class", successor["profile_class"]),
        ("required_claim_ids", list(policy.required_claim_ids)),
        ("required_purposes", list(policy.required_purposes)),
        ("required_reference_paths", [asdict(item) for item in policy.required_reference_paths]),
        (
            "whole_conditions_and_limitations_ref",
            thaw_json(successor["whole_conditions_and_limitations_ref"]),
        ),
    ):
        if value[field] != expected:
            raise _conflict(reference.digest, "/" + field)
    sources = {
        field: _source(
            decode_reference(value[field], subject=reference.digest, pointer="/" + field),
            resolver=resolver,
            budget=budget,
            subject=reference.digest,
            pointer="/" + field,
        )
        for field in ("whole_base_policy_ref", "whole_conditions_and_limitations_ref")
    }
    base = cast(AcquiredDocument, sources["whole_base_policy_ref"].document)
    declaration = parse_policy_source(base)
    if (
        declaration.namespace != "operational"
        or not declaration.requires_clock
        or declaration.clock_reference is not None
    ):
        raise _conflict(reference.digest, "/whole_base_policy_ref")
    reconstructed = cast(
        dict[str, JsonValue], thaw_json(parse_policy_source(final_policy).declaration)
    )
    clock = cast(dict[str, JsonValue], reconstructed[CLOCK_FIELD])
    clock["clock_qualification_ref"] = None
    if reconstructed != base.value:
        raise _conflict(reference.digest, "/whole_base_policy_ref")
    if sources["whole_base_policy_ref"].reference != base_policy_reference:
        raise _conflict(reference.digest, "/whole_base_policy_ref")
    provenance_refs = rule_references(
        value["provenance_refs"], subject=reference.digest, pointer="/provenance_refs"
    )
    if not provenance_refs:
        raise rule_configuration_refusal(reference.digest, "/provenance_refs")
    provenance = tuple(
        _source(
            ref,
            resolver=resolver,
            budget=budget,
            subject=reference.digest,
            pointer="/provenance_refs/" + str(index),
        )
        for index, ref in enumerate(provenance_refs)
    )
    exception = value["unsigned_exception"]
    if exception is not None:
        scoped = rule_object(
            exception, EXCEPTION_FIELDS, subject=reference.digest, pointer="/unsigned_exception"
        )
        if value["profile_class"] != "unsigned_declared":
            raise _conflict(reference.digest, "/unsigned_exception")
        actual_content = decode_reference(
            scoped["content_ref"],
            subject=reference.digest,
            pointer="/unsigned_exception/content_ref",
        )
        claims = rule_population(
            scoped["claim_ids"], subject=reference.digest, pointer="/unsigned_exception/claim_ids"
        )
        purposes = rule_population(
            scoped["purposes"], subject=reference.digest, pointer="/unsigned_exception/purposes"
        )
        records = rule_references(
            scoped["validation_record_refs"],
            subject=reference.digest,
            pointer="/unsigned_exception/validation_record_refs",
        )
        obligations = content.content_claim_obligations
        if (
            actual_content != content.content_ref
            or not set(claims) <= {item.claim_id for item in obligations}
            or not set(purposes) <= set(policy.required_purposes)
            or not set(records)
            <= {item.validation_record for item in obligations if item.claim_id in claims}
        ):
            raise _conflict(reference.digest, "/unsigned_exception")
    return SignatureRuleSource(
        source,
        sources["whole_base_policy_ref"],
        sources["whole_conditions_and_limitations_ref"],
        provenance,
        cast(Mapping[str, FrozenJson], freeze_json(value)),
    )
