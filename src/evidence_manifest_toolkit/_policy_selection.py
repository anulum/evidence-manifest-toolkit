# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole independent policy and caller pairing

"""Pair complete caller-selected policies before acquiring stronger authority sources."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._budget import ReferenceBudget
from ._clock_sources import ClockSources, acquire_clock_sources
from ._codecs import decode_reference
from ._context_sources import ContextSource, acquire_context_source
from ._errors import ConfigurationError, InputRefused, ReferenceUnavailable
from ._format_sources import validate_fixed_source
from ._immutable import FrozenJson, freeze_json
from ._interfaces import Resolver
from ._invocation_wire import CallerTrust, SuccessorTrust
from ._json import AcquiredDocument, JsonValue
from ._method_rule_sources import MethodRuleSources, acquire_method_rule_sources
from ._policy_source import PolicyDeclaration, parse_policy_source
from ._protected_control_sources import ProtectedControlSources, acquire_protected_controls
from ._protected_ordinary_sources import (
    PreparedProtectedSources,
    acquire_protected_ordinary_sources,
)
from ._registry_types import SchemaRegistry
from ._schema_resources import StaticSchema
from ._software_sources import SoftwareSources, acquire_software_sources
from ._successor_format_bindings import FORMAT_BINDINGS
from ._successor_trust import (
    DelegatedTrustContextV2,
    SoftwareTrustContextV2,
    UnsignedTrustContextV2,
)
from ._trust_types import TrustContext, VerificationPolicy
from ._values import Digest, Reason

_SUCCESSOR_POLICY = "evidence_manifest_toolkit.authority_policy.v2"


@dataclass(frozen=True, slots=True)
class PolicySelection:
    """Retain both entire source policies without conferring authority or qualification.

    Attributes
    ----------
    source : ContextSource
        Original independent policy argument and all actual acquired bytes or refusals.
    artifact_source : ContextSource
        Whole ordinary invocation policy P, equal to source for the legacy route.
    declaration : PolicyDeclaration or None
        Entire ordinary policy requirements; absent when its source is unavailable.
    successor : Mapping or None
        All fourteen immutable successor fields, or absent for the original route.
        Neither matching class nor structural validity supplies an accepted Clock or key.
    clock_sources : ClockSources or None
        Entire independently selected successor Clock acquisition, configuration and
        closure. Source joins, actual entry and physical predicates remain separate.
    software_sources : SoftwareSources or None
        Entire selected software stream/floor/archive/key-source initialization before
        Clock acquisition. Absent for unsigned/legacy/delegated; not signing authority.
    method_rules : MethodRuleSources or None
        Complete identity/validation and optional foreign source selection and closure,
        checked before Clock. Absent for legacy, without granting native source authority.
    protected_sources : ProtectedControlSources or None
        Whole independently selected r6 rule and ordered control correspondence, only
        for an explicitly delegated caller. Matching supplies no accepted protected state.
    protected_statements : PreparedProtectedSources or None
        One actual C0 preparation and complete ordinary receipt source matches, only
        for a nonempty delegated population. No signature or class is admitted.
    """

    source: ContextSource
    artifact_source: ContextSource
    declaration: PolicyDeclaration | None
    successor: Mapping[str, FrozenJson] | None
    clock_sources: ClockSources | None = None
    software_sources: SoftwareSources | None = None
    method_rules: MethodRuleSources | None = None
    protected_sources: ProtectedControlSources | None = None
    protected_statements: PreparedProtectedSources | None = None


def _refusal(subject: Digest, pointer: str) -> ConfigurationError:
    """Locate a whole policy configuration refusal without echoing received data.

    Parameters
    ----------
    subject : str
        Actual independently selected policy identity.
    pointer : str
        Literal field position within the selected source or caller configuration.

    Returns
    -------
    ConfigurationError
        Full fixed five-field configuration diagnostic.
    """
    return ConfigurationError(
        Reason(
            "configuration_error",
            subject,
            None,
            pointer,
            "Invalid local trust or policy configuration.",
        )
    )


def _pair_successor(
    document: AcquiredDocument,
    *,
    policy: VerificationPolicy,
    trust: SuccessorTrust,
    envelopes: tuple[bytes, ...],
    registry: SchemaRegistry,
) -> Mapping[str, FrozenJson]:
    """Pair the whole validated native policy and independent class before stronger acquisition.

    Parameters
    ----------
    document : AcquiredDocument
        Complete identity-matching authority policy after whole fixed-format validation.
    policy : VerificationPolicy
        Entire original caller scope and selected policy reference.
    trust : successor context
        Independent frozen caller class, never inferred from missing authority.
    envelopes : tuple of bytes
        Whole actual ordered ordinary receipt population.
    registry : SchemaRegistry
        Original caller cohort, without fixed native/private entries inserted into it.

    Returns
    -------
    Mapping
        Entire immutable fourteen-field successor declaration after pairing only.

    Raises
    ------
    ConfigurationError
        Source shape, metadata, caller class, purposes, receipt class or cohort conflicts.
    """
    subject = policy.policy_ref.digest
    value = cast(dict[str, JsonValue], document.value)
    if value["profile_class"] != trust.profile_class:
        raise _refusal(subject, "/profile_class")
    if any(
        purpose not in ("evidence", "deployment", "human_review")
        for purpose in policy.required_purposes
    ):
        raise _refusal(subject, "/required_purposes")
    if isinstance(trust, UnsignedTrustContextV2) and envelopes:
        raise _refusal(subject, "/envelopes")
    if any(entry.schema_id in FORMAT_BINDINGS for entry in registry.entries):
        raise _refusal(subject, "/registry/entries")
    if isinstance(trust, DelegatedTrustContextV2):
        grant = decode_reference(
            value["root_grant_ref"], subject=subject, pointer="/root_grant_ref"
        )
        if grant != trust.root_grant_ref:
            raise _refusal(subject, "/root_grant_ref")
    return cast(Mapping[str, FrozenJson], freeze_json(document.value))


def acquire_policy_selection(
    policy: VerificationPolicy,
    *,
    content_json: bytes,
    schema_id: str,
    trust: CallerTrust,
    envelopes: tuple[bytes, ...],
    registry: SchemaRegistry,
    schemas: Mapping[str, StaticSchema],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> PolicySelection:
    """Acquire and pair whole original or successor policy without initializing authority.

    Parameters
    ----------
    policy : VerificationPolicy
        Validated original caller policy reference, claims, purposes and selectors.
    content_json, schema_id : bytes, str
        Whole actual operation subject and independently selected schema, prepared once
        only for a nonempty protected ordinary population before its Clock acquisition.
    trust : TrustContext or successor context
        Independent caller selection; no downgrade or fabricated v1 root is permitted.
    envelopes : tuple of bytes
        All actual ordinary receipts, preserved in caller order.
    registry : SchemaRegistry
        Original complete independently validated caller catalogue.
    schemas : Mapping
        Complete independently validated caller structural dispatch, without inserted formats.
    resolver : Resolver
        Caller-owned bounded source for exact whole policy bytes and referenced P.
    budget : ReferenceBudget
        Sole cumulative budget including fixed schema resources and every selected policy.

    Returns
    -------
    PolicySelection
        Whole original reference, whole ordinary P and complete parsed declaration.
        Source absence stays absence. A matching successor retains the entire selected
        Clock/configuration closure, including referenced declarations. Acquisition
        authenticates no root, table, grant, snapshot, control rule or Clock fact.

    Raises
    ------
    ConfigurationError
        Whole source grammar, class pairing or required claim/purpose populations conflict.
    InputRefused
        Actual shared source acquisition or format validation exceeds operation bounds.
    """
    source = acquire_context_source(
        policy.policy_ref,
        expected_control=None,
        resolver=resolver,
        budget=budget,
        subject=policy.policy_ref.digest,
        pointer="/policy_ref",
    )
    document = source.document
    if document is None:
        if not isinstance(trust, TrustContext):
            if source.raw_bytes is None:
                raise ReferenceUnavailable(source.reference)
            raise InputRefused(source.reasons[0])
        return PolicySelection(source, source, None, None)
    value = cast(dict[str, JsonValue], document.value)
    successor = None
    successor_trust: SuccessorTrust | None = None
    artifact_source = source
    if (
        policy.policy_ref.schema_id == _SUCCESSOR_POLICY
        or value.get("schema_id") == _SUCCESSOR_POLICY
    ):
        checked = validate_fixed_source(
            source,
            format_name=_SUCCESSOR_POLICY,
            formats=schemas,
            budget=budget,
            subject=policy.policy_ref.digest,
            pointer="/policy_ref",
        )
        if checked.source.reasons:
            raise _refusal(policy.policy_ref.digest, checked.source.reasons[0].pointer or "")
        source = checked.source
        if isinstance(trust, TrustContext):
            raise _refusal(policy.policy_ref.digest, "/trust")
        successor_trust = trust
        successor = _pair_successor(
            document,
            policy=policy,
            trust=trust,
            envelopes=envelopes,
            registry=registry,
        )
        reference = decode_reference(
            value["whole_legacy_artifact_policy_ref"],
            subject=policy.policy_ref.digest,
            pointer="/whole_legacy_artifact_policy_ref",
        )
        artifact_source = acquire_context_source(
            reference,
            expected_control=None,
            resolver=resolver,
            budget=budget,
            subject=policy.policy_ref.digest,
            pointer="/whole_legacy_artifact_policy_ref",
        )
        if artifact_source.document is None:
            if artifact_source.raw_bytes is None:
                raise ReferenceUnavailable(artifact_source.reference)
            raise InputRefused(artifact_source.reasons[0])
    elif not isinstance(trust, TrustContext):
        raise _refusal(policy.policy_ref.digest, "/policy_ref")
    declaration = (
        None if artifact_source.document is None else parse_policy_source(artifact_source.document)
    )
    if (
        successor_trust is not None
        and declaration is not None
        and (declaration.namespace != "operational" or not declaration.requires_clock)
    ):
        raise _refusal(policy.policy_ref.digest, "/whole_legacy_artifact_policy_ref")
    if declaration is not None:
        for name, actual, expected in (
            ("required_claim_ids", declaration.required_claim_ids, policy.required_claim_ids),
            ("required_purposes", declaration.required_purposes, policy.required_purposes),
        ):
            if actual != expected:
                raise _refusal(policy.policy_ref.digest, "/" + name)
    software_sources = (
        acquire_software_sources(
            successor_trust,
            authority_rule_reference=decode_reference(
                value["authority_rule_ref"],
                subject=policy.policy_ref.digest,
                pointer="/authority_rule_ref",
            ),
            policy_subject=policy.policy_ref.digest,
            formats=schemas,
            resolver=resolver,
            budget=budget,
        )
        if isinstance(successor_trust, SoftwareTrustContextV2)
        else None
    )
    method_rules = (
        acquire_method_rule_sources(
            successor,
            policy_subject=policy.policy_ref.digest,
            formats=schemas,
            resolver=resolver,
            budget=budget,
        )
        if successor is not None
        else None
    )
    protected_sources = (
        acquire_protected_controls(
            successor_trust,
            policy=cast(Mapping[str, FrozenJson], successor),
            policy_subject=policy.policy_ref.digest,
            formats=schemas,
            resolver=resolver,
            budget=budget,
        )
        if isinstance(successor_trust, DelegatedTrustContextV2)
        else None
    )
    protected_statements = (
        acquire_protected_ordinary_sources(
            content_json,
            schema_id=schema_id,
            envelopes=envelopes,
            protected=protected_sources,
            declaration=declaration,
            evaluation_time=trust.evaluation_time,
            policy=policy,
            schemas=schemas,
            resolver=resolver,
            budget=budget,
        )
        if protected_sources is not None and declaration is not None and envelopes
        else None
    )
    clock_sources = (
        acquire_clock_sources(
            trust=successor_trust,
            policy_reference=policy.policy_ref,
            declaration=declaration,
            formats=schemas,
            resolver=resolver,
            budget=budget,
            class_sources=(
                tuple(
                    table.fixed
                    for table in (*software_sources.history, *software_sources.selected_history)
                )
                if software_sources is not None
                else ()
            )
            + (() if method_rules is None else method_rules.roots)
            + (() if protected_sources is None else protected_sources.roots)
            + (() if protected_statements is None else protected_statements.roots),
        )
        if successor_trust is not None and declaration is not None
        else None
    )
    return PolicySelection(
        source,
        artifact_source,
        declaration,
        successor,
        clock_sources,
        software_sources,
        method_rules,
        protected_sources,
        protected_statements,
    )
