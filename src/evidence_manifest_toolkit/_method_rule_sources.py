# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole independently selected native method rule sources

"""Acquire complete identity, validation and optional foreign rules without granting trust."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._budget import ReferenceBudget
from ._closure import ClosureResult
from ._codecs import decode_reference, reference_value
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import (
    FixedSource,
    acquire_fixed_source,
    native_format_lookup,
)
from ._immutable import FrozenJson
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._native_rule_bindings import NativeRuleBindings, acquire_native_rule_bindings
from ._subject_formats import SubjectFormat
from ._values import Digest, Reason


@dataclass(frozen=True, slots=True)
class MethodRuleSources:
    """Keep every whole selected rule and all its actual source observations.

    Attributes
    ----------
    identity, validation : FixedSource
        Entire original identity/validation references, bytes and bounded parsed bodies.
    foreign : FixedSource or None
        Entire independently selected foreign rule, absent only when not selected.
        No foreign helper, root refresh, network operation or authority is initialized.
    closure : ClosureResult
        Complete independently selected rule graph under the SAME invocation budget.
        Structural/class/reference consistency does not qualify any source predicate.
    native_bindings : NativeRuleBindings
        Four whole independently selected native declarations and the SAME complete
        connected rule graph; their presence supplies no native method acceptance.
    """

    identity: FixedSource
    validation: FixedSource
    foreign: FixedSource | None
    closure: ClosureResult
    native_bindings: NativeRuleBindings

    @property
    def roots(self) -> tuple[FixedSource, ...]:
        """Return every entire selected rule without inventing an absent foreign source.

        Returns
        -------
        tuple of FixedSource
            Actual identity/validation, optional foreign and four native declaration roots.
            Their fixed formats remain present along every parent-to-descendant path.
        """
        return (
            (self.identity, self.validation)
            + (() if self.foreign is None else (self.foreign,))
            + self.native_bindings.roots
        )


def acquire_method_rule_sources(
    policy: Mapping[str, FrozenJson],
    *,
    policy_subject: Digest,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> MethodRuleSources:
    """Read complete selected private method rules before Clock or native admission.

    Parameters
    ----------
    policy : Mapping
        Whole structurally valid independently selected authority policy, already paired
        with the explicit caller class. No received artifact selects a verifier.
    policy_subject : str
        Actual enclosing policy identity for original located join refusals.
    formats : Mapping
        Whole original caller structural lookup; private tokens are never registered.
    resolver : Resolver
        Sole bounded source for the actual original references.
    budget : ReferenceBudget
        SAME operation quota including fixed definitions and every earlier class source.

    Returns
    -------
    MethodRuleSources
        Whole syntax/class/reference-checked bodies and complete closure, preserving
        unqualified launcher, key, comparison, hosted and source-rule obligations.

    Raises
    ------
    ReferenceUnavailable
        A required whole selected rule is absent, retaining its exact original reference.
    InputRefused
        Original source/schema/metadata/quota failure or class/identity-rule/foreign pair
        conflict. Such failures never become an approval or a weaker class selection.
    """
    installed = native_format_lookup(formats, budget=budget)

    def acquire(field: str, format_name: str) -> FixedSource:
        """Retain one actual complete fixed private source and its original errors.

        Parameters
        ----------
        field : str
            Original exact enclosing policy field.
        format_name : str
            Known installed private definition selected by this fixed owning method.

        Returns
        -------
        FixedSource
            Complete validated body, with every original opaque procedure reference kept.

        Raises
        ------
        ReferenceUnavailable
            The actual required original argument is absent.
        InputRefused
            Whole source, metadata or fixed-schema validation fails.
        """
        reference = decode_reference(policy[field], subject=policy_subject, pointer="/" + field)
        fixed = acquire_fixed_source(
            reference,
            format_name=format_name,
            formats=installed,
            resolver=resolver,
            budget=budget,
            subject=policy_subject,
            pointer="/" + field,
        )
        if fixed.source.raw_bytes is None:
            raise ReferenceUnavailable(reference)
        if fixed.source.document is None:
            raise InputRefused(fixed.source.reasons[0])
        return fixed

    def refuse(field: str) -> InputRefused:
        """Locate an actual complete rule-selection join without echoing source text.

        Parameters
        ----------
        field : str
            Exact affected policy field.

        Returns
        -------
        InputRefused
            Original whole policy identity and fixed safe method-rule diagnostic.
        """
        return InputRefused(
            Reason(
                "policy_unavailable",
                policy_subject,
                None,
                "/" + field,
                "Selected method rule sources conflict.",
            )
        )

    identity = acquire("identity_rule_ref", "emt-seat-identity-rule-source-r1")
    validation = acquire("validation_rule_ref", "emt-independent-validation-rule-source-r1")
    identity_value = cast(
        dict[str, JsonValue], cast(AcquiredDocument, identity.source.document).value
    )
    validation_value = cast(
        dict[str, JsonValue], cast(AcquiredDocument, validation.source.document).value
    )
    if identity_value["custody_class"] != policy["profile_class"]:
        raise refuse("identity_rule_ref")
    if policy["minimum_identity_class"] not in cast(
        list[str], identity_value["permitted_identity_classes"]
    ):
        raise refuse("minimum_identity_class")
    if validation_value["profile_class"] != policy["profile_class"] or (
        validation_value["independent_identity_policy_ref"]
        != reference_value(identity.source.reference)
    ):
        raise refuse("validation_rule_ref")
    if not set(cast(tuple[str, ...], policy["allowed_nonuse_classes"])).intersection(
        cast(list[str], validation_value["required_nonuse_classes"])
    ):
        raise refuse("allowed_nonuse_classes")
    foreign_selected = policy["foreign_rule_ref"] is not None
    if foreign_selected != (policy["independent_foreign_trust_ref"] is not None):
        raise refuse("independent_foreign_trust_ref")
    foreign = (
        acquire("foreign_rule_ref", "emt-foreign-github-identity-rule-source-r1")
        if foreign_selected
        else None
    )
    native_bindings = acquire_native_rule_bindings(
        identity,
        validation,
        other_rules=() if foreign is None else (foreign,),
        formats=installed,
        resolver=resolver,
        budget=budget,
    )
    return MethodRuleSources(
        identity, validation, foreign, native_bindings.closure, native_bindings
    )
