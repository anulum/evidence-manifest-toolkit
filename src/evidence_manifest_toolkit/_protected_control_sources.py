# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole independently selected protected control sources

"""Acquire actual protected control selections without manufacturing an accepted state."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._budget import ReferenceBudget
from ._closure import ClosureResult, ClosureRoot
from ._codecs import decode_reference
from ._context_sources import ContextSource, acquire_context_source
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import (
    FixedSource,
    acquire_fixed_source,
    close_fixed_sources,
    native_format_lookup,
)
from ._immutable import FrozenJson, thaw_json
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._policy_source import parse_policy_source
from ._protected_certificate_issuers import check_protected_certificate_issuers
from ._protected_certificate_keys import check_protected_certificate_keys
from ._protected_certificate_sources import acquire_protected_certificate_sources
from ._protected_control_bindings import ProtectedControlBinding, bind_protected_controls
from ._protected_control_target_bounds import check_protected_control_targets
from ._protected_revocation_sources import acquire_protected_revocation_sources
from ._protected_rotation_keys import check_protected_rotation_keys
from ._protected_rotation_sources import acquire_protected_rotation_sources
from ._protected_state_sources import ProtectedStateSources, acquire_protected_state_sources
from ._subject_formats import SubjectFormat
from ._successor_trust import DelegatedTrustContextV2
from ._values import BlobRef, Digest, Reason


@dataclass(frozen=True, slots=True)
class ProtectedControlSources:
    """Retain the entire selected rule, earlier base and actual receipt correspondence.

    Attributes
    ----------
    rule, selection : FixedSource
        Whole original r6 private sources, without an invented public schema identifier.
    base : ContextSource
        Complete earlier ordinary B with its original explicit null Clock slot.
    bindings : tuple of ProtectedControlBinding
        Whole expected and actual target/statement/receipt pairs, not admitted transitions.
    state_sources : ProtectedStateSources
        Entire independently selected root/grant/current/archive history and original
        current floor. Necessary source consistency supplies no authenticated state.
    certificates : tuple of FixedSource
        Entire native parents rooted in the exact selected grant, with their whole
        source bounds checked. No admitted issuer follows from source consistency.
    revocations : tuple of FixedSource
        Whole withdrawal targets and their earlier histories, with ordered additive
        revocations and unchanged non-withdrawal state. No withdrawal authority is admitted.
    rotations : tuple of FixedSource
        Complete rotation chains and earlier authorising snapshots, retaining actual
        declared issuer continuity without accepting a controller, key or transition.
    closure : ClosureResult
        Complete required graph under the SAME invocation budget. Matching grants no
        protected root/custody/state/native-signature/time or current eligibility.
    """

    rule: FixedSource
    selection: FixedSource
    base: ContextSource
    bindings: tuple[ProtectedControlBinding, ...]
    state_sources: ProtectedStateSources
    certificates: tuple[FixedSource, ...]
    revocations: tuple[FixedSource, ...]
    rotations: tuple[FixedSource, ...]
    closure: ClosureResult

    @property
    def roots(self) -> tuple[FixedSource, ...]:
        """Return every whole known selected root for the original complete Clock closure.

        Returns
        -------
        tuple of FixedSource
            Actual rule/selection followed by complete statement and target populations.
        """
        return (
            (self.rule, self.selection)
            + self.state_sources.roots
            + self.certificates
            + self.revocations
            + self.rotations
            + tuple(
                source
                for binding in self.bindings
                for source in (binding.statement, binding.target)
            )
        )


def acquire_protected_controls(
    trust: DelegatedTrustContextV2,
    *,
    policy: Mapping[str, FrozenJson],
    policy_subject: Digest,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> ProtectedControlSources:
    """Acquire the full independent r6 selection before Clock and protected state admission.

    Parameters
    ----------
    trust : DelegatedTrustContextV2
        Entire explicit caller and ordered original controls; no weaker caller invokes this.
    policy : Mapping
        Whole independently selected enclosing authority policy after complete class pairing.
    policy_subject : str
        Original enclosing policy identity for located source-selection contradictions.
    formats : Mapping
        Original caller structural lookup, with no private-format registry insertion.
    resolver : Resolver
        Sole original bounded byte source, never a helper/root/controller discovery service.
    budget : ReferenceBudget
        SAME operation quota, including every prior registry and policy source.

    Returns
    -------
    ProtectedControlSources
        All actual selected sources and necessary receipt correspondences. Empty controls
        do not waive the full independently admitted bootstrap/grant/current-state method.

    Raises
    ------
    ReferenceUnavailable
        A required original rule/selection/base/target/statement or descendant is absent.
    InputRefused
        Whole original source/schema/identity/graph/quota or a necessary exact join fails.
    ConfigurationError
        Selected ordinary B, an installed structural binding or a key source is invalid.
    """
    installed = native_format_lookup(formats, budget=budget)

    def fixed(reference: BlobRef, name: str, pointer: str) -> FixedSource:
        """Acquire a whole selected private body without hiding its original source error."""
        result = acquire_fixed_source(
            reference,
            format_name=name,
            formats=installed,
            resolver=resolver,
            budget=budget,
            subject=policy_subject,
            pointer=pointer,
        )
        if result.source.raw_bytes is None:
            raise ReferenceUnavailable(reference)
        if result.source.document is None:
            raise InputRefused(result.source.reasons[0])
        return result

    def refuse(pointer: str) -> InputRefused:
        """Keep a selected whole policy contradiction distinct from source unavailability."""
        return InputRefused(
            Reason(
                "policy_unavailable",
                policy_subject,
                None,
                pointer,
                "Protected control rule sources conflict.",
            )
        )

    rule_reference = decode_reference(
        policy["authority_rule_ref"], subject=policy_subject, pointer="/authority_rule_ref"
    )
    rule = fixed(rule_reference, "emt-protected-control-rule-source-r6", "/authority_rule_ref")
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, rule.source.document).value)
    if value["independent_root_selection_ref"] != dict(
        trust.independent_root_selection_ref.to_mapping()
    ):
        raise refuse("/trust/independent_root_selection_ref")
    if (
        value["whole_conditions_and_limitations_ref"]
        != policy["whole_conditions_and_limitations_ref"]
    ):
        raise refuse("/whole_conditions_and_limitations_ref")
    selection = fixed(
        trust.authority_control_selection_ref,
        "emt-protected-control-selection-source-r6",
        "/trust/authority_control_selection_ref",
    )
    selection_value = cast(
        dict[str, JsonValue], cast(AcquiredDocument, selection.source.document).value
    )
    if selection_value["control_rule_ref"] != dict(rule_reference.to_mapping()):
        raise refuse("/trust/authority_control_selection_ref")
    base_reference = decode_reference(
        value["whole_legacy_base_policy_ref"],
        subject=rule_reference.digest,
        pointer="/whole_legacy_base_policy_ref",
    )
    base = acquire_context_source(
        base_reference,
        expected_control=None,
        resolver=resolver,
        budget=budget,
        subject=rule_reference.digest,
        pointer="/whole_legacy_base_policy_ref",
    )
    if base.raw_bytes is None:
        raise ReferenceUnavailable(base_reference)
    if base.document is None:
        raise InputRefused(base.reasons[0])
    declaration = parse_policy_source(base.document)
    if (
        declaration.namespace != "operational"
        or not declaration.requires_clock
        or declaration.clock_reference is not None
    ):
        raise refuse("/authority_rule_ref")
    bindings = bind_protected_controls(
        selection,
        envelopes=trust.control_envelopes,
        formats=installed,
        resolver=resolver,
        budget=budget,
    )
    state_sources = acquire_protected_state_sources(
        trust,
        rule=rule,
        policy_subject=policy_subject,
        formats=installed,
        resolver=resolver,
        budget=budget,
    )
    certificates = acquire_protected_certificate_sources(
        state_sources,
        formats=installed,
        resolver=resolver,
        budget=budget,
        additional_roots=tuple(
            binding.target
            for binding in bindings
            if binding.entry["operation"] == "issue_certificate"
            and cast(
                dict[str, JsonValue], cast(AcquiredDocument, binding.target.source.document).value
            )["parent_authorization_ref"]
            == thaw_json(binding.entry["authorization_ref"])
        ),
    )
    rotations = acquire_protected_rotation_sources(
        state_sources, bindings=bindings, formats=installed, resolver=resolver, budget=budget
    )
    roots = (
        (rule, selection)
        + state_sources.roots
        + certificates
        + rotations
        + tuple(source for binding in bindings for source in (binding.statement, binding.target))
    )
    closure = close_fixed_sources(
        roots,
        formats=installed,
        resolver=resolver,
        budget=budget,
        additional_roots=(
            ClosureRoot(base_reference, base.raw_bytes),
            ClosureRoot(state_sources.root.reference, cast(bytes, state_sources.root.raw_bytes)),
        ),
    )
    if closure.missing_references:
        raise ReferenceUnavailable(closure.missing_references[0])
    if closure.reasons:
        raise InputRefused(closure.reasons[0])
    check_protected_certificate_keys(
        state_sources.grant, certificates, resolver=resolver, budget=budget
    )
    check_protected_certificate_issuers(state_sources.grant, certificates)
    check_protected_rotation_keys(bindings, sources=rotations, resolver=resolver, budget=budget)
    revocations = acquire_protected_revocation_sources(
        bindings,
        state=state_sources,
        formats=installed,
        resolver=resolver,
        budget=budget,
    )
    check_protected_control_targets(bindings, root_selection=state_sources.root.reference)
    return ProtectedControlSources(
        rule,
        selection,
        base,
        bindings,
        state_sources,
        certificates,
        revocations,
        rotations,
        closure,
    )
