# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete explicitly selected Clock source graph

"""Acquire every whole Clock configuration under the existing invocation budget."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import cast

from ._budget import ReferenceBudget
from ._clock_values import clock_unavailable
from ._closure import ClosureResult, ClosureRoot
from ._codecs import decode_reference
from ._context_sources import ContextSource, acquire_context_source
from ._format_sources import (
    FixedSource,
    acquire_fixed_source,
    close_fixed_sources,
    native_format_lookup,
)
from ._immutable import thaw_json
from ._interfaces import Resolver
from ._invocation_wire import SuccessorTrust
from ._json import AcquiredDocument, JsonValue
from ._policy_literals import CLOCK_FIELD
from ._policy_source import PolicyDeclaration
from ._subject_formats import SubjectFormat
from ._values import BlobRef, Reason


@dataclass(frozen=True, slots=True)
class ClockSources:
    """Retain complete selected sources and their original bounded closure.

    Attributes
    ----------
    fixed : Mapping
        Actual acquired witness, independent first sample/profile, subject, acceptance
        and whole caller context. A missing earlier object supplies no invented child.
    configurations : Mapping
        Whole earlier base policy, original registry configuration and all six Limits.
    documents : Mapping
        Every actual valid whole document, retaining original raw bytes and numeric
        tokens. Invalid or missing sources are absent and retain their actual reasons.
    closure : ClosureResult
        All selected fixed/configuration roots, original edges and actual failures.
    reasons : tuple of Reason
        Whole acquisition/closure failures, or the original missing Clock requirement.
        Empty reasons establish no sampler, source, authority, identity or Clock verdict.
    """

    fixed: Mapping[str, FixedSource]
    configurations: Mapping[str, ContextSource]
    documents: Mapping[str, AcquiredDocument]
    closure: ClosureResult
    reasons: tuple[Reason, ...]


def _reference(reference: BlobRef, document: AcquiredDocument, name: str) -> BlobRef:
    """Decode an actual field only after its whole selected source has passed validation.

    Parameters
    ----------
    reference : BlobRef
        Entire acquired source identity.
    document : AcquiredDocument
        Whole identity-matching fixed-format object after structural validation.
    name : str
        Exact independently selected required reference field.

    Returns
    -------
    BlobRef
        All original field values; absent optional schema metadata stays absent.
    """
    value = cast(dict[str, JsonValue], document.value)
    return decode_reference(value[name], subject=reference.digest, pointer="/" + name)


def acquire_clock_sources(
    *,
    trust: SuccessorTrust,
    policy_reference: BlobRef,
    declaration: PolicyDeclaration,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
    class_sources: tuple[FixedSource, ...],
) -> ClockSources:
    """Read the complete independently selected Clock graph without qualifying its facts.

    Parameters
    ----------
    trust : successor context
        Complete frozen caller class and its independent first-sample/profile selections.
    policy_reference : BlobRef
        Whole independently selected enclosing policy, used for the original Clock diagnostic.
    declaration : PolicyDeclaration
        Entire parsed final ordinary policy, retaining its actual Clock reference or absence.
    formats : Mapping
        Original independently validated caller schemas, without invented fixed entries.
    resolver : Resolver
        Sole bounded offline source, without hidden receipt/source discovery.
    budget : ReferenceBudget
        Existing cumulative operation budget, reused for every object and fixed resource.
    class_sources : tuple of FixedSource
        Complete already selected class/history roots. Their known private bindings join
        context edges in this same closure; source reads are cached, never edge-deduplicated.

    Returns
    -------
    ClockSources
        Whole selected sources, configuration roots and complete closure. Unavailable
        parents prevent child selection; check/result labels confer no acceptance.

    Raises
    ------
    ConfigurationError
        Local source binding/resolver configuration is invalid or collides with a fixed format.
    InputRefused
        A real shared bound, metadata conflict or malformed declared reference is encountered.
    """
    fixed: dict[str, FixedSource] = {}
    configurations: dict[str, ContextSource] = {}
    formats = native_format_lookup(formats, budget=budget)
    missing_clock: tuple[Reason, ...] = ()
    pointer = "/" + CLOCK_FIELD + "/clock_qualification_ref"
    witness_ref = declaration.clock_reference
    if witness_ref is None:
        missing_clock = (clock_unavailable(policy_reference.digest, pointer).reason,)
    else:
        fixed["witness"] = acquire_fixed_source(
            witness_ref,
            format_name="autonomous-evaluation-clock-witness-source-r4",
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=policy_reference.digest,
            pointer=pointer,
        )
        binding = cast(dict[str, JsonValue], thaw_json(trust.clock_entry_binding))
        for name, field, format_name in (
            (
                "first_sample",
                "first_sample_source_ref",
                "autonomous-evaluation-clock-first-sample-source-r4",
            ),
            ("profile", "source_profile_ref", "autonomous-evaluation-clock-profile-source-r4"),
        ):
            reference = decode_reference(
                binding[field],
                subject=policy_reference.digest,
                pointer="/trust/clock_entry_binding/" + field,
            )
            fixed[name] = acquire_fixed_source(
                reference,
                format_name=format_name,
                formats=formats,
                resolver=resolver,
                budget=budget,
                subject=policy_reference.digest,
                pointer="/trust/clock_entry_binding/" + field,
            )
        witness = fixed["witness"].source
        if witness.document is not None:
            for name, field, format_name in (
                ("subject", "subject_ref", "autonomous-evaluation-clock-subject-source-r4"),
                (
                    "acceptance",
                    "acceptance_body_ref",
                    "autonomous-evaluation-clock-acceptance-source-r4",
                ),
            ):
                fixed[name] = acquire_fixed_source(
                    _reference(witness.reference, witness.document, field),
                    format_name=format_name,
                    formats=formats,
                    resolver=resolver,
                    budget=budget,
                    subject=witness.reference.digest,
                    pointer="/" + field,
                )
            subject = fixed["subject"].source
            if subject.document is not None:
                fixed["context"] = acquire_fixed_source(
                    _reference(subject.reference, subject.document, "whole_trust_context_ref"),
                    format_name=trust.namespace,
                    formats=formats,
                    resolver=resolver,
                    budget=budget,
                    subject=subject.reference.digest,
                    pointer="/whole_trust_context_ref",
                )
                for name, field in (
                    ("base_policy", "whole_base_policy_ref"),
                    ("registry", "schema_registry_ref"),
                    ("limits", "whole_limits_ref"),
                ):
                    configurations[name] = acquire_context_source(
                        _reference(subject.reference, subject.document, field),
                        expected_control=None,
                        resolver=resolver,
                        budget=budget,
                        subject=subject.reference.digest,
                        pointer="/" + field,
                    )
    roots = tuple(
        ClosureRoot(source.reference, source.raw_bytes)
        for source in configurations.values()
        if source.document is not None and source.raw_bytes is not None
    )
    closure = close_fixed_sources(
        (*class_sources, *fixed.values()),
        formats=formats,
        resolver=resolver,
        budget=budget,
        additional_roots=roots,
    )
    closure = replace(
        closure,
        reasons=tuple(reason for source in configurations.values() for reason in source.reasons)
        + closure.reasons,
        missing_references=tuple(
            source.reference for source in configurations.values() if source.raw_bytes is None
        )
        + closure.missing_references,
    )
    contexts = {name: item.source for name, item in fixed.items()} | configurations
    documents = {
        name: source.document for name, source in contexts.items() if source.document is not None
    }
    return ClockSources(
        MappingProxyType(fixed),
        MappingProxyType(configurations),
        MappingProxyType(documents),
        closure,
        missing_clock + closure.reasons,
    )
