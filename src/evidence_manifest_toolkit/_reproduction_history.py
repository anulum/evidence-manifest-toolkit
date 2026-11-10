# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — entire causal independent-validation parent history

"""Retain and reconstruct whole earlier parent chains under one original source budget."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import cast

from ._acquisition import acquire_reference
from ._budget import ByteIdentity, ReferenceBudget
from ._closure import ClosureResult, ClosureRoot
from ._codecs import decode_reference
from ._content import CompleteContent
from ._context_sources import ContextSource
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource, close_fixed_sources
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._reproduction_record_relations import ReproductionRecordSources
from ._reproduction_source_graph import acquire_reproduction_source
from ._reproduction_subjects import (
    ReproductionSubject,
    prepare_reproduction_subject,
    reproduction_common_semantics,
)
from ._reproduction_transitions import ReproductionTransition, reproduction_transition_matches
from ._subject_formats import SubjectFormat
from ._values import BlobRef, Reason


@dataclass(frozen=True, slots=True)
class ReproductionHistory:
    """Keep the entire actual causal graph and corresponding whole parent transitions.

    Attributes
    ----------
    subjects : tuple of ReproductionSubject
        Every actual current/earlier whole parent manifest and original source reference.
    records : tuple of ReproductionRecordSources
        Whole actual package occurrences in their owning parent context, including
        inherited/replaced records. Earlier policy/run/native authority is not inferred
        from the current caller; unperformed mathematical checks remain absent.
    transitions : tuple of ReproductionTransition
        One whole matching single-claim predecessor for each independently reproduced
        parent. Correspondence supplies no actual independent run or class acceptance.
    closure : ClosureResult
        Complete typed source graph from the current parent and all earlier roots,
        enforcing the SAME original depth/reference/byte bounds without schema-less resets.
    roots : tuple of ClosureRoot
        Actual complete independently selected source arguments for definitive current
        policy-bound preparation, preserving original metadata, raw bytes and formats.
    """

    subjects: tuple[ReproductionSubject, ...]
    records: tuple[ReproductionRecordSources, ...]
    transitions: tuple[ReproductionTransition, ...]
    closure: ClosureResult
    roots: tuple[ClosureRoot, ...]


def acquire_reproduction_history(
    content: CompleteContent,
    records: tuple[ReproductionRecordSources, ...],
    *,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> ReproductionHistory:
    """Discover actual predecessor sources and reconstruct every whole parent transition.

    Parameters
    ----------
    content : CompleteContent
        Entire actual current C0 after preceding native/common source checks.
    records : tuple of ReproductionRecordSources
        Nonempty actual current package population after existing relations/native math.
        This source result is not a completed record/Clock/class admission predicate.
    formats : Mapping
        Original compiled static and installed native structural bindings.
    resolver : Resolver
        Sole bounded original byte source without discovery or fallback.
    budget : ReferenceBudget
        SAME original invocation allowance. Earlier sources receive no new limits.

    Returns
    -------
    ReproductionHistory
        Entire original causal graph and whole structural transitions. Full earlier
        identity/policy/authority/time/run/nonuse/comparison remain independently required.

    Raises
    ------
    InputRefused
        Exact whole parent/package/source/graph or an original operation bound conflicts.
    ReferenceUnavailable
        An exact selected earlier manifest/package/body/identity/source is absent.
    """
    current = content.content_ref
    root_key = current.digest, current.digest_basis, current.byte_length
    document = content.closure.documents[root_key]
    root = ContextSource(current, document.raw_bytes, document, current.schema_id, ())
    pending = [(root, 0)]
    subjects: dict[ByteIdentity, ReproductionSubject] = {}
    cache = {record.record.source.reference: record for record in records}
    populations: dict[ByteIdentity, list[ReproductionRecordSources]] = {}
    occurrences: list[ReproductionRecordSources] = []
    sources: list[FixedSource] = []
    manifests: list[ClosureRoot] = []
    policies: list[ClosureRoot] = []
    while pending:
        source, depth = pending.pop()
        reference = source.reference
        source_identity = reference.digest, reference.digest_basis, reference.byte_length
        if depth > budget.limits.max_graph_depth:
            raise InputRefused(
                Reason(
                    "limit_exceeded",
                    reference.digest,
                    None,
                    None,
                    "Reference graph depth bound exceeded.",
                )
            )
        manifests.append(
            ClosureRoot(
                reference, cast(bytes, source.raw_bytes), "evidence_manifest_toolkit.manifest.v1"
            )
        )
        if source_identity in subjects:
            continue
        subject = prepare_reproduction_subject(
            source, formats=formats, resolver=resolver, budget=budget
        )
        subjects[source_identity] = subject
        population: list[ReproductionRecordSources] = []
        for index, claim in enumerate(subject.claims):
            if claim.validation_status != "independently_reproduced":
                continue
            record_ref = cast(BlobRef, claim.validation_record)
            if record_ref in cache:
                record = replace(cache[record_ref], claim=claim)
            else:
                record = acquire_reproduction_source(
                    claim,
                    index,
                    containing_subject=reference,
                    formats=formats,
                    resolver=resolver,
                    budget=budget,
                )
                cache[record_ref] = record
            population.append(record)
            occurrences.append(record)
            sources.extend((record.record, record.body, record.producer, record.runner))
            if record.foreign is not None:
                sources.append(record.foreign)
            policies.append(
                ClosureRoot(record.policy.reference, cast(bytes, record.policy.raw_bytes))
            )
            if record.native_evidence is not None:
                for receipt in record.native_evidence.receipts:
                    sources.append(receipt.statement)
                    if receipt.certificate is not None:
                        sources.append(receipt.certificate)
            package = cast(
                dict[str, JsonValue], cast(AcquiredDocument, record.record.source.document).value
            )
            if package["validation_C0_statement_ref"] is not None:
                validation_ref = decode_reference(
                    package["validation_C0_statement_ref"],
                    subject=record.record.source.reference.digest,
                    pointer="/validation_C0_statement_ref",
                )
                validation_raw = acquire_reference(
                    validation_ref,
                    resolver=resolver,
                    budget=budget,
                    subject=record.record.source.reference.digest,
                    pointer="/validation_C0_statement_ref",
                )
                manifests.append(
                    ClosureRoot(
                        validation_ref, validation_raw, "evidence_manifest_toolkit.manifest.v1"
                    )
                )
            pending.append((record.subject, depth + 3))
        populations[source_identity] = population
    closure = close_fixed_sources(
        tuple(sources),
        formats=formats,
        resolver=resolver,
        budget=budget,
        additional_roots=tuple(manifests + policies),
    )
    if closure.missing_references:
        raise ReferenceUnavailable(closure.missing_references[0])
    if closure.reasons:
        raise InputRefused(closure.reasons[0])
    reproduction_common_semantics(closure, formats=formats, limits=budget.limits)
    transitions: list[ReproductionTransition] = []
    for identity, subject in subjects.items():
        population = populations[identity]
        if not population:
            continue
        for record in population:
            earlier_ref = record.subject.reference
            earlier = subjects[
                earlier_ref.digest, earlier_ref.digest_basis, earlier_ref.byte_length
            ]
            if reproduction_transition_matches(subject, earlier, record, limits=budget.limits):
                transitions.append(ReproductionTransition(subject, earlier, record))
                break
        else:
            raise InputRefused(
                Reason(
                    "invalid_claim",
                    subject.source.reference.digest,
                    None,
                    "/claims",
                    "Independent validation parent does not reconstruct its whole earlier subject.",
                )
            )
    roots = tuple(manifests + policies) + tuple(
        ClosureRoot(
            source.source.reference,
            cast(bytes, source.source.raw_bytes),
            format_name=source.format.name,
        )
        for source in sources
    )
    return ReproductionHistory(
        tuple(subjects.values()), tuple(occurrences), tuple(transitions), closure, roots
    )
