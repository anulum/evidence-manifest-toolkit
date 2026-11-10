# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole single reproduction record source graph

"""Acquire every whole single-record source without assigning later policy or authority."""

from collections.abc import Mapping
from typing import cast

from ._budget import ReferenceBudget
from ._claims import ClaimObligation
from ._closure import ClosureRoot
from ._codecs import decode_reference
from ._context_sources import ContextSource, acquire_context_source
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource, acquire_fixed_source, close_fixed_sources
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._reproduction_record_relations import ReproductionRecordSources
from ._subject_formats import SubjectFormat
from ._values import BlobRef, Digest


def acquire_reproduction_source(
    claim: ClaimObligation,
    index: int,
    *,
    containing_subject: BlobRef,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> ReproductionRecordSources:
    """Read one whole explicitly selected package and all original earlier source graphs.

    Parameters
    ----------
    claim : ClaimObligation
        Actual claim in the entire containing manifest, not a projected received record.
    index : int
        Actual source-order position for the original reference diagnostic.
    containing_subject : BlobRef
        Entire containing manifest source identity, preserving its original basis.
    formats : Mapping
        Complete independently installed native and static structural lookup.
    resolver : Resolver
        Sole bounded source for unchanged full references.
    budget : ReferenceBudget
        SAME original operation allowance; no historical lookup gets a fresh budget.

    Returns
    -------
    ReproductionRecordSources
        Whole record/body/producer/runner/subject/policy/foreign graph. No relation,
        native equation, current policy, run, Clock or authority is inferred.

    Raises
    ------
    ReferenceUnavailable
        An exact selected required source is missing.
    InputRefused
        Whole source identity/schema/metadata/graph or original bounds fail.
    """

    def fixed(reference: BlobRef, name: str, subject: Digest, pointer: str) -> FixedSource:
        """Acquire one entire explicitly selected fixed native body and its original errors."""
        result = acquire_fixed_source(
            reference,
            format_name=name,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=subject,
            pointer=pointer,
        )
        if result.source.raw_bytes is None:
            raise ReferenceUnavailable(reference)
        if result.source.document is None:
            raise InputRefused(result.source.reasons[0])
        return result

    def child(parent: FixedSource, field: str, name: str) -> FixedSource:
        """Keep the full native child reference at its actual containing field."""
        subject = parent.source.reference.digest
        value = cast(dict[str, JsonValue], cast(AcquiredDocument, parent.source.document).value)
        reference = decode_reference(value[field], subject=subject, pointer="/" + field)
        return fixed(reference, name, subject, "/" + field)

    def context(parent: FixedSource, field: str) -> ContextSource:
        """Retain a whole earlier subject or policy without imposing a future invocation."""
        subject = parent.source.reference.digest
        value = cast(dict[str, JsonValue], cast(AcquiredDocument, parent.source.document).value)
        reference = decode_reference(value[field], subject=subject, pointer="/" + field)
        result = acquire_context_source(
            reference,
            expected_control=None,
            resolver=resolver,
            budget=budget,
            subject=subject,
            pointer="/" + field,
        )
        if result.raw_bytes is None:
            raise ReferenceUnavailable(reference)
        if result.document is None:
            raise InputRefused(result.reasons[0])
        return result

    record = fixed(
        cast(BlobRef, claim.validation_record),
        "evidence_manifest_toolkit.independent_validation_record.v2",
        containing_subject.digest,
        "/claims/" + str(index) + "/validation/record_ref",
    )
    body = child(record, "body_ref", "evidence_manifest_toolkit.independent_validation_body.v2")
    producer = child(body, "producer_binding_ref", "evidence_manifest_toolkit.identity_binding.v2")
    runner = child(body, "runner_binding_ref", "evidence_manifest_toolkit.identity_binding.v2")
    subject = context(body, "subject_ref")
    earlier_policy = context(body, "whole_policy_ref")
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, record.source.document).value)
    foreign = (
        child(
            record,
            "foreign_run_identity_ref",
            "evidence_manifest_toolkit.foreign_run_identity.v1",
        )
        if value["foreign_run_identity_ref"] is not None
        else None
    )
    roots = (record, body, producer, runner) + (() if foreign is None else (foreign,))
    closure = close_fixed_sources(
        roots,
        formats=formats,
        resolver=resolver,
        budget=budget,
        additional_roots=tuple(
            ClosureRoot(source.reference, cast(bytes, source.raw_bytes))
            for source in (subject, earlier_policy)
        ),
    )
    if closure.missing_references:
        raise ReferenceUnavailable(closure.missing_references[0])
    if closure.reasons:
        raise InputRefused(closure.reasons[0])
    complete = ReproductionRecordSources(
        claim, record, body, producer, runner, subject, earlier_policy, foreign, closure
    )
    return complete
