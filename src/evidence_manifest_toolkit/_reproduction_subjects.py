# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole original reproduction subject semantics

"""Keep original earlier manifest references and full native/common source semantics."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import cast

from ._budget import ByteIdentity, ReferenceBudget
from ._claims import ClaimObligation
from ._closure import ClosureResult, ClosureRoot, traverse_closure
from ._context_sources import ContextSource
from ._errors import InputRefused, ReferenceUnavailable
from ._interfaces import Resolver
from ._json import AcquiredDocument, canonicalize_json
from ._schema_resources import StaticSchema
from ._semantics import SubjectSemantics, subject_semantics
from ._subject_formats import SubjectFormat
from ._values import Limits


@dataclass(frozen=True, slots=True)
class ReproductionSubject:
    """Retain an entire actual parent manifest without replacing its reference basis.

    Attributes
    ----------
    source : ContextSource
        Original full reference and unchanged bounded bytes/number-token custody.
    document : AcquiredDocument
        Entire original source after native structural validation.
    canonical_content : bytes
        Whole comparison bytes only; no synthetic canonical resolver argument is charged.
    claims : tuple of ClaimObligation
        Actual native inventory with unwaived run/signature/measurement obligations.
    closure : ClosureResult
        Whole original required source graph and static/common semantics.
    """

    source: ContextSource
    document: AcquiredDocument
    canonical_content: bytes
    claims: tuple[ClaimObligation, ...]
    closure: ClosureResult


def prepare_reproduction_subject(
    source: ContextSource,
    *,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> ReproductionSubject:
    """Check the entire known native manifest under its original reference and budget.

    Parameters
    ----------
    source : ContextSource
        Actual earlier subject after whole identity/strict JSON acquisition; raw bytes
        and document are present, or the owning source method has already refused.
    formats : Mapping
        Original compiled static registry and explicit installed native bindings.
    resolver : Resolver
        Sole original bounded source; unknown objects never become roots.
    budget : ReferenceBudget
        SAME original allowance, including already acquired record and Clock sources.

    Returns
    -------
    ReproductionSubject
        Whole earlier source and all actual common predicates, without independent run,
        custody, native authority, physical Clock or reproduction acceptance.

    Raises
    ------
    ReferenceUnavailable
        An exact required original descendant is missing.
    InputRefused
        Whole native/common source, metadata, identity, graph or bounds conflict.
    """
    raw = cast(bytes, source.raw_bytes)
    closure = traverse_closure(
        (ClosureRoot(source.reference, raw, "evidence_manifest_toolkit.manifest.v1"),),
        schemas=formats,
        resolver=resolver,
        budget=budget,
        requirements=(),
    )
    if closure.missing_references:
        raise ReferenceUnavailable(closure.missing_references[0])
    if closure.reasons:
        raise InputRefused(closure.reasons[0])
    reference = source.reference
    root = reference.digest, reference.digest_basis, reference.byte_length
    semantics = reproduction_common_semantics(closure, formats=formats, limits=budget.limits)
    return ReproductionSubject(
        source,
        closure.documents[root],
        canonicalize_json(raw, limits=budget.limits),
        semantics[root].claim_obligations,
        closure,
    )


def reproduction_common_semantics(
    closure: ClosureResult, *, formats: Mapping[str, SubjectFormat], limits: Limits
) -> Mapping[ByteIdentity, SubjectSemantics]:
    """Check every entire original static/common subject in the selected history graph.

    Parameters
    ----------
    closure : ClosureResult
        Entire actually typed required source graph with original document/token custody.
    formats : Mapping
        Original compiled static schemas and installed fixed native definitions.
    limits : Limits
        Original operation bounds for native inventory validation.

    Returns
    -------
    Mapping
        Actual whole common predicates; fixed native containers retain their owning
        method obligations and do not receive invented common or authority results.

    Raises
    ------
    InputRefused
        An actual required original common semantic predicate fails.
    """
    statics = {name: value for name, value in formats.items() if isinstance(value, StaticSchema)}
    results: dict[ByteIdentity, SubjectSemantics] = {}
    for identity, document in closure.documents.items():
        static = statics.get(closure.bindings[identity])
        if static is None:
            continue
        semantics = subject_semantics(
            static,
            document,
            subject=identity[0],
            documents=closure.documents,
            schemas=statics,
            limits=limits,
        )
        if semantics.reasons:
            raise InputRefused(semantics.reasons[0])
        results[identity] = semantics
    return MappingProxyType(results)
