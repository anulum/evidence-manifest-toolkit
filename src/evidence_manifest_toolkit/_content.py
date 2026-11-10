# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete content and closure semantic composition

"""Compose common content checks without manufacturing signature or domain acceptance."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ._budget import ByteIdentity, ReferenceBudget
from ._claims import ClaimObligation
from ._closure import ClosureResult, ClosureRoot, traverse_closure
from ._interfaces import Resolver
from ._json import canonicalize_json
from ._references import reference_bytes
from ._registry_types import ReferenceRequirement
from ._schema_resources import StaticSchema
from ._semantics import SubjectSemantics, subject_semantics
from ._subject_formats import SubjectFormat
from ._values import BlobRef, Reason


@dataclass(frozen=True, slots=True)
class CompleteContent:
    """Retain the whole content, required graph and every common semantic result.

    Attributes
    ----------
    canonical_content : bytes
        Entire original admitted content represented by RFC8785, with no receipt inserted.
    content_ref : BlobRef
        Identity and length of those same canonical bytes, under the caller's schema ID.
    closure : ClosureResult
        Every selected edge and required whole schema-valid subject.
    semantics : Mapping
        Common results indexed by actual byte identity; opaque optional objects are absent.
    reasons : tuple of Reason
        Complete required closure and common contradictions, without signature decisions.
    """

    canonical_content: bytes
    content_ref: BlobRef
    closure: ClosureResult
    semantics: Mapping[ByteIdentity, SubjectSemantics]
    reasons: tuple[Reason, ...]

    @property
    def content_claim_obligations(self) -> tuple[ClaimObligation, ...]:
        """Return the entire native root inventory's outstanding authority obligations.

        Returns
        -------
        tuple of ClaimObligation
            Original root claims in source order, or empty for a non-claim content root.
        """
        reference = self.content_ref
        selected = self.semantics.get(
            (reference.digest, reference.digest_basis, reference.byte_length)
        )
        return () if selected is None else selected.claim_obligations


def prepare_content(
    content_json: bytes,
    *,
    schema_id: str,
    schemas: Mapping[str, StaticSchema],
    resolver: Resolver,
    budget: ReferenceBudget,
    requirements: tuple[ReferenceRequirement, ...],
    additional_roots: tuple[ClosureRoot, ...] = (),
    formats: Mapping[str, SubjectFormat] | None = None,
) -> CompleteContent:
    """Check whole content and every explicitly selected required subject together.

    Parameters
    ----------
    content_json : bytes
        Complete source bytes, retained through the closure document's raw-token custody.
    schema_id : str
        Independent caller selection; a received declaration cannot select an implementation.
    schemas : Mapping
        Entire already validated static registry, including protected common source constraints.
    resolver : Resolver
        Explicit local source for declared reference bytes; unused store objects select nothing.
    budget : ReferenceBudget
        Sole operation budget including all prior schema/context acquisitions.
    requirements : tuple of ReferenceRequirement
        Validated existing selector requirements for verification, or empty for construction.
    additional_roots : tuple of ClosureRoot
        Only actual caller-selected registry/context/envelope content roots.

    formats : Mapping or None
        Explicit owning method's installed structural lookup for native descendants.
        None uses only the original static registry. Native containers retain complete
        structural/reference observations; their semantic/authority predicates belong
        to the selected native methods and receive no manufactured common result.

    Returns
    -------
    CompleteContent
        Whole canonical identity, graph and common results. Missing required lookups retain
        their original complete references; no signature, current or domain verdict is inferred.

    Raises
    ------
    InputRefused
        The original content cannot be acquired or canonically represented within its bounds.
    ConfigurationError
        Explicit static schema or resolver configuration fails while traversing selected roots.
    """
    limits = budget.limits
    canonical = canonicalize_json(content_json, limits=limits)
    reference = reference_bytes(
        canonical,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=schema_id,
        limits=limits,
    )
    roots = (ClosureRoot(reference, content_json),) + additional_roots
    closure = traverse_closure(
        roots,
        schemas=schemas if formats is None else formats,
        resolver=resolver,
        budget=budget,
        requirements=requirements,
    )
    selected: dict[ByteIdentity, BlobRef] = {
        (
            root.reference.digest,
            root.reference.digest_basis,
            root.reference.byte_length,
        ): root.reference
        for root in roots
    }
    for observation in closure.observations:
        child = observation.reference
        if observation.required and observation.outcome == "matched" and child is not None:
            selected[(child.digest, child.digest_basis, child.byte_length)] = child
    semantics: dict[ByteIdentity, SubjectSemantics] = {}
    reasons = list(closure.reasons)
    for identity, document in closure.documents.items():
        child = selected[identity]
        static = schemas.get(closure.bindings[identity])
        if static is None:
            continue
        result = subject_semantics(
            static,
            document,
            subject=child.digest,
            documents=closure.documents,
            schemas=schemas,
            limits=limits,
        )
        semantics[identity] = result
        reasons.extend(result.reasons)
    for requirement in requirements:
        if not any(
            child.digest == requirement.subject_digest
            and closure.bindings.get(identity) == requirement.schema_id
            and identity in closure.documents
            for identity, child in selected.items()
        ):
            reasons.append(
                Reason(
                    "scope_missing",
                    requirement.subject_digest,
                    None,
                    None,
                    "Required selector subject is outside the selected valid closure.",
                )
            )
    return CompleteContent(
        canonical, reference, closure, MappingProxyType(semantics), tuple(reasons)
    )
