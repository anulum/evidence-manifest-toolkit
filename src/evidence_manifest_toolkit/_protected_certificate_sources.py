# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete independently rooted native certificate source graph

"""Retain complete certificate parent graphs without manufacturing admitted issuer authority."""

from collections.abc import Mapping
from typing import cast

from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._format_sources import FixedSource
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._protected_certificate_bounds import check_certificate_source_parent_bounds
from ._protected_state_history import acquire_protected_native_source, protected_source_conflict
from ._protected_state_sources import ProtectedStateSources
from ._subject_formats import SubjectFormat
from ._values import BlobRef, Digest

_CERTIFICATE = "evidence_manifest_toolkit.delegated_certificate.v2"
_GRANT = "evidence_manifest_toolkit.authority_grant.v2"


def acquire_protected_certificate_sources(
    state: ProtectedStateSources,
    *,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
    additional_roots: tuple[FixedSource, ...] = (),
) -> tuple[FixedSource, ...]:
    """Acquire every selected whole certificate chain to the exact independent grant.

    Parameters
    ----------
    state : ProtectedStateSources
        Complete already acquired root/grant/current/archive source histories. They are
        source declarations, not an admitted bootstrap or authenticated protected state.
    formats : Mapping
        Original fixed native structural lookup, without artifact-selected code dispatch.
    resolver : Resolver
        Sole original bounded source for actual complete certificate and parent arguments.
    budget : ReferenceBudget
        SAME original quota and graph-depth bound, including any memoised ancestor suffix.
    additional_roots : tuple of FixedSource
        Whole independently selected issue_certificate targets, in original selection
        order. Their parents need not already be listed in an earlier snapshot.

    Returns
    -------
    tuple of FixedSource
        Entire native certificate sources in actual first-acquisition order, including
        every full parent and each additional whole selected control certificate.
        Whole references and all identity/custody/key fields survive;
        source consistency grants no actual key, issuer, native-signature or Clock authority.

    Raises
    ------
    ReferenceUnavailable
        An exact original selected leaf or parent argument is unavailable.
    InputRefused
        Original source/schema/identity/quota or complete parent/scope/depth/window fails.

    Notes
    -----
    Every checked parent edge strictly increases remaining depth toward the grant,
    so a source cycle cannot pass the unchanged parent bounds. Graph-depth and
    cumulative acquisition limits still bound every unresolved chain.
    A local chain cache is populated only after reaching the selected grant. Every
    original snapshot and certificate body remains a full root/edge of the subsequent
    shared closure. An advertised different grant is never adopted or discovered as a
    replacement root. Actual rotated issuer selection, signature, possession, identity,
    custody, withdrawal and full eligibility remain separate required predicates.
    """
    acquired: dict[BlobRef, FixedSource] = {}
    rooted: dict[BlobRef, tuple[BlobRef, ...]] = {}
    grant_reference = state.grant.source.reference

    def certificate(reference: BlobRef, *, subject: Digest, pointer: str) -> FixedSource:
        """Read a full native certificate with original metadata and cumulative bounds.

        Parameters
        ----------
        reference : BlobRef
            Exact original snapshot or earlier certificate parent argument.
        subject : str
            Actual complete containing source identity.
        pointer : str
            Original source position, retained for acquisition diagnostics.

        Returns
        -------
        FixedSource
            Entire actual structurally checked source. Repeated source bytes use the
            original budget cache while each acquisition retains its original metadata.
        """
        result = acquire_protected_native_source(
            reference,
            format_name=_CERTIFICATE,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=subject,
            pointer=pointer,
        )
        acquired.setdefault(reference, result)
        return result

    seeds: list[tuple[BlobRef, Digest, str]] = []
    for snapshot in (*state.history, *state.selected_history):
        value = cast(
            dict[str, JsonValue], cast(AcquiredDocument, snapshot.fixed.source.document).value
        )
        for index, selected in enumerate(cast(list[JsonValue], value["certificate_refs"])):
            subject = snapshot.fixed.source.reference.digest
            pointer = "/certificate_refs/" + str(index)
            reference = decode_reference(selected, subject=subject, pointer=pointer)
            seeds.append((reference, subject, pointer))
    seeds.extend(
        (source.source.reference, source.source.reference.digest, "") for source in additional_roots
    )
    for reference, subject, pointer in seeds:
        child = certificate(reference, subject=subject, pointer=pointer)
        chain: list[BlobRef] = []
        while reference != grant_reference and reference not in rooted:
            if len(chain) >= budget.limits.max_graph_depth:
                raise protected_source_conflict(subject, pointer, code="limit_exceeded")
            body = cast(dict[str, JsonValue], cast(AcquiredDocument, child.source.document).value)
            parent_reference = decode_reference(
                body["parent_authorization_ref"],
                subject=reference.digest,
                pointer="/parent_authorization_ref",
            )
            parent = (
                state.grant
                if parent_reference == grant_reference or parent_reference.schema_id == _GRANT
                else certificate(
                    parent_reference,
                    subject=reference.digest,
                    pointer="/parent_authorization_ref",
                )
            )
            check_certificate_source_parent_bounds(child, parent=parent)
            chain.append(reference)
            subject, pointer = reference.digest, "/parent_authorization_ref"
            reference, child = parent_reference, parent
        suffix = rooted.get(reference, ())
        if len(chain) + len(suffix) > budget.limits.max_graph_depth:
            raise protected_source_conflict(subject, pointer, code="limit_exceeded")
        complete = (*chain, *suffix)
        for index, member in enumerate(chain):
            rooted[member] = complete[index:]
    return tuple(acquired.values())
