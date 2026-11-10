# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual earlier rotation key withdrawal sources

"""Reject invalid or previously withdrawn rotation keys without admitting authority."""

from typing import cast

from ._acquisition import acquire_reference
from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._format_sources import FixedSource
from ._immutable import thaw_json
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._protected_control_bindings import ProtectedControlBinding
from ._protected_state_history import protected_source_conflict
from ._statements import key_id
from ._values import BlobRef, Digest


def check_protected_rotation_keys(
    bindings: tuple[ProtectedControlBinding, ...],
    *,
    sources: tuple[FixedSource, ...],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> None:
    """Check actual new key data against the complete earlier withdrawn-key population.

    Parameters
    ----------
    bindings : tuple of ProtectedControlBinding
        Entire independently selected controls after original target, statement,
        earlier-state and full identity/schema/metadata closure checks.
    sources : tuple of FixedSource
        Complete retained rotation and earlier authorising snapshot population
        produced by the original source-continuity method, before this call.
    resolver : Resolver
        Sole original bounded source. Every selected key was acquired by that same
        complete closure; cached bytes retain their original full declarations.
    budget : ReferenceBudget
        SAME invocation byte/count/depth bounds, never a fresh key-read budget.

    Returns
    -------
    None
        Selected rotation keys are actual raw32 values matching their key IDs and
        differ from every earlier withdrawn key. Other control operations and
        non-key withdrawals retain their original separate predicates. No root,
        custody, possession, signature, time, Clock or state authority is admitted.

    Raises
    ------
    InputRefused
        Actual raw key data, selected key identity or earlier key withdrawal conflicts.
        Original source metadata and cumulative acquisition failures remain typed.
    ReferenceUnavailable
        An exact original whole selected key source cannot be acquired.
    ConfigurationError
        The caller-owned source supplies an invalid value instead of bytes.
    """
    selected = {source.source.reference: source for source in sources}

    def value(source: FixedSource) -> dict[str, JsonValue]:
        """Retain the entire already validated declaration without a field projection.

        Parameters
        ----------
        source : FixedSource
            Whole structurally validated native target or earlier state.

        Returns
        -------
        dict
            Actual complete original parsed declaration.
        """
        return cast(dict[str, JsonValue], cast(AcquiredDocument, source.source.document).value)

    def public(raw: JsonValue, *, subject: Digest, pointer: str) -> bytes:
        """Read exact already closure-checked native raw32 source data under the same quota.

        Parameters
        ----------
        raw : object
            Entire original reference value without rewritten metadata.
        subject : str
            Actual containing rotation or earlier snapshot identity.
        pointer : str
            Exact original key-reference field position.

        Returns
        -------
        bytes
            Complete actual 32-byte native public key, without provider invocation.

        Raises
        ------
        InputRefused
            Native raw key length or original acquisition metadata/quota fails.
        ReferenceUnavailable
            The exact original selected source cannot be acquired.
        """
        reference = decode_reference(raw, subject=subject, pointer=pointer)
        data = acquire_reference(
            reference, resolver=resolver, budget=budget, subject=subject, pointer=pointer
        )
        if len(data) != 32:
            raise protected_source_conflict(subject, pointer)
        return data

    for binding in bindings:
        if binding.entry["operation"] != "rotate_authority":
            continue
        target = value(binding.target)
        subject = binding.target.source.reference.digest
        key = public(target["new_public_key_ref"], subject=subject, pointer="/new_public_key_ref")
        if key_id(key) != target["new_key_id"]:
            raise protected_source_conflict(subject, "/new_public_key_ref")
        earlier_reference: BlobRef = decode_reference(
            thaw_json(binding.entry["authorizing_state_ref"]),
            subject=binding.statement.source.reference.digest,
            pointer="/authorizing_state_ref",
        )
        earlier = selected[earlier_reference]
        for index, row in enumerate(
            cast(list[dict[str, JsonValue]], value(earlier)["revocations"])
        ):
            if row["target_kind"] != "key":
                continue
            withdrawn = public(
                row["target_ref"],
                subject=earlier_reference.digest,
                pointer="/revocations/" + str(index) + "/target_ref",
            )
            if withdrawn == key:
                raise protected_source_conflict(subject, "/new_public_key_ref")
