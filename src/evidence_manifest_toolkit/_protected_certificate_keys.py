# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — selected grant and certificate key source correspondence

"""Bind actual public-key data to the entire selected native certificate forest."""

from typing import cast

from ._acquisition import acquire_reference
from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._errors import InputRefused
from ._format_sources import FixedSource
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._protected_state_history import protected_source_conflict
from ._statements import key_id
from ._values import BlobRef, Reason


def acquire_certificate_public_key(
    certificate: FixedSource, *, resolver: Resolver, budget: ReferenceBudget
) -> tuple[BlobRef, bytes]:
    """Read and bind one complete certificate's actual public-key source.

    Parameters
    ----------
    certificate : FixedSource
        Entire selected native certificate after its original source/format checks.
        Its own key ID is separate from issuer authority or protected custody.
    resolver : Resolver
        SAME bounded original source, without a decoder or discovery path.
    budget : ReferenceBudget
        SAME cumulative invocation allowance, retaining all original metadata assertions.

    Returns
    -------
    tuple of BlobRef and bytes
        Full unchanged key reference and actual 32 bytes matching the certificate's own
        native key ID. No curve, signature, possession, Clock or class is admitted.

    Raises
    ------
    InputRefused
        Actual key length/ID, original byte identity, metadata or quota conflicts.
    ReferenceUnavailable
        The exact original whole key source is unavailable.
    ConfigurationError
        The original resolver supplies an invalid value instead of bytes.
    """
    subject = certificate.source.reference.digest
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, certificate.source.document).value)
    reference = decode_reference(
        value["subject_public_key_ref"], subject=subject, pointer="/subject_public_key_ref"
    )
    public = acquire_reference(
        reference,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer="/subject_public_key_ref",
    )
    if len(public) != 32 or key_id(public) != value["subject_key_id"]:
        raise InputRefused(
            Reason(
                "invalid_delegation",
                subject,
                None,
                "/subject_public_key_ref",
                "Selected native key data does not match the certificate subject.",
            )
        )
    return reference, public


def check_protected_certificate_keys(
    grant: FixedSource,
    certificates: tuple[FixedSource, ...],
    *,
    resolver: Resolver,
    budget: ReferenceBudget,
) -> None:
    """Check every selected issuer and certificate key's actual bytes and own declared ID.

    Parameters
    ----------
    grant : FixedSource
        Entire independently selected grant after its original complete source closure.
        Its initial issuer is separate from the independently selected root.
    certificates : tuple of FixedSource
        Whole rooted certificate forest from current and selected archived histories,
        including every acquired parent in original acquisition order.
    resolver : Resolver
        SAME bounded original source, without key discovery or decoding selection.
    budget : ReferenceBudget
        SAME cumulative invocation allowance, retaining each full metadata assertion.

    Returns
    -------
    None
        All selected key sources contain 32 bytes matching their own native key IDs.
        This establishes no curve equation, root, current issuer, protected custody,
        key possession, signature, Clock, admitted state or certificate eligibility.

    Raises
    ------
    InputRefused
        An actual key length or own key ID conflicts, or original identity/metadata/quota fails.
    ReferenceUnavailable
        An exact original required whole key source cannot be acquired.
    ConfigurationError
        The original source supplies an invalid value instead of bytes.
    """
    subject = grant.source.reference.digest
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, grant.source.document).value)
    reference = decode_reference(
        value["initial_issuer_public_key_ref"],
        subject=subject,
        pointer="/initial_issuer_public_key_ref",
    )
    public = acquire_reference(
        reference,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer="/initial_issuer_public_key_ref",
    )
    if len(public) != 32 or key_id(public) != value["initial_issuer_key_id"]:
        raise protected_source_conflict(subject, "/initial_issuer_public_key_ref")
    for certificate in certificates:
        acquire_certificate_public_key(certificate, resolver=resolver, budget=budget)
