# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected certificate issuer correspondence

"""Compare declared parent issuers throughout the complete selected certificate forest."""

from typing import cast

from ._codecs import decode_reference
from ._errors import InputRefused
from ._format_sources import FixedSource
from ._json import AcquiredDocument, JsonValue
from ._values import Reason


def match_certificate_parent_issuer(child: FixedSource, *, parent: FixedSource) -> None:
    """Match a whole certificate's declared issuer to its exact parent certificate subject.

    Parameters
    ----------
    child : FixedSource
        Whole native child with its original identity, format and public key checked.
    parent : FixedSource
        Whole exact parent certificate from the original bounded source forest.

    Returns
    -------
    None
        The declared issuer names the parent subject. This admits no signature,
        identity, custody, possession, Clock or current authorization.

    Raises
    ------
    InputRefused
        The child's declared issuer differs from its parent's subject key ID.
    """
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, child.source.document).value)
    ancestor = cast(dict[str, JsonValue], cast(AcquiredDocument, parent.source.document).value)
    if value["issuer_key_id"] != ancestor["subject_key_id"]:
        raise InputRefused(
            Reason(
                "invalid_delegation",
                child.source.reference.digest,
                None,
                "/issuer_key_id",
                "Protected certificate issuer does not match its parent.",
            )
        )


def check_protected_certificate_issuers(
    grant: FixedSource, certificates: tuple[FixedSource, ...]
) -> None:
    """Check every non-grant parent issuer in the complete already acquired forest.

    Parameters
    ----------
    grant : FixedSource
        Entire independently selected grant, separate from root and issuer eligibility.
    certificates : tuple of FixedSource
        Whole original current, archived, historical and ancestor certificate sources.
        Exact reference, rooted graph, metadata, scope, depth and keys precede this call.

    Returns
    -------
    None
        Every declared child issuer matches its exact parent certificate subject.
        Direct grant children retain independent earlier-state and rotation requirements;
        the initial grant issuer is never treated as a permanent issuer shortcut.

    Raises
    ------
    InputRefused
        An actual non-grant parent relation has a conflicting declared issuer.
    """
    sources = {certificate.source.reference: certificate for certificate in certificates}
    for child in certificates:
        value = cast(dict[str, JsonValue], cast(AcquiredDocument, child.source.document).value)
        reference = decode_reference(
            value["parent_authorization_ref"],
            subject=child.source.reference.digest,
            pointer="/parent_authorization_ref",
        )
        if reference != grant.source.reference:
            match_certificate_parent_issuer(child, parent=sources[reference])
