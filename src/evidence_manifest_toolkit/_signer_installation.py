# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — private trusted CLI signer association

"""Acquire an existing installation-owned signer without enrollment or artifact-selected code."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ._errors import SignerUnavailable
from ._interfaces import Signer
from ._reference_paths import configuration_refusal
from ._trust_types import SignerConfig
from ._values import Reason


@dataclass(frozen=True, slots=True)
class _Association:
    """Hold only an independently selected descriptor and an actual existing Signer.

    Attributes
    ----------
    descriptor : SignerConfig
        Exact original four-field identity independently selected by the trusted installation.
    signer : Signer
        Actual already qualified owner-controlled object; this value performs no enrollment,
        device discovery, code import, factory call or qualification transaction.
    """

    descriptor: SignerConfig
    signer: Signer


_INSTALLATION: Mapping[str, _Association] = MappingProxyType({})


def installed_signer(configuration: SignerConfig) -> Signer:
    """Select the exact existing private association and preserve descriptor mismatch scope.

    Parameters
    ----------
    configuration : SignerConfig
        Complete already decoded original caller descriptor, with an opaque exact adapter_ref.

    Returns
    -------
    Signer
        Actual independently qualified installation-owned object with matching descriptor.
        Its public bytes and returned signature remain subject to genuine seal authority checks.

    Raises
    ------
    ConfigurationError
        A supplied field differs from the trusted installed descriptor, at /signer/field with
        the original caller reason. Received configuration never updates or enrolls an entry.
    SignerUnavailable
        No qualified association exists. The current verified empty installation refuses with
        null subject/claim/pointer before signing or publication, without unsigned fallback.

    Notes
    -----
    Only trusted installed application custody supplies associations. No public setter,
    configuration field, environment variable, plugin group or callable factory populates them.
    """
    association = _INSTALLATION.get(configuration.adapter_ref)
    if association is None:
        raise SignerUnavailable(
            Reason(
                "signer_unavailable",
                None,
                None,
                None,
                "The required signing adapter is unavailable.",
            )
        )
    for field in ("adapter_ref", "signer_key_id", "public_key", "profile_id"):
        if getattr(configuration, field) != getattr(association.descriptor, field):
            raise configuration_refusal("/signer/" + field)
    return association.signer
