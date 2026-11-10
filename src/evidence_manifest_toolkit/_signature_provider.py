# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit local verifier initialization failure

"""Keep missing or unusable verifier configuration separate from evaluated signature refusals."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._errors import ConfigurationError
from ._values import Reason

if TYPE_CHECKING:
    from ._native_signature import NativeVerifier


def initialize_verifier() -> NativeVerifier:
    """Initialize the maintained local verifier before attempting signature authentication.

    Returns
    -------
    NativeVerifier
        Actual initialized supported point provider; complete qualification is a build gate.

    Raises
    ------
    ConfigurationError
        Absence, unsupported local version or initialization failure yields the exact
        fixed original configuration reason, without a fabricated VerificationReport.
    """
    try:
        from ._native_signature import NativeVerifier

        return NativeVerifier()
    except Exception as error:
        raise ConfigurationError(
            Reason(
                "configuration_error",
                None,
                None,
                None,
                "A conforming local verifier for the required signature profile is unavailable.",
            )
        ) from error
