# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete software authorization use intervals

"""Require one whole actual signature-verified source row through native entry."""

from ._clock_method_values import CLOCK_POINTER
from ._clock_values import coordinate_utc
from ._clock_windows import ClockInterval
from ._errors import InputRefused
from ._software_receipts import SoftwareReceiptCheck
from ._software_sources import SoftwareSources
from ._values import BlobRef, Reason, Utc


def check_software_intervals(
    receipts: tuple[SoftwareReceiptCheck, ...],
    *,
    sources: SoftwareSources,
    interval: ClockInterval,
    origin: str,
    policy_reference: BlobRef,
) -> None:
    """Require complete selected-source and single-row coverage of actual use.

    Parameters
    ----------
    receipts : tuple of SoftwareReceiptCheck
        Actual complete native equations and whole matched rows after preceding
        target, point-time, scope and revocation failures have been refused.
    sources : SoftwareSources
        Original independently selected current or archived whole source. The
        current floor is preserved; current rows never replace selected history.
    interval : ClockInterval
        ENTIRE actual calculated S0/capture/H/native-entry union. Its numerical
        consistency supplies no independently supported physical Clock.
    origin : str
        Exact independently installed native coordinate origin, without a new
        default, snapshot timestamp or later sampling operation.
    policy_reference : BlobRef
        Original whole policy for unsupported actual interval-to-UTC mapping.

    Raises
    ------
    InputRefused
        The selected source postdates any use or claimed signing time, or no
        single whole equation-verified row covers both inclusive use endpoints.
        Unsupported actual Clock interval coordinates retain the original refusal.
        Legal key/source UTC windows use the complete common calendar and precision.

    Notes
    -----
    Passing supplies this necessary temporal relation only. It grants no key
    custody, identity, possession, state authentication, physical Clock,
    independent run, record signature waiver or final class eligibility.
    """
    lower = Utc(
        coordinate_utc(
            interval.lower_ns,
            origin=origin,
            subject=policy_reference.digest,
            pointer=CLOCK_POINTER,
        )
    )
    upper = Utc(
        coordinate_utc(
            interval.upper_ns,
            origin=origin,
            subject=policy_reference.digest,
            pointer=CLOCK_POINTER,
        )
    )
    for receipt in receipts:
        signed_at = Utc(receipt.envelope.statement.value["claimed_signed_at"])
        if (
            sources.selected.issued_at.compare(lower) > 0
            or sources.selected.issued_at.compare(signed_at) > 0
            or not any(
                key.valid_from.compare(lower) <= 0 and upper.compare(key.valid_until) < 0
                for key in receipt.verified_keys
            )
        ):
            raise InputRefused(
                Reason(
                    "invalid_delegation",
                    receipt.envelope.reference.digest,
                    None,
                    "/statement/authorization_ref",
                    "Software authorization does not cover the complete verification interval.",
                )
            )
