# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected protected ordinary use intervals

"""Check whole selected temporal sources without admitting protected authority."""

from typing import cast

from ._clock_method_values import CLOCK_POINTER
from ._clock_values import coordinate_utc
from ._clock_windows import ClockInterval
from ._codecs import decode_reference
from ._errors import InputRefused
from ._format_sources import FixedSource
from ._json import AcquiredDocument, JsonValue
from ._protected_control_sources import ProtectedControlSources
from ._protected_ordinary_sources import ProtectedOrdinarySource
from ._values import BlobRef, Reason, Utc


def check_protected_use_intervals(
    protected: ProtectedControlSources,
    *,
    receipts: tuple[ProtectedOrdinarySource, ...],
    interval: ClockInterval,
    origin: str,
    policy_reference: BlobRef,
) -> None:
    """Require the complete ordinary use interval inside every actual selected source window.

    Parameters
    ----------
    protected : ProtectedControlSources
        Whole independently selected grant and exact current or archived snapshot.
        Older control histories are retained without requalifying their past signers at E.
    receipts : tuple of ProtectedOrdinarySource
        Actual matched ordinary receipt certificates and complete already rooted parent
        graphs. Unrelated historical certificates are not selected as current authorisers.
    interval : ClockInterval
        Both inclusive conservative S0-through-native-E endpoints, without moving S0.
    origin : str
        Explicit installed native coordinate origin. Source windows retain the entire
        common UTC calendar and precision rather than the sampler's narrower range.
    policy_reference : BlobRef
        Original policy for an unsupported interval-to-UTC mapping.

    Raises
    ------
    InputRefused
        The selected snapshot postdates its ordinary statement, or any full use endpoint
        precedes a selected lower bound or reaches its excluded
        upper bound. Original unsupported Clock mapping keeps its original diagnostic.

    Notes
    -----
    An until-withdrawal grant has an explicitly absent upper bound, not authenticated
    infinity. Actual current withdrawal, root/custody/identity, historical signing-time,
    native control/signature, Clock/model and full class predicates remain required.
    """
    lower, upper = (
        Utc(
            coordinate_utc(
                endpoint,
                origin=origin,
                subject=policy_reference.digest,
                pointer=CLOCK_POINTER,
            )
        )
        for endpoint in (interval.lower_ns, interval.upper_ns)
    )
    state = protected.state_sources
    grant = cast(dict[str, JsonValue], cast(AcquiredDocument, state.grant.source.document).value)
    lifetime = cast(dict[str, JsonValue], grant["lifetime"])
    windows: list[tuple[FixedSource, str, str | None, str, str]] = [
        (
            state.grant,
            cast(str, lifetime["not_before"]),
            cast(str, lifetime["not_after"]) if lifetime["kind"] == "finite" else None,
            "/lifetime/not_before",
            "/lifetime/not_after",
        ),
        (
            state.selected.fixed,
            str(state.selected.issued_at),
            str(state.selected.expires_at),
            "/issued_at",
            "/expires_at",
        ),
    ]
    certificates = {source.source.reference: source for source in protected.certificates}
    for receipt in receipts:
        signed_at = Utc(receipt.envelope.statement.value["claimed_signed_at"])
        if state.selected.issued_at.compare(signed_at) > 0:
            raise InputRefused(
                Reason(
                    "invalid_delegation",
                    state.selected.fixed.source.reference.digest,
                    None,
                    "/issued_at",
                    "Protected authorisation does not precede its ordinary statement.",
                )
            )
        certificate = receipt.certificate
        while certificate.source.reference != state.grant.source.reference:
            value = cast(
                dict[str, JsonValue], cast(AcquiredDocument, certificate.source.document).value
            )
            windows.append(
                (
                    certificate,
                    cast(str, value["not_before"]),
                    cast(str, value["not_after"]),
                    "/not_before",
                    "/not_after",
                )
            )
            parent = decode_reference(
                value["parent_authorization_ref"],
                subject=certificate.source.reference.digest,
                pointer="/parent_authorization_ref",
            )
            certificate = (
                state.grant if parent == state.grant.source.reference else certificates[parent]
            )
    for source, beginning, ending, lower_pointer, upper_pointer in windows:
        early = Utc(beginning).compare(lower) > 0
        late = ending is not None and upper.compare(Utc(ending)) >= 0
        if early or late:
            raise InputRefused(
                Reason(
                    "invalid_delegation",
                    source.source.reference.digest,
                    None,
                    lower_pointer if early else upper_pointer,
                    "Protected authorisation does not cover the complete verification interval.",
                )
            )
