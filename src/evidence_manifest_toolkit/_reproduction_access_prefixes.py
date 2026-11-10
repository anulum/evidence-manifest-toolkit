# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — immutable whole staged native access prefixes

"""Preserve earlier whole access events and capture bindings across the original stages."""

from typing import cast

from ._format_sources import FixedSource
from ._json import AcquiredDocument, JsonValue
from ._values import Reason


def native_access_prefix_reasons(
    access: tuple[FixedSource, ...], *, claim_id: str
) -> tuple[Reason, ...]:
    """Compare whole run, release and comparison prefixes without admitting capture truth.

    Parameters
    ----------
    access : tuple of FixedSource
        Complete already closed run/release/comparison access sources in that order.
        Their original shapes and per-record sequence law are checked by the caller.
    claim_id : str
        Original containing validation claim, retained in each located diagnostic.

    Returns
    -------
    tuple of Reason
        Exact later source and field for a changed capture binding or earlier event.
        All original event fields and Ref metadata participate. Empty or unchanged
        prefixes are source-consistent only: actual completeness, loss, event time,
        method, recorder custody and isolation still require their owning qualifier.
        Recorder identity is distinct from each event's observed process identity.
    """
    reasons: list[Reason] = []
    for earlier_source, later_source in zip(access, access[1:], strict=False):
        earlier = cast(
            dict[str, JsonValue], cast(AcquiredDocument, earlier_source.source.document).value
        )
        later = cast(
            dict[str, JsonValue], cast(AcquiredDocument, later_source.source.document).value
        )
        earlier_events = cast(list[JsonValue], earlier["events"])
        later_events = cast(list[JsonValue], later["events"])
        checks = [
            (field, later[field], earlier[field])
            for field in (
                "access_method_ref",
                "access_method_qualification_ref",
                "recorder_process_identity_ref",
                "environment_ref",
                "policy_and_input_boundary_ref",
            )
        ]
        checks.append(("events", later_events[: len(earlier_events)], earlier_events))
        for field, actual, expected in checks:
            if actual != expected:
                reasons.append(
                    Reason(
                        "invalid_claim",
                        later_source.source.reference.digest,
                        claim_id,
                        "/" + field,
                        "Native access prefixes conflict.",
                    )
                )
    return tuple(reasons)
