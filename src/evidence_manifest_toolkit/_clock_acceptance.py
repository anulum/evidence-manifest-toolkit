# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole original annual clock acceptance capture

"""Recompute complete acceptance sample relations without admitting physical source bounds."""

from fractions import Fraction
from typing import cast

from ._budget import ReferenceBudget
from ._clock_method_types import ClockMethodSource
from ._clock_method_values import CLOCK_POINTER
from ._clock_raw_sample import read_raw_clock_sample
from ._clock_subject import BoundClockSubject
from ._clock_values import ClockSample, clock_integer, clock_unavailable
from ._clock_windows import (
    ClockInterval,
    capture_interval,
    require_five_second_budget,
)
from ._json import JsonValue
from ._values import BlobRef


def calculate_acceptance_capture(
    clock: BoundClockSubject,
    *,
    sources: tuple[ClockMethodSource, ClockMethodSource],
    policy_reference: BlobRef,
    budget: ReferenceBudget,
) -> ClockInterval:
    """Check the entire original acceptance capture against its own source domain and full budget.

    Parameters
    ----------
    clock : BoundClockSubject
        Whole matching invocation, original annual acceptance and installed UTC origin.
        Current entry ticks never replace the earlier acceptance's observations.
    sources : tuple of ClockMethodSource
        Complete original before/after raw sources in that order, acquired under the
        same invocation quota with their actual full metadata and dependency graphs.
    policy_reference : BlobRef
        Original selected policy for the prescribed evaluation-time refusal.
    budget : ReferenceBudget
        SAME original allowance for bounded strict interpretation of retained raw bytes.

    Returns
    -------
    ClockInterval
        Whole original declared acceptance interval after raw/sample/order/budget
        checks. Declared error/calibration provenance, actual synchronization, six annual
        predicates, physical source/model support and class admission remain required.

    Raises
    ------
    InputRefused
        Original raw source or numerical mapping fails, capture/order is inconsistent,
        an acquisition bracket is understated, or full five-second budget containment fails.
    ConfigurationError
        A retained raw capture violates the installed complete fixed record grammar.
    """
    subject = policy_reference.digest
    value = cast(dict[str, JsonValue], clock.sources.documents["acceptance"].value)
    rate = cast(dict[str, JsonValue], value["ticks_per_second"])
    calibration = Fraction(
        clock_integer(
            cast(str, rate["numerator"]), signed=False, subject=subject, pointer=CLOCK_POINTER
        ),
        clock_integer(
            cast(str, rate["denominator"]), signed=False, subject=subject, pointer=CLOCK_POINTER
        ),
    )
    before, after = (
        ClockSample.from_value(
            cast(dict[str, JsonValue], value[name]),
            origin=clock.native_entry.origin,
            subject=subject,
            pointer=CLOCK_POINTER,
        )
        for name in ("before", "after")
    )
    for sample, source in zip((before, after), sources, strict=True):
        utc, bracket = read_raw_clock_sample(
            source,
            expected_ticks=sample.monotonic_ticks,
            ticks_per_second=calibration,
            subject=subject,
            budget=budget,
        )
        if utc != sample.utc_ns or sample.accuracy_radius_ns < bracket:
            raise clock_unavailable(subject, CLOCK_POINTER)
    recomputed = capture_interval(
        before, after, ticks_per_second=calibration, subject=subject, pointer=CLOCK_POINTER
    )
    declared = ClockInterval(
        clock_integer(
            cast(str, value["acceptance_utc_lower_ns"]),
            signed=True,
            subject=subject,
            pointer=CLOCK_POINTER,
        ),
        clock_integer(
            cast(str, value["acceptance_utc_upper_ns"]),
            signed=True,
            subject=subject,
            pointer=CLOCK_POINTER,
        ),
    )
    if declared.lower_ns > recomputed.lower_ns or declared.upper_ns < recomputed.upper_ns:
        raise clock_unavailable(subject, CLOCK_POINTER)
    require_five_second_budget(
        declared, evaluation_origin_ns=before.utc_ns, subject=subject, pointer=CLOCK_POINTER
    )
    return declared
