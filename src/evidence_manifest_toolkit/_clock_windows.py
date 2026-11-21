# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole conservative capture and entry windows

"""Extend complete Clock uncertainty through actual entry without moving its fixed origin."""

from dataclasses import dataclass
from fractions import Fraction
from math import ceil, floor

from ._clock_values import (
    NANOSECONDS_PER_SECOND,
    ClockSample,
    civil_anniversary,
    clock_unavailable,
    coordinate_utc,
    elapsed_nanoseconds,
)
from ._utc import utc_key
from ._values import BlobRef, Digest

EVALUATION_BUDGET_NS = 5 * NANOSECONDS_PER_SECOND
"""Half-width of the budget around the evaluation origin that every Clock interval must fit."""


@dataclass(frozen=True, slots=True)
class ClockInterval:
    """Retain both inclusive integer endpoints of a conservative source interval.

    Attributes
    ----------
    lower_ns, upper_ns : int
        Complete outward-rounded lower and upper bounds in one selected coordinate.
    """

    lower_ns: int
    upper_ns: int


@dataclass(frozen=True, slots=True)
class UseErrorTerms:
    """Require all observed use/mapping terms and their whole derivation source.

    Attributes
    ----------
    acquisition_ns, mapping_ns, quantization_ns, adjustment_ns : int
        All independently supported nonnegative bounds, with no implicit zero term.
    derivation_ref : BlobRef
        Whole original observation/model derivation, still requiring its full source checks.
    """

    acquisition_ns: int
    mapping_ns: int
    quantization_ns: int
    adjustment_ns: int
    derivation_ref: BlobRef

    @property
    def total_ns(self) -> int:
        """Return all four actual added bounds without subtracting earlier uncertainty.

        Returns
        -------
        int
            Full acquisition, mapping, quantization and bounded-adjustment contribution.
        """
        return self.acquisition_ns + self.mapping_ns + self.quantization_ns + self.adjustment_ns


@dataclass(frozen=True, slots=True)
class ClockHandoff:
    """Retain whole use/entry observations and independently supported propagation inputs.

    Attributes
    ----------
    use_ticks, entry_ticks : int
        Original observed H and actual E in the same boot/process/calibrated domain.
        The owning fixed entry sampler must supply E; this value does not capture it.
    ticks_per_second, maximum_error_rate : Fraction
        Exact supported tick calibration and maximum added nanosecond error per elapsed
        nanosecond, with actual source assumptions checked by the owning method.
    use_error_bound_ns : int
        Entire declared additional H bound; it may conservatively overcount required terms.
    use_terms, entry_terms : UseErrorTerms
        Every actual non-drift addition and its whole independent derivation source.
    """

    use_ticks: int
    entry_ticks: int
    ticks_per_second: Fraction
    maximum_error_rate: Fraction
    use_error_bound_ns: int
    use_terms: UseErrorTerms
    entry_terms: UseErrorTerms


@dataclass(frozen=True, slots=True)
class ClockUse:
    """Keep complete capture, pre-call and actual-entry bounds as separate observations.

    Attributes
    ----------
    capture, at_use, at_entry, whole : ClockInterval
        Original capture and calculated H/E intervals plus their complete union.
        Entry results never replace or modify the earlier witness/policy source.
    required_use_error_ns, complete_entry_error_ns : int
        Recomputed H addition and the entire E radius including the after-sample error.
    """

    capture: ClockInterval
    at_use: ClockInterval
    at_entry: ClockInterval
    whole: ClockInterval
    required_use_error_ns: int
    complete_entry_error_ns: int


def capture_interval(
    before: ClockSample,
    after: ClockSample,
    *,
    ticks_per_second: Fraction,
    subject: Digest,
    pointer: str,
) -> ClockInterval:
    """Recompute complete capture endpoints and calibrated sample-order consistency.

    Parameters
    ----------
    before, after : ClockSample
        Whole coordinate-matching samples whose error terms still require raw-source proof.
    ticks_per_second : Fraction
        Exact selected positive calibration in one actual observed domain.
    subject : str
        Whole selected policy identity.
    pointer : str
        Actual selected Clock requirement position.

    Returns
    -------
    ClockInterval
        Entire [S0 UTC minus full error, S1 UTC plus full error] interval.

    Raises
    ------
    InputRefused
        Backwards/reset or incompatible full coordinate/calibration bounds prevent mapping.
    """
    elapsed = elapsed_nanoseconds(
        before.monotonic_ticks,
        after.monotonic_ticks,
        ticks_per_second=ticks_per_second,
        subject=subject,
        pointer=pointer,
    )
    if after.utc_ns < before.utc_ns or abs(after.utc_ns - before.utc_ns - elapsed) > (
        before.error_ns + after.error_ns
    ):
        raise clock_unavailable(subject, pointer)
    return ClockInterval(before.utc_ns - before.error_ns, after.utc_ns + after.error_ns)


def extend_interval(
    captured: ClockInterval,
    after: ClockSample,
    handoff: ClockHandoff,
    *,
    subject: Digest,
    pointer: str,
) -> ClockUse:
    """Add actual elapsed/drift/use bounds through E and retain the entire interval union.

    Parameters
    ----------
    captured : ClockInterval
        Complete original recomputed S0..S1 interval.
    after : ClockSample
        Whole original S1 with every source/bracket/mapping/quantization error retained.
    handoff : ClockHandoff
        Actual H/E and complete independently supported nonnegative propagation inputs.
    subject : str
        Whole policy identity.
    pointer : str
        Actual Clock requirement position.

    Returns
    -------
    ClockUse
        Separate conservative H/E intervals and full union, including a lower bound
        that can expand under holdover; checking only the later upper bound is insufficient.

    Raises
    ------
    InputRefused
        Missing ordering, negative bounds/rate or understated complete H error refuses mapping.
    """
    if handoff.entry_ticks < handoff.use_ticks or handoff.maximum_error_rate < 0:
        raise clock_unavailable(subject, pointer)
    for terms in (handoff.use_terms, handoff.entry_terms):
        if (
            min(terms.acquisition_ns, terms.mapping_ns, terms.quantization_ns, terms.adjustment_ns)
            < 0
        ):
            raise clock_unavailable(subject, pointer)
    use_elapsed = elapsed_nanoseconds(
        after.monotonic_ticks,
        handoff.use_ticks,
        ticks_per_second=handoff.ticks_per_second,
        subject=subject,
        pointer=pointer,
    )
    entry_elapsed = elapsed_nanoseconds(
        after.monotonic_ticks,
        handoff.entry_ticks,
        ticks_per_second=handoff.ticks_per_second,
        subject=subject,
        pointer=pointer,
    )
    required_use = ceil(handoff.maximum_error_rate * use_elapsed) + handoff.use_terms.total_ns
    if handoff.use_error_bound_ns < required_use:
        raise clock_unavailable(subject, pointer)
    use_error = after.error_ns + handoff.use_error_bound_ns
    entry_error = (
        use_error
        + ceil(handoff.maximum_error_rate * (entry_elapsed - use_elapsed))
        + handoff.entry_terms.total_ns
    )
    use_center = after.utc_ns + use_elapsed
    entry_center = after.utc_ns + entry_elapsed
    at_use = ClockInterval(floor(use_center - use_error), ceil(use_center + use_error))
    at_entry = ClockInterval(floor(entry_center - entry_error), ceil(entry_center + entry_error))
    whole = ClockInterval(
        min(captured.lower_ns, at_use.lower_ns, at_entry.lower_ns),
        max(captured.upper_ns, at_use.upper_ns, at_entry.upper_ns),
    )
    return ClockUse(captured, at_use, at_entry, whole, required_use, entry_error)


def require_five_second_budget(
    interval: ClockInterval, *, evaluation_origin_ns: int, subject: Digest, pointer: str
) -> None:
    """Check both full endpoints inclusively against the original S0-centred budget.

    Parameters
    ----------
    interval : ClockInterval
        Whole conservative capture-through-entry interval, not a center or partial range.
    evaluation_origin_ns : int
        Exact fixed earlier S0, never moved to traversal completion or entry UTC.
    subject : str
        Whole policy identity.
    pointer : str
        Actual selected Clock requirement.

    Raises
    ------
    InputRefused
        Either full endpoint exceeds five seconds around the fixed origin.
    """
    radius = EVALUATION_BUDGET_NS
    if interval.lower_ns > interval.upper_ns or not (
        evaluation_origin_ns - radius <= interval.lower_ns
        and interval.upper_ns <= evaluation_origin_ns + radius
    ):
        raise clock_unavailable(subject, pointer)


def require_half_open_window(
    interval: ClockInterval,
    *,
    valid_from: str,
    valid_until: str,
    origin: str,
    subject: Digest,
    pointer: str,
) -> None:
    """Require the entire inclusive interval inside an exact original half-open UTC window.

    Parameters
    ----------
    interval : ClockInterval
        Whole conservative range in the selected coordinate origin.
    valid_from, valid_until : str
        Entire original common UTC bounds, including all original fractional digits.
    origin : str
        Explicit source-selected coordinate origin.
    subject : str
        Whole policy identity.
    pointer : str
        Actual applicable authority/acceptance window position.

    Raises
    ------
    InputRefused
        A malformed, unsupported, reversed or boundary-crossing whole window refuses.
    """
    beginning = utc_key(valid_from, subject_digest=subject, pointer=pointer)
    ending = utc_key(valid_until, subject_digest=subject, pointer=pointer)
    lower = utc_key(
        coordinate_utc(interval.lower_ns, origin=origin, subject=subject, pointer=pointer)
    )
    upper = utc_key(
        coordinate_utc(interval.upper_ns, origin=origin, subject=subject, pointer=pointer)
    )
    if (
        interval.lower_ns > interval.upper_ns
        or not beginning < ending
        or not (beginning <= lower and upper < ending)
    ):
        raise clock_unavailable(subject, pointer)


def require_civil_year(valid_from: str, valid_until: str, *, subject: Digest, pointer: str) -> None:
    """Check exact anniversary spelling while preserving the whole source validity interval.

    Parameters
    ----------
    valid_from, valid_until : str
        Original start and end tokens; equivalent rounded/normalized suffixes do not match.
    subject : str
        Whole policy identity.
    pointer : str
        Actual acceptance validity position.

    Raises
    ------
    InputRefused
        The full lexical anniversary differs from the selected civil-year renewal rule.
    """
    utc_key(valid_until, subject_digest=subject, pointer=pointer)
    if valid_until != civil_anniversary(valid_from, subject=subject, pointer=pointer):
        raise clock_unavailable(subject, pointer)
