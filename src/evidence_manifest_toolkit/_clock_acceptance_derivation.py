# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete original annual sample derivations

"""Recompute original annual packet and sample relations without claiming physical support."""

from dataclasses import dataclass
from fractions import Fraction
from typing import cast

from ._budget import ReferenceBudget
from ._clock_acceptance import calculate_acceptance_capture
from ._clock_bounds import NtpEstimate
from ._clock_method_types import ClockAcceptanceInputs
from ._clock_method_values import CLOCK_POINTER
from ._clock_sample_estimate import calculate_sample_estimate
from ._clock_subject import BoundClockSubject
from ._clock_values import ClockSample, clock_integer, clock_unavailable
from ._clock_windows import ClockInterval, require_half_open_window
from ._json import JsonValue
from ._values import BlobRef


@dataclass(frozen=True, slots=True)
class ClockAcceptanceCalculation:
    """Retain both whole original annual estimates and their complete capture interval.

    Attributes
    ----------
    inputs : ClockAcceptanceInputs
        Entire selected original annual record, associations, bounds and source bytes.
    before, after : NtpEstimate
        Exact signed original packet offsets and all eight N contributions per sample.
        Conditional calculations do not establish actual physical source/model admission.
    capture : ClockInterval
        Whole original annual capture after source/sample/error/window consistency checks.
        This does not require capture inside its own later issued acceptance window.
    """

    inputs: ClockAcceptanceInputs
    before: NtpEstimate
    after: NtpEstimate
    capture: ClockInterval


def calculate_acceptance_derivation(
    inputs: ClockAcceptanceInputs,
    *,
    clock: BoundClockSubject,
    policy_reference: BlobRef,
    budget: ReferenceBudget,
) -> ClockAcceptanceCalculation:
    """Calculate both original annual samples and the explicitly associated signed offset.

    Parameters
    ----------
    inputs : ClockAcceptanceInputs
        Whole original raw method, before/after associations and all six terms per sample.
        Later request-bound derivations cannot replace these sources.
    clock : BoundClockSubject
        Whole matching original annual acceptance, profile and explicit installed UTC origin.
        Its current native entry ticks/rate are not annual observation defaults.
    policy_reference : BlobRef
        Original selected policy for the prescribed Clock-unavailable diagnostic.
    budget : ReferenceBudget
        SAME original quota for raw/sample/packet interpretation and every prior source.

    Returns
    -------
    ClockAcceptanceCalculation
        Complete conditional sample/capture calculations. Physical model, calibration,
        source/version/address and six annual class predicates still require admission.
        Original capture consistency precedes derivation of its error contributions.

    Raises
    ------
    InputRefused
        A source, packet, numeric mapping, sample bound, selected signed offset or original
        method applicability window fails. Original typed source/quota errors are retained.
    ConfigurationError
        A whole raw capture violates its installed closed record grammar or field types.
    """
    subject = policy_reference.digest
    capture = calculate_acceptance_capture(
        clock, sources=inputs.raw_samples, policy_reference=policy_reference, budget=budget
    )
    annual = cast(dict[str, JsonValue], clock.sources.documents["acceptance"].value)
    rate = cast(dict[str, JsonValue], annual["ticks_per_second"])
    calibration = Fraction(
        clock_integer(
            cast(str, rate["numerator"]), signed=False, subject=subject, pointer=CLOCK_POINTER
        ),
        clock_integer(
            cast(str, rate["denominator"]), signed=False, subject=subject, pointer=CLOCK_POINTER
        ),
    )
    mapping = dict(inputs.record.evidence)["/daemon_field_mapping_rule_ref"].reference
    estimates: list[NtpEstimate] = []
    for index, (name, bounds) in enumerate(
        (("before", inputs.before_bounds), ("after", inputs.after_bounds))
    ):
        sample = ClockSample.from_value(
            cast(dict[str, JsonValue], annual[name]),
            origin=clock.native_entry.origin,
            subject=subject,
            pointer=CLOCK_POINTER,
        )
        estimates.append(
            calculate_sample_estimate(
                sample,
                bounds,
                ntp=inputs.ntp_sources[index],
                raw=inputs.raw_samples[index],
                ticks_per_second=calibration,
                mapping_rule_ref=mapping,
                subject=subject,
                budget=budget,
            )
        )
    selected = next(
        estimate
        for source, estimate in zip(inputs.ntp_sources, estimates, strict=True)
        if source.reference == inputs.measured_offset_source.reference
    )
    measured = clock_integer(
        cast(str, annual["measured_ntp_offset_ns"]),
        signed=True,
        subject=subject,
        pointer=CLOCK_POINTER,
    )
    if selected.offset_ns != measured:
        raise clock_unavailable(subject, CLOCK_POINTER)
    require_half_open_window(
        capture,
        valid_from=cast(str, inputs.record.declaration["valid_from"]),
        valid_until=cast(str, inputs.record.declaration["valid_until"]),
        origin=clock.native_entry.origin,
        subject=subject,
        pointer=CLOCK_POINTER,
    )
    return ClockAcceptanceCalculation(inputs, estimates[0], estimates[1], capture)
