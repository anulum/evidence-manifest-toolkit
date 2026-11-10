# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete original sample source calculation

"""Calculate the whole selected sample using its own raw sources and calibration."""

from collections.abc import Mapping
from fractions import Fraction

from ._budget import ReferenceBudget
from ._clock_bounds import AdditionalNtpBounds, NtpEstimate
from ._clock_method_types import ClockBoundDatum, ClockMethodSource
from ._clock_method_values import CLOCK_POINTER
from ._clock_raw_sample import read_raw_clock_sample
from ._clock_values import ClockSample, clock_unavailable
from ._timesyncd_estimate import derive_timesyncd_estimate
from ._timesyncd_message import parse_timesyncd_message
from ._values import BlobRef, Digest


def calculate_sample_estimate(
    sample: ClockSample,
    terms: Mapping[str, ClockBoundDatum],
    *,
    ntp: ClockMethodSource,
    raw: ClockMethodSource,
    ticks_per_second: Fraction,
    mapping_rule_ref: BlobRef,
    subject: Digest,
    budget: ReferenceBudget,
) -> NtpEstimate:
    """Recompute all eight N terms and the sample's acquisition, mapping and quantisation.

    Parameters
    ----------
    sample : ClockSample
        Whole original annual or invocation sample in its selected UTC coordinate.
    terms : Mapping
        All six explicit original per-sample bounds and their whole source bytes.
    ntp, raw : ClockMethodSource
        Explicitly associated original packet and realtime/bracket observation.
    ticks_per_second : Fraction
        Exact positive calibration of this sample's own original monotonic domain.
        A later invocation's rate is not an annual-input default.
    mapping_rule_ref : BlobRef
        Whole selected daemon mapping, without artifact-selected executable code.
    subject : str
        Original policy identity for the prescribed Clock-unavailable diagnostic.
    budget : ReferenceBudget
        SAME cumulative operation quota for original source and packet interpretation.

    Returns
    -------
    NtpEstimate
        Full exact conditional packet calculation. Actual source/model/calibration
        support, provenance class and Clock admission remain separate predicates.

    Raises
    ------
    InputRefused
        Original source, packet, quota, numeric mapping or any required sample bound fails.
    ConfigurationError
        The complete raw realtime capture has invalid closed grammar or field types.
    """
    utc, bracket = read_raw_clock_sample(
        raw,
        expected_ticks=sample.monotonic_ticks,
        ticks_per_second=ticks_per_second,
        subject=subject,
        budget=budget,
    )
    if utc != sample.utc_ns or terms["acquisition"].nanoseconds < bracket:
        raise clock_unavailable(subject, CLOCK_POINTER)
    message = parse_timesyncd_message(
        ntp.raw_bytes,
        reference=ntp.reference,
        budget=budget,
        subject=subject,
        pointer=CLOCK_POINTER,
    )
    additional = AdditionalNtpBounds(
        terms["source_encoding"].nanoseconds,
        terms["elapsed_holdover"].nanoseconds,
        terms["post_exchange_adjustment"].nanoseconds,
        terms["source_encoding"].source.reference,
        terms["elapsed_holdover"].source.reference,
        terms["post_exchange_adjustment"].source.reference,
    )
    estimate = derive_timesyncd_estimate(
        message,
        mapping_rule_ref=mapping_rule_ref,
        additional=additional,
        subject=subject,
        pointer=CLOCK_POINTER,
    )
    if (
        sample.accuracy_radius_ns < estimate.radius_ns + terms["acquisition"].nanoseconds
        or sample.mapping_error_bound_ns < terms["mapping"].nanoseconds
        or sample.quantization_error_bound_ns < terms["quantization"].nanoseconds
    ):
        raise clock_unavailable(subject, CLOCK_POINTER)
    return estimate
