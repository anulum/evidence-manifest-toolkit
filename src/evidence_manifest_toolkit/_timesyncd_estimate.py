# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit timesyncd reported-unit and encoding-error mapping

"""Map the entire selected daemon observation into the exact conditional NTP calculation."""

from ._clock_bounds import (
    AdditionalNtpBounds,
    NtpEstimate,
    NtpMeasurement,
    derive_ntp_estimate,
)
from ._clock_values import clock_unavailable
from ._timesyncd_message import TimesyncdMessage
from ._values import BlobRef, Digest

_ERA0_END_US = 2_085_978_496_000_000
_SHORT_UNSIGNED_MAX_US = 65_535_999_984
_SHORT_SIGNED_NEGATIVE_US = 32_768_000_000
_MICROSECOND_ENCODING_BOUND_NS = 6_000


def derive_timesyncd_estimate(
    message: TimesyncdMessage,
    *,
    mapping_rule_ref: BlobRef,
    additional: AdditionalNtpBounds,
    subject: Digest,
    pointer: str,
) -> NtpEstimate:
    """Map exact reported coordinates and retain every mandatory uncertainty source.

    Parameters
    ----------
    message : TimesyncdMessage
        ENTIRE independently acquired fixed structured observation and its original source.
        Source version, configuration, server/address, class and capture chronology must
        still match the whole selected method; daemon fields alone do not establish them.
    mapping_rule_ref : BlobRef
        Whole independently selected mapping rule, requiring actual byte/implementation/
        environment correspondence. The reference never loads artifact-selected code.
    additional : AdditionalNtpBounds
        Complete actual encoding/holdover/post-exchange-adjustment bounds and whole
        derivation sources. None has a default or is inferred from Frequency or jitter.
    subject : str
        Entire selected policy identity for the original Clock-unavailable reason.
    pointer : str
        Actual selected Clock requirement/source position.

    Returns
    -------
    NtpEstimate
        Exact reported-coordinate D/theta and all eight conditional source-error terms,
        with whole raw/mapping/additional references. This is no complete Clock pass:
        accepted bound provenance, actual bracket/mapping/quantization, calibrated use
        and entry observations, request joins and full validity windows remain required.

    Raises
    ------
    InputRefused
        Unsynchronized/ignored/unsupported protocol data, signed root-delay encoding,
        unresolved rollover, insufficient encoding bound or an invalid exact NTP
        calculation prevents this selected source mapping. No term is silently zeroed.

    Notes
    -----
    The systemd v255 timesyncd-bus.c mapping emits integer microseconds. Multiplication
    by 1000 preserves those reported coordinates, not discarded fractional information.
    A conservative symmetric 1us error for each of four timestamps contributes at most
    2us to theta and 2us to D/2; root delay/2 adds 0.5us and root dispersion 1us.
    Rounding that 5.5us sum outward to 6us supplies this adapter's conservative
    conversion allowance, not a tight minimum error or a physical source calibration.
    The COMPLETE encoding bound must include it and all other supported source errors.
    The v255 timestamp conversion supplies no era-unfolding evidence; values outside
    its unambiguous Unix-coordinate era0 range refuse instead of inventing a rollover.
    """
    if (
        message.leap > 2
        or message.version not in (3, 4)
        or message.mode != 4
        or not 1 <= message.stratum < 16
        or message.ignored
        or message.packet_count == 0
        or message.root_delay_us >= _SHORT_SIGNED_NEGATIVE_US
        or message.root_dispersion_us > _SHORT_UNSIGNED_MAX_US
        or additional.source_encoding_ns < _MICROSECOND_ENCODING_BOUND_NS
    ):
        raise clock_unavailable(subject, pointer)
    coordinates = (
        message.originate_us,
        message.receive_us,
        message.transmit_us,
        message.destination_us,
    )
    if any(not 0 <= value < _ERA0_END_US for value in coordinates):
        raise clock_unavailable(subject, pointer)
    measurement = NtpMeasurement(
        message.originate_us * 1000,
        message.receive_us * 1000,
        message.transmit_us * 1000,
        message.destination_us * 1000,
        message.root_delay_us * 1000,
        message.root_dispersion_us * 1000,
        message.precision,
        message.raw_source_ref,
        mapping_rule_ref,
    )
    return derive_ntp_estimate(measurement, additional, subject=subject, pointer=pointer)
