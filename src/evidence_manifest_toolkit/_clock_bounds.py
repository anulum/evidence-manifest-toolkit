# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete exact NTP uncertainty calculation

"""Calculate every selected NTP term while preserving its actual source obligations."""

from dataclasses import dataclass
from fractions import Fraction
from math import ceil

from ._clock_values import NANOSECONDS_PER_SECOND, clock_unavailable
from ._values import BlobRef, Digest


@dataclass(frozen=True, slots=True)
class NtpMeasurement:
    """Retain the complete source-mapped NTP exchange without inventing source acceptance.

    Attributes
    ----------
    originate_ns, receive_ns, transmit_ns, destination_ns : int
        Whole exact coordinates after the independently selected encoding/rollover mapping.
        Differences use one coordinate system; no rounded status-table values are admitted.
    root_delay_ns, root_dispersion_ns : int
        Nonnegative decoded source terms with their actual encoding bounds retained separately.
    precision_exponent : int
        Signed eight-bit packet exponent from the selected NTP mapping.
    raw_source_ref, mapping_rule_ref : BlobRef
        Entire raw observation and independently selected mapping, both still requiring
        actual acquisition, identity, version/environment and source qualification.
    """

    originate_ns: int
    receive_ns: int
    transmit_ns: int
    destination_ns: int
    root_delay_ns: int
    root_dispersion_ns: int
    precision_exponent: int
    raw_source_ref: BlobRef
    mapping_rule_ref: BlobRef


@dataclass(frozen=True, slots=True)
class AdditionalNtpBounds:
    """Require every independently supported added term and its entire provenance.

    Attributes
    ----------
    source_encoding_ns, elapsed_holdover_ns, post_exchange_adjustment_ns : int
        Actual independently supported nonnegative bounds. No field has a zero default;
        an unavailable term cannot be represented by omission or converted to zero.
    source_encoding_ref, elapsed_holdover_ref, post_exchange_adjustment_ref : BlobRef
        Whole selected derivation/observation/model sources, never approval labels.
        Holding these declarations does not qualify their actual source predicates.
    """

    source_encoding_ns: int
    elapsed_holdover_ns: int
    post_exchange_adjustment_ns: int
    source_encoding_ref: BlobRef
    elapsed_holdover_ref: BlobRef
    post_exchange_adjustment_ref: BlobRef


@dataclass(frozen=True, slots=True)
class NtpEstimate:
    """Retain the exact offset and every separately calculated conservative source term.

    Attributes
    ----------
    measurement : NtpMeasurement
        Entire original exchange and its actual raw/mapping declarations.
    additional : AdditionalNtpBounds
        Every complete supplied bound and source reference, without hidden replacement.
    delay_ns : int
        Exact nonnegative round-trip delay D.
    offset_ns : Fraction
        Exact signed theta, including a possible half nanosecond. This value is never
        silently narrowed to fit an integer field in a later source body.
    offset_bound_ns, root_delay_bound_ns, root_dispersion_ns, delay_bound_ns : int
        Outward-rounded magnitude, root-delay half, original dispersion and delay half.
    precision_bound_ns : int
        Exact ceiling of the source precision in nanoseconds.
    """

    measurement: NtpMeasurement
    additional: AdditionalNtpBounds
    delay_ns: int
    offset_ns: Fraction
    offset_bound_ns: int
    root_delay_bound_ns: int
    root_dispersion_ns: int
    delay_bound_ns: int
    precision_bound_ns: int

    @property
    def radius_ns(self) -> int:
        """Return the complete selected eight-term source uncertainty N.

        Returns
        -------
        int
            Offset, root delay, dispersion, path delay, precision, encoding, elapsed
            holdover and post-exchange adjustment, with no term dropped or subtracted.
        """
        return (
            self.offset_bound_ns
            + self.root_delay_bound_ns
            + self.root_dispersion_ns
            + self.delay_bound_ns
            + self.precision_bound_ns
            + self.additional.source_encoding_ns
            + self.additional.elapsed_holdover_ns
            + self.additional.post_exchange_adjustment_ns
        )


def derive_ntp_estimate(
    measurement: NtpMeasurement, additional: AdditionalNtpBounds, *, subject: Digest, pointer: str
) -> NtpEstimate:
    """Recompute exact offset, delay and all selected conservative uncertainty terms.

    Parameters
    ----------
    measurement : NtpMeasurement
        Whole source-mapped exchange. Raw source identity, synchronization, authorized
        address/configuration and installed mapping qualification remain owning predicates.
    additional : AdditionalNtpBounds
        All independently supported encoding/holdover/adjustment terms and their sources.
    subject : str
        Whole independently selected policy identity.
    pointer : str
        Actual Clock requirement/source position.

    Returns
    -------
    NtpEstimate
        Exact theta and complete N. This calculation alone does not accept a Clock profile,
        prove source assumptions, qualify the declared bounds or admit a verification time.

    Raises
    ------
    InputRefused
        Backwards/negative/unsupported source values or an offset over five seconds
        prevent the selected Clock calculation.

    Notes
    -----
    The selected systemd v255 packet declares precision as int8_t. Its D-Bus mapping
    is a separate whole-source/version obligation. Integer source coordinates are
    used here only after their complete encoding/rollover bounds have been applied.
    """
    t1 = measurement.originate_ns
    t2 = measurement.receive_ns
    t3 = measurement.transmit_ns
    t4 = measurement.destination_ns
    if t4 < t1 or t3 < t2:
        raise clock_unavailable(subject, pointer)
    if (
        min(
            measurement.root_delay_ns,
            measurement.root_dispersion_ns,
            additional.source_encoding_ns,
            additional.elapsed_holdover_ns,
            additional.post_exchange_adjustment_ns,
        )
        < 0
    ):
        raise clock_unavailable(subject, pointer)
    exponent = measurement.precision_exponent
    if not -128 <= exponent <= 127:
        raise clock_unavailable(subject, pointer)
    delay = (t4 - t1) - (t3 - t2)
    offset = Fraction((t2 - t1) + (t3 - t4), 2)
    if delay < 0 or abs(offset) > 5 * NANOSECONDS_PER_SECOND:
        raise clock_unavailable(subject, pointer)
    precision = (
        Fraction(NANOSECONDS_PER_SECOND * (1 << exponent), 1)
        if exponent >= 0
        else Fraction(NANOSECONDS_PER_SECOND, 1 << -exponent)
    )
    return NtpEstimate(
        measurement,
        additional,
        delay,
        offset,
        ceil(abs(offset)),
        ceil(Fraction(measurement.root_delay_ns, 2)),
        measurement.root_dispersion_ns,
        ceil(Fraction(delay, 2)),
        ceil(precision),
    )
