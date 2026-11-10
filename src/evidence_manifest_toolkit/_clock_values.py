# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact selected Clock coordinates and complete samples

"""Retain exact Clock values without treating source declarations as qualified time."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from fractions import Fraction
from typing import cast

from ._codecs import decode_reference
from ._errors import InputRefused
from ._immutable import FrozenJson, freeze_json
from ._json import JsonValue
from ._utc import UtcKey, utc_key
from ._values import BlobRef, Digest, Reason

NANOSECONDS_PER_SECOND = 1_000_000_000
_DAY_NS = 86_400 * NANOSECONDS_PER_SECOND
_CLOCK_TOKEN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](?:\.[0-9]{1,9})?Z"
)
_INTEGER_TOKEN = re.compile(r"0|[1-9][0-9]*")
_SIGNED_INTEGER_TOKEN = re.compile(r"0|-?[1-9][0-9]*")


def clock_integer(value: str, *, signed: bool, subject: Digest, pointer: str) -> int:
    """Decode an entire canonical Clock integer without trimming or token normalization.

    Parameters
    ----------
    value : str
        Whole bounded source token after fixed-schema validation.
    signed : bool
        Whether the selected coordinate field permits a negative nonzero value.
    subject : str
        Actual containing policy or source identity.
    pointer : str
        Exact integer position.

    Returns
    -------
    int
        Exact original integer, preserving the unchanged original token in its source.

    Raises
    ------
    InputRefused
        A complete token, sign or length violates the canonical Clock encoding.
    """
    pattern = _SIGNED_INTEGER_TOKEN if signed else _INTEGER_TOKEN
    if len(value) > 256 or pattern.fullmatch(value) is None:
        raise InputRefused(
            Reason("invalid_schema", subject, None, pointer, "Invalid Clock integer encoding.")
        )
    return int(value)


def clock_unavailable(subject: Digest, pointer: str) -> InputRefused:
    """Retain the original evaluation-time refusal for an unsupported Clock mapping.

    Parameters
    ----------
    subject : str
        Whole independently selected policy identity.
    pointer : str
        Actual Clock requirement or source position.

    Returns
    -------
    InputRefused
        Located unavailable predicate for the owning verification composer. Malformed
        common UTC and other source failures retain their separate original codes.
    """
    return InputRefused(
        Reason(
            "policy_unavailable",
            subject,
            None,
            pointer,
            "The required evaluation-time qualification is unavailable.",
        )
    )


def _components(value: str, *, subject: Digest, pointer: str) -> UtcKey:
    """Check the selected Clock profile after validating the original common UTC law.

    Parameters
    ----------
    value : str
        Whole original UTC token, retained unchanged for source equality and hashing.
    subject : str
        Actual containing policy identity.
    pointer : str
        Actual source coordinate position.

    Returns
    -------
    tuple
        Exact Gregorian fields and decimal fraction within the selected Clock profile.

    Raises
    ------
    InputRefused
        Common UTC is malformed, or a legal common value has no selected Clock mapping.
    """
    result = utc_key(value, subject_digest=subject, pointer=pointer)
    if result[0] == 0 or _CLOCK_TOKEN.fullmatch(value) is None:
        raise clock_unavailable(subject, pointer)
    return result


def civil_nanoseconds(value: str, *, subject: Digest, pointer: str) -> int:
    """Calculate exact Gregorian nanoseconds from the first civil day without floats.

    Parameters
    ----------
    value : str
        Complete original Clock-profile UTC token.
    subject : str
        Containing policy identity.
    pointer : str
        Literal source coordinate position.

    Returns
    -------
    int
        Private civil coordinate relative to year1 January1, not an inferred wire epoch.

    Raises
    ------
    InputRefused
        The value is malformed or unsupported by the selected Clock coordinate profile.
    """
    year, month, day, hour, minute, second, fraction = _components(
        value, subject=subject, pointer=pointer
    )
    days = date(year, month, day).toordinal() - 1
    return ((days * 24 + hour) * 3600 + minute * 60 + second) * NANOSECONDS_PER_SECOND + int(
        fraction.ljust(9, "0")
    )


def coordinate_nanoseconds(value: str, *, origin: str, subject: Digest, pointer: str) -> int:
    """Map UTC using the complete independently selected method's explicit origin.

    Parameters
    ----------
    value, origin : str
        Exact Clock UTC and independently selected origin; neither has a hidden default.
    subject : str
        Whole containing policy identity.
    pointer : str
        Actual source coordinate position.

    Returns
    -------
    int
        Exact signed nanoseconds, retaining pre-origin values without clipping.
    """
    return civil_nanoseconds(value, subject=subject, pointer=pointer) - civil_nanoseconds(
        origin, subject=subject, pointer=pointer
    )


def coordinate_utc(value: int, *, origin: str, subject: Digest, pointer: str) -> str:
    """Render an exact calculated interval endpoint without normalizing source lexemes.

    Parameters
    ----------
    value : int
        Calculated signed nanosecond coordinate.
    origin : str
        Explicit origin selected by the same whole fixed method.
    subject : str
        Whole policy identity for unsupported-range diagnostics.
    pointer : str
        Actual interval position.

    Returns
    -------
    str
        Generated endpoint UTC, with at most nine exact fractional digits.

    Raises
    ------
    InputRefused
        The entire calculated endpoint lies outside the selected Gregorian range.
    """
    absolute = value + civil_nanoseconds(origin, subject=subject, pointer=pointer)
    days, day_ns = divmod(absolute, _DAY_NS)
    if not 0 <= days < date.max.toordinal():
        raise clock_unavailable(subject, pointer)
    seconds, fraction = divmod(day_ns, NANOSECONDS_PER_SECOND)
    hour, remainder = divmod(seconds, 3600)
    minute, second = divmod(remainder, 60)
    suffix = "" if fraction == 0 else "." + f"{fraction:09d}".rstrip("0")
    return (
        date.fromordinal(days + 1).isoformat() + f"T{hour:02d}:{minute:02d}:{second:02d}{suffix}Z"
    )


def civil_anniversary(value: str, *, subject: Digest, pointer: str) -> str:
    """Apply one civil year with February29 clamped and the exact lexical suffix retained.

    Parameters
    ----------
    value : str
        Whole source validity-start UTC token.
    subject : str
        Actual policy identity.
    pointer : str
        Source validity position.

    Returns
    -------
    str
        Exact required anniversary token, preserving original fractional spelling.

    Raises
    ------
    InputRefused
        The start or next anniversary has no mapping in the selected Clock range.
    """
    year, month, day, *_ = _components(value, subject=subject, pointer=pointer)
    if year == 9999:
        raise clock_unavailable(subject, pointer)
    suffix = "-02-28" + value[10:] if (month, day) == (2, 29) else value[4:]
    return f"{year + 1:04d}" + suffix


def elapsed_nanoseconds(
    before: int, after: int, *, ticks_per_second: Fraction, subject: Digest, pointer: str
) -> Fraction:
    """Convert nonnegative calibrated tick elapsed time without binary64 or rounding.

    Parameters
    ----------
    before, after : int
        Whole observed ticks within one actual admitted monotonic domain.
    ticks_per_second : Fraction
        Exact positive independently supported calibration, not a nominal frequency estimate.
    subject : str
        Whole policy identity.
    pointer : str
        Actual selected tick-source position.

    Returns
    -------
    Fraction
        Complete exact elapsed nanoseconds; no floor removes uncertainty.

    Raises
    ------
    InputRefused
        A reset, backwards observation or unsupported calibration prevents this mapping.
    """
    if before < 0 or after < before or ticks_per_second <= 0:
        raise clock_unavailable(subject, pointer)
    return Fraction((after - before) * NANOSECONDS_PER_SECOND, 1) / ticks_per_second


@dataclass(frozen=True, slots=True)
class ClockSample:
    """Retain every sample field and all independent conservative error components.

    Attributes
    ----------
    utc_lexeme : str
        Whole original UTC, unchanged even when an equivalent coordinate exists.
    utc_ns, monotonic_ticks : int
        Exact matching coordinate and original nonnegative tick value.
    accuracy_radius_ns, mapping_error_bound_ns, quantization_error_bound_ns : int
        All three original error terms; accuracy already includes source and bracket.
    raw_reference : BlobRef
        Complete declared raw capture identity; parsing does not qualify its provenance.
    source : Mapping
        Entire immutable original seven-field sample, retaining every numeric lexeme.
    """

    utc_lexeme: str
    utc_ns: int
    monotonic_ticks: int
    accuracy_radius_ns: int
    mapping_error_bound_ns: int
    quantization_error_bound_ns: int
    raw_reference: BlobRef
    source: Mapping[str, FrozenJson]

    @property
    def error_ns(self) -> int:
        """Return source-plus-bracket, mapping and quantization error without subtraction.

        Returns
        -------
        int
            Complete sum of all three separately retained conservative components.
        """
        return (
            self.accuracy_radius_ns + self.mapping_error_bound_ns + self.quantization_error_bound_ns
        )

    @classmethod
    def from_value(
        cls, value: Mapping[str, JsonValue], *, origin: str, subject: Digest, pointer: str
    ) -> "ClockSample":
        """Interpret a whole fixed-schema-valid sample and check its exact coordinate join.

        Parameters
        ----------
        value : Mapping
            Entire seven-field source, already validated with its whole pinned Clock schema.
        origin : str
            Explicit independently selected coordinate origin.
        subject : str
            Whole policy identity.
        pointer : str
            Actual sample position within its whole body.

        Returns
        -------
        ClockSample
            Exact values and immutable source; no raw bound or capture becomes qualified here.

        Raises
        ------
        InputRefused
            The selected coordinate mapping or whole UTC/integer equality fails.
        """
        utc = cast(str, value["utc_lexeme"])
        coordinate = coordinate_nanoseconds(utc, origin=origin, subject=subject, pointer=pointer)
        if coordinate != clock_integer(
            cast(str, value["utc_epoch_ns"]),
            signed=True,
            subject=subject,
            pointer=pointer + "/utc_epoch_ns",
        ):
            raise clock_unavailable(subject, pointer + "/utc_epoch_ns")
        return cls(
            utc,
            coordinate,
            clock_integer(
                cast(str, value["monotonic_ticks"]),
                signed=False,
                subject=subject,
                pointer=pointer + "/monotonic_ticks",
            ),
            clock_integer(
                cast(str, value["accuracy_radius_ns"]),
                signed=False,
                subject=subject,
                pointer=pointer + "/accuracy_radius_ns",
            ),
            clock_integer(
                cast(str, value["mapping_error_bound_ns"]),
                signed=False,
                subject=subject,
                pointer=pointer + "/mapping_error_bound_ns",
            ),
            clock_integer(
                cast(str, value["quantization_error_bound_ns"]),
                signed=False,
                subject=subject,
                pointer=pointer + "/quantization_error_bound_ns",
            ),
            decode_reference(
                value["clock_sample_raw_ref"],
                subject=subject,
                pointer=pointer + "/clock_sample_raw_ref",
            ),
            cast(Mapping[str, FrozenJson], freeze_json(dict(value))),
        )
