# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact offline UTC source comparisons

"""Validate calendar fields and compare full fractions without host rounding."""

import calendar
import re

from ._errors import InputRefused
from ._leaps import (
    EXPLICIT_NO_LEAP_DAYS,
    HISTORY_COVERED_THROUGH,
    HISTORY_START,
    POSITIVE_LEAP_DAYS,
)
from ._values import Digest, Reason

_GRAMMAR = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?Z"
)
type UtcKey = tuple[int, int, int, int, int, int, str]


def utc_key(
    value: str, *, subject_digest: Digest | None = None, pointer: str | None = None
) -> UtcKey:
    """Read a complete UTC token while retaining every fractional digit.

    The caller retains the original string for hashing and serialization. The
    returned comparison key removes only insignificant trailing fraction zeros.
    No clock, epoch float or platform date parser supplies validity or precision.
    Genuine leap seconds use the independently pinned IERS history/C72 source.
    The parser does not consume an artifact table or infer future announcements.

    Parameters
    ----------
    value : str
        Original RFC3339 timestamp ending in uppercase Z.
    subject_digest : str or None
        Actual containing content identity, when already known.
    pointer : str or None
        Actual native field location, when applicable.

    Returns
    -------
    tuple
        Gregorian fields and exact decimal fraction ordered by the UTC instant.

    Raises
    ------
    InputRefused
        Invalid grammar/calendar or a leap outside the supported source history.
    """
    match = _GRAMMAR.fullmatch(value)
    if match is None:
        raise InputRefused(
            Reason("invalid_schema", subject_digest, None, pointer, "Invalid UTC timestamp.")
        )
    year, month, day, hour, minute, second = (int(match[i]) for i in range(1, 7))
    if not (
        1 <= month <= 12
        and 1 <= day <= calendar.monthrange(year, month)[1]
        and hour < 24
        and minute < 60
        and second <= 60
    ):
        raise InputRefused(
            Reason("invalid_schema", subject_digest, None, pointer, "Invalid UTC calendar fields.")
        )
    if second == 60:
        day_key = year, month, day
        if hour != 23 or minute != 59:
            raise InputRefused(
                Reason("invalid_schema", subject_digest, None, pointer, "Invalid leap-second time.")
            )
        if day_key not in POSITIVE_LEAP_DAYS:
            covered = (
                HISTORY_START <= day_key <= HISTORY_COVERED_THROUGH
                or day_key in EXPLICIT_NO_LEAP_DAYS
            )
            code = "invalid_schema" if covered else "unsupported_profile"
            detail = (
                "No leap second occurs on the declared day."
                if covered
                else "Leap-second source history does not cover the declared day."
            )
            raise InputRefused(Reason(code, subject_digest, None, pointer, detail))
    fraction = (match[7] or "").rstrip("0")
    return year, month, day, hour, minute, second, fraction
