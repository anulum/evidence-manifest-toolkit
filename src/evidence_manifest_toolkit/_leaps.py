# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — independently pinned UTC leap history

"""Retain actual historical insertions without selecting a received time table."""

# IERS Leap_Second.dat SHA256:
# 6cb6f5d4b819f2e568e25db4b0b26d89dedf031fdffb18bc94d40f4e94e268d7
# Bulletin C72 SHA256:
# 310e172eadacacca3adf92cb9bd646fcc0d6320e35e996a106d2644ede3b52f0
# Initial offset10 at1972-01-01 is not an insertion. No negative step exists.
# Source coverage/explicit announcement are fixed, never inferred from a clock.
POSITIVE_LEAP_DAYS: frozenset[tuple[int, int, int]] = frozenset(
    (
        (1972, 6, 30),
        (1972, 12, 31),
        (1973, 12, 31),
        (1974, 12, 31),
        (1975, 12, 31),
        (1976, 12, 31),
        (1977, 12, 31),
        (1978, 12, 31),
        (1979, 12, 31),
        (1981, 6, 30),
        (1982, 6, 30),
        (1983, 6, 30),
        (1985, 6, 30),
        (1987, 12, 31),
        (1989, 12, 31),
        (1990, 12, 31),
        (1992, 6, 30),
        (1993, 6, 30),
        (1994, 6, 30),
        (1995, 12, 31),
        (1997, 6, 30),
        (1998, 12, 31),
        (2005, 12, 31),
        (2008, 12, 31),
        (2012, 6, 30),
        (2015, 6, 30),
        (2016, 12, 31),
    )
)
HISTORY_START = (1972, 1, 1)
HISTORY_COVERED_THROUGH = (2026, 7, 6)
EXPLICIT_NO_LEAP_DAYS: frozenset[tuple[int, int, int]] = frozenset(((2026, 12, 31),))
