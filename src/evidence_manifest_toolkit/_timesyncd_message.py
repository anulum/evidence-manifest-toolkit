# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole structured timesyncd message and original source custody

"""Decode the fixed integer D-Bus reply without promoting daemon fields to Clock proof."""

import re
from dataclasses import dataclass

from ._acquisition import identity_reason
from ._budget import ReferenceBudget
from ._clock_values import clock_unavailable
from ._errors import InputRefused
from ._values import BlobRef, Digest


@dataclass(frozen=True, slots=True)
class TimesyncdMessage:
    """Retain every field of the whole original structured NTPMessage observation.

    Attributes
    ----------
    raw_source_ref : BlobRef
        Entire independently selected original reference, with unchanged metadata.
    raw_bytes : bytes
        Whole original fixed busctl reply, including its actual terminal newline.
    leap, version, mode, stratum : int
        Actual unsigned32 D-Bus values; parsing alone asserts no synchronized protocol state.
    precision : int
        Complete signed32 reported value; the packet's supported int8 range is separate.
    root_delay_us, root_dispersion_us : int
        Whole unsigned64 reported microseconds, never rounded human status strings.
    reference_id : bytes
        All four original packet reference octets, without address/identity inference.
    originate_us, receive_us, transmit_us, destination_us : int
        All four reported coordinates, retaining the mapping's microsecond resolution.
    ignored : bool
        Original daemon spike/ignore state, never silently dropped.
    packet_count, jitter_us : int
        Entire observed count and jitter. Jitter supplies no worst-case drift bound.
    """

    raw_source_ref: BlobRef
    raw_bytes: bytes
    leap: int
    version: int
    mode: int
    stratum: int
    precision: int
    root_delay_us: int
    root_dispersion_us: int
    reference_id: bytes
    originate_us: int
    receive_us: int
    transmit_us: int
    destination_us: int
    ignored: bool
    packet_count: int
    jitter_us: int


def _integer(token: str, *, bits: int, signed: bool, subject: Digest, pointer: str) -> int:
    """Read one complete D-Bus integer under its actual fixed wire width.

    Parameters
    ----------
    token : str
        Original untrimmed token, without exponent, sign coercion or leading zeros.
    bits : int
        Fixed8/32/64 wire width chosen by the installed adapter.
    signed : bool
        Only the precision field uses a signed D-Bus value.
    subject : str
        Actual containing selected policy identity.
    pointer : str
        Original Clock source requirement position.

    Returns
    -------
    int
        Exact complete integer, without a floating-point conversion.

    Raises
    ------
    InputRefused
        The whole token or numeric range has no selected source mapping.
    """
    pattern = r"0|-?[1-9][0-9]*" if signed else r"0|[1-9][0-9]*"
    if len(token) > 20 or re.fullmatch(pattern, token) is None:
        raise clock_unavailable(subject, pointer)
    value = int(token)
    lower = -(1 << (bits - 1)) if signed else 0
    upper = 1 << (bits - 1 if signed else bits)
    if not lower <= value < upper:
        raise clock_unavailable(subject, pointer)
    return value


def parse_timesyncd_message(
    data: bytes,
    *,
    reference: BlobRef,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> TimesyncdMessage:
    """Acquire every fixed v255 structured field under the sole operation budget.

    Parameters
    ----------
    data : bytes
        Whole actual busctl NTPMessage reply, never the human-readable timesync table.
    reference : BlobRef
        Entire independently selected original raw source declaration; no schema metadata
        is stripped. Registered schema assertions require separate whole graph validation.
    budget : ReferenceBudget
        SAME invocation byte/count/metadata budget, including previously acquired sources.
    subject : str
        Whole selected policy identity used by the original Clock diagnostic.
    pointer : str
        Actual Clock requirement/source position, without private source text in errors.

    Returns
    -------
    TimesyncdMessage
        Complete original bytes/reference and all fifteen reported fields. This supplies
        no installed-version correspondence, approved server, synchronization, physical
        uncertainty, provenance class, current request or accepted Clock verdict.

    Raises
    ------
    InputRefused
        Shared bounds/metadata or source identity fails, or the complete wire signature,
        field population, ASCII/boolean/integer representation or range is unsupported.
        Actual acquisition errors keep their original code rather than becoming Clock absence.
    """
    budget.charge(reference, data, subject=subject, pointer=pointer)
    failure = identity_reason(reference, data, budget=budget, subject=subject, pointer=pointer)
    if failure is not None:
        raise InputRefused(failure)
    try:
        tokens = data.decode("ascii").removesuffix("\n").split(" ")
    except UnicodeError as error:
        raise clock_unavailable(subject, pointer) from error
    if (
        len(tokens) != 20
        or tokens[0] != "(uuuuittayttttbtt)"
        or tokens[8] != "4"
        or tokens[17] not in ("true", "false")
    ):
        raise clock_unavailable(subject, pointer)
    values: dict[int, int] = {}
    for index in (*range(1, 8), *range(9, 17), 18, 19):
        width = 8 if 9 <= index <= 12 else 32 if index <= 5 else 64
        values[index] = _integer(
            tokens[index], bits=width, signed=index == 5, subject=subject, pointer=pointer
        )
    return TimesyncdMessage(
        reference,
        data,
        values[1],
        values[2],
        values[3],
        values[4],
        values[5],
        values[6],
        values[7],
        bytes(values[index] for index in range(9, 13)),
        values[13],
        values[14],
        values[15],
        values[16],
        tokens[17] == "true",
        values[18],
        values[19],
    )
