# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual fixed read-only Linux verifier-entry observation

"""Capture actual E and whole native sources without granting Clock or authority acceptance."""

import ctypes
import os
import re
import sys
import sysconfig
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import rfc8785

ENVIRONMENT_FIELDS = (
    "python_implementation",
    "python_version",
    "python_cache_tag",
    "python_executable",
    "python_soabi",
    "libc_reported_version",
    "uname",
    "byte_order",
    "long_bits",
    "pointer_bits",
)


class _Timeval(ctypes.Structure):
    """Describe the observed Linux64 timeval ABI, without foreign-pointer arguments."""

    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _Timespec(ctypes.Structure):
    """Retain the exact integer nanosecond units of native clock_getres."""

    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


class _Timex(ctypes.Structure):
    """Describe the entire Linux64 read-only timex ABI, including reserved bytes."""

    _fields_ = [
        ("modes", ctypes.c_uint),
        ("offset", ctypes.c_long),
        ("freq", ctypes.c_long),
        ("maxerror", ctypes.c_long),
        ("esterror", ctypes.c_long),
        ("status", ctypes.c_int),
        ("constant", ctypes.c_long),
        ("precision", ctypes.c_long),
        ("tolerance", ctypes.c_long),
        ("time", _Timeval),
        ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long),
        ("jitter", ctypes.c_long),
        ("shift", ctypes.c_int),
        ("stabil", ctypes.c_long),
        ("jitcnt", ctypes.c_long),
        ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long),
        ("stbcnt", ctypes.c_long),
        ("tai", ctypes.c_int),
        ("reserved", ctypes.c_int * 11),
    ]


@dataclass(frozen=True, slots=True)
class NativeEntryUnavailable:
    """Retain an actual unsupported or failed native observation without a zero sample.

    Attributes
    ----------
    cause : str
        Fixed safe category; received paths or exception text are not published.
    system_errno : int or None
        Actual syscall/read errno when available, never invented successful state.
    """

    cause: Literal["unsupported_abi", "native_read_failed", "identity_read_failed"]
    system_errno: int | None


@dataclass(frozen=True, slots=True)
class NativeEntryObservation:
    """Retain actual entry and all whole host observations separately from the earlier witness.

    Attributes
    ----------
    entry_ticks, acquired_through_ticks : int
        First actual CLOCK_MONOTONIC_RAW E and end of the bounded acquisition bracket.
        No later traversal time replaces the first observation.
    resolution_ns : int
        Exact integer clock_getres result, not a float-derived accuracy guarantee.
    raw_timex : bytes
        Entire zero-initialized 208-byte ABI result, including all reported fields/padding.
        The query always uses modes0 and never adjusts any clock parameter.
    kernel_result, kernel_status : int
        Actual reported clock state. Successful acquisition is not Clock eligibility.
    maximum_error_us, tolerance_scaled_ppm, frequency_scaled_ppm : int
        Entire actual fields; the correction estimate is not substituted for a drift bound.
    utc_seconds, utc_subseconds : int
        Actual kernel time fields, whose subsecond units remain explicit in nano_mode.
    nano_mode : bool
        Actual STA_NANO state; maxerror remains microseconds under either mode.
    boot_bytes, process_bytes : bytes
        Whole actual boot-id and current /proc/self/stat sources, never a projected Ref.
    process_id, process_start_ticks : int
        Actual stable process-start relation extracted from the retained whole source.
    environment_json : bytes
        Whole canonical reported runtime/ABI environment; it proves no stronger identity.
    """

    entry_ticks: int
    acquired_through_ticks: int
    resolution_ns: int
    raw_timex: bytes
    kernel_result: int
    kernel_status: int
    maximum_error_us: int
    tolerance_scaled_ppm: int
    frequency_scaled_ppm: int
    utc_seconds: int
    utc_subseconds: int
    nano_mode: bool
    boot_bytes: bytes
    process_bytes: bytes
    process_id: int
    process_start_ticks: int
    environment_json: bytes


type NativeEntryCapture = NativeEntryObservation | NativeEntryUnavailable


def process_start_identity(raw: bytes) -> tuple[int, int]:
    """Read PID/start ticks from an entire retained native Linux stat source.

    Parameters
    ----------
    raw : bytes
        Full actual /proc/pid/stat, preserving comm bytes including spaces/parentheses.

    Returns
    -------
    tuple of int
        Stable PID and field22 starttime. No Ref is computed from this projection.

    Raises
    ------
    ValueError
        The native source is incomplete or its stable fields are not positive integers.
    """
    prefix, opening, rest = raw.partition(b" (")
    _comm, closing, suffix = rest.rpartition(b") ")
    fields = suffix.split()
    if not opening or not closing or len(fields) < 20:
        raise ValueError("Incomplete native process source.")
    if (
        re.fullmatch(rb"[1-9][0-9]{0,19}", prefix) is None
        or re.fullmatch(rb"0|[1-9][0-9]{0,19}", fields[19]) is None
    ):
        raise ValueError("Invalid native process integer encoding.")
    process_id, started = int(prefix), int(fields[19])
    if max(process_id, started) >= 1 << 64:
        raise ValueError("Invalid native process identity.")
    return process_id, started


def _read_source(path: str, maximum: int) -> bytes:
    """Read one fixed native source within its method's explicit small observation bound.

    Parameters
    ----------
    path : str
        Installed literal source; received configuration never supplies this path.
    maximum : int
        Complete bounded native source allowance, independently of later reference quotas.

    Returns
    -------
    bytes
        Whole actual source, without trimming or normalization.

    Raises
    ------
    OSError
        The source is unavailable or exceeds this fixed native capture bound.
    """
    with Path(path).open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise OSError("Native source exceeds its capture bound.")
    return raw


def capture_verifier_entry() -> NativeEntryCapture:
    """Observe actual E through the fixed installed Linux method before Ref traversal.

    Returns
    -------
    NativeEntryObservation or NativeEntryUnavailable
        Real immutable E/source data or actual unsupported/failure category. No accepted
        Clock, independent controller, physical bound or protected authority is asserted.

    Notes
    -----
    Only this built-in read-only method runs. No input chooses a library, symbol, mode,
    executable, path or callback. The complete independent binding is checked afterward.
    """
    if (
        sys.platform != "linux"
        or os.uname().machine != "x86_64"
        or sys.byteorder != "little"
        or ctypes.sizeof(ctypes.c_long) != 8
        or ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(_Timex) != 208
        or (_Timex.maxerror.offset, _Timex.tolerance.offset, _Timex.time.offset) != (24, 64, 72)
    ):
        return NativeEntryUnavailable("unsupported_abi", None)
    phase: Literal["identity_read_failed", "native_read_failed"] = "identity_read_failed"
    try:
        entered = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        process = _read_source("/proc/self/stat", 16_384)
        boot = _read_source("/proc/sys/kernel/random/boot_id", 4096)
        process_id, started = process_start_identity(process)
        if process_id != os.getpid():
            return NativeEntryUnavailable("identity_read_failed", None)
        phase = "native_read_failed"
        libc_version = os.confstr("CS_GNU_LIBC_VERSION")
        soabi = sysconfig.get_config_var("SOABI")
        if (
            not isinstance(libc_version, str)
            or not libc_version.startswith("glibc ")
            or not isinstance(soabi, str)
            or not soabi
            or not sys.implementation.cache_tag
        ):
            return NativeEntryUnavailable("unsupported_abi", None)
        libc = ctypes.CDLL(None, use_errno=True)
        query = libc.adjtimex
        query.argtypes, query.restype = [ctypes.POINTER(_Timex)], ctypes.c_int
        result = _Timex()
        ctypes.set_errno(0)
        status = query(ctypes.byref(result))
        if status < 0:
            return NativeEntryUnavailable("native_read_failed", ctypes.get_errno())
        resolution = _Timespec()
        clock_resolution = libc.clock_getres
        clock_resolution.argtypes = [ctypes.c_int, ctypes.POINTER(_Timespec)]
        clock_resolution.restype = ctypes.c_int
        if clock_resolution(time.CLOCK_MONOTONIC_RAW, ctypes.byref(resolution)) != 0:
            return NativeEntryUnavailable("native_read_failed", ctypes.get_errno())
        environment = {
            "python_implementation": sys.implementation.name,
            "python_version": sys.version,
            "python_cache_tag": sys.implementation.cache_tag,
            "python_executable": sys.executable,
            "python_soabi": soabi,
            "libc_reported_version": libc_version,
            "uname": list(os.uname()),
            "byte_order": sys.byteorder,
            "long_bits": str(ctypes.sizeof(ctypes.c_long) * 8),
            "pointer_bits": str(ctypes.sizeof(ctypes.c_void_p) * 8),
        }
        environment_json = rfc8785.dumps(environment)
        through = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        return NativeEntryObservation(
            entered,
            through,
            resolution.tv_sec * 1_000_000_000 + resolution.tv_nsec,
            bytes(result),
            status,
            result.status,
            result.maxerror,
            result.tolerance,
            result.freq,
            result.time.tv_sec,
            result.time.tv_usec,
            bool(result.status & 0x2000),
            boot,
            process,
            process_id,
            started,
            environment_json,
        )
    except (OSError, ValueError, AttributeError) as error:
        return NativeEntryUnavailable(phase, error.errno if isinstance(error, OSError) else None)
