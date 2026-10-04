# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Run trusted exec-only commands with bounded capture and owned Linux groups."""

from __future__ import annotations

import asyncio
import ctypes
import math
import os
import signal
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from .policy import LEAF_SECONDS, MAX_CAPTURE
from .reports import Fault


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Actual native process exit and privately retained bounded raw captures.

    Attributes
    ----------
    exit_code : int
        Actual child native exit after owned cleanup.
    stdout : bytes
        Complete bounded original stdout bytes, retained privately.
    stderr : bytes
        Complete bounded original stderr bytes, retained privately.
    """

    exit_code: int
    stdout: bytes
    stderr: bytes


@dataclass(slots=True)
class ProcessObservation:
    """Privately retain bounded actual pipe prefixes and the native child exit.

    A caller owns this optional evidence container. Raw bytes never enter Fault
    or the public guard report. One invocation requires a fresh empty container.

    Attributes
    ----------
    stdout : bytearray
        Actual bounded stdout prefix collected into this fresh caller-owned buffer.
    stderr : bytearray
        Actual bounded stderr prefix collected into this fresh caller-owned buffer.
    native_exit : int | None
        Observed native child exit, or None before child termination is observed.
    """

    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    native_exit: int | None = None


async def capture(stream: asyncio.StreamReader, output: bytearray) -> bytes:
    """Drain one real pipe while enforcing its inclusive capture byte bound.

    Parameters
    ----------
    stream : asyncio.StreamReader
        Owned native stdout/stderr reader drained in 8192-byte blocks.
    output : bytearray
        Caller-owned bytearray retaining the actual bounded prefix as bytes arrive.

    Returns
    -------
    bytes
        Complete pipe bytes when native EOF arrives within MAX_CAPTURE.

    Raises
    ------
    Fault
        Raised as tool_output_limit before appending a block that exceeds the inclusive cap.
    """
    while block := await stream.read(8192):
        if len(output) + len(block) > MAX_CAPTURE:
            raise Fault("tool_output_limit")
        output.extend(block)
    return bytes(output)


async def terminate_group(child: asyncio.subprocess.Process, deadline: float) -> None:
    """Reap the exact exec group, leaving the main PID to its native asyncio waiter.

    Parameters
    ----------
    child : asyncio.subprocess.Process
        Actual native child/session group created by this invocation; unrelated PIDs are not signalled.
    deadline : float
        Absolute monotonic completion deadline shared by SIGTERM/SIGKILL, waiting and owned descendant reaping.

    Raises
    ------
    Fault
        Raised as tool_timeout when the owned group cannot finish within the original deadline.
    """
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            return
        remaining = max(0.0, deadline - time.monotonic())
        grace = min(2.0, remaining / 2 if signum == signal.SIGTERM else remaining)
        stage_deadline = time.monotonic() + grace
        try:
            await asyncio.wait_for(asyncio.shield(child.wait()), timeout=grace)
        except TimeoutError:
            continue
        while time.monotonic() < stage_deadline:
            try:
                pid, _ = os.waitpid(-child.pid, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                await asyncio.sleep(0.01)
    try:
        await asyncio.wait_for(child.wait(), timeout=max(0.0, deadline - time.monotonic()))
    except TimeoutError as error:
        raise Fault("tool_timeout", exit_code=3) from error
    while time.monotonic() < deadline:
        try:
            pid, _ = os.waitpid(-child.pid, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            await asyncio.sleep(0.01)
    raise Fault("tool_timeout", exit_code=3)


async def execute(
    command: list[str],
    root: Path,
    total_deadline: float,
    cleanup: float,
    observation: ProcessObservation,
    environment: Mapping[str, str] | None = None,
) -> ProcessResult:
    """Own an exec-only child, both readers and inclusive deadline-bounded cleanup.

    Parameters
    ----------
    command : list[str]
        Caller-authorised exec argv; no shell or repository-selected callback is used.
    root : Path
        Caller-authorised child working directory.
    total_deadline : float
        Absolute monotonic deadline including capture, wait and group cleanup.
    cleanup : float
        Seconds reserved within total_deadline for owned descendant termination.
    observation : ProcessObservation
        Fresh caller-owned raw pipe prefixes and native child exit container.
    environment : Mapping[str, str] | None
        Explicit trusted child environment, or inherited environment when None; original five-argument calls remain supported.

    Returns
    -------
    ProcessResult
        Actual child exit plus complete bounded pipe bytes after owned resource cleanup.

    Raises
    ------
    Fault
        Raised for native exec unavailability, timeout, capture overflow or cleanup timeout; interruption propagates through cleanup.
    """
    try:
        child = await asyncio.create_subprocess_exec(
            *command,
            cwd=root,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=environment,
        )
    except OSError as error:
        raise Fault("tool_unavailable", exit_code=3) from error
    stdout = asyncio.create_task(
        capture(cast(asyncio.StreamReader, child.stdout), observation.stdout)
    )
    stderr = asyncio.create_task(
        capture(cast(asyncio.StreamReader, child.stderr), observation.stderr)
    )
    wait = asyncio.create_task(child.wait())
    tasks = (stdout, stderr, wait)
    try:
        observed = await asyncio.wait_for(
            asyncio.gather(*tasks),
            timeout=max(0.0, total_deadline - cleanup - time.monotonic()),
        )
        return ProcessResult(observed[2], observed[0], observed[1])
    except TimeoutError as error:
        raise Fault("tool_timeout", exit_code=3) from error
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            await terminate_group(child, total_deadline)
        finally:
            observation.native_exit = child.returncode


def run_process(
    command: list[str],
    root: Path,
    timeout: float = LEAF_SECONDS,
    *,
    observation: ProcessObservation | None = None,
    environment: Mapping[str, str] | None = None,
) -> ProcessResult:
    """Execute caller-authorised arguments with no shell or repository callback.

    The caller supplies trusted executable arguments and optional environment;
    repository input never selects them. Finite authorised programs qualify real process handling
    without claiming tool acceptance. Linux supplies owned descendant reaping.
    The synchronous API owns its event loop and all resources until actual exit.
    Startup defers interruption until the loop belongs to its cleanup context;
    the caller's signal mask is restored before any child is started.

    Parameters
    ----------
    command : list[str]
        Nonempty caller-authorised exec argv, never received repository instructions.
    root : Path
        Native child working directory supplied by the trusted caller.
    timeout : float
        Finite positive inclusive seconds, at most LEAF_SECONDS; includes owned cleanup.
    observation : ProcessObservation | None
        Optional fresh empty evidence container for actual stdout/stderr prefixes and native exit.
    environment : Mapping[str, str] | None
        Explicit trusted environment or inherited caller environment; caller signal masks are restored before exec.

    Returns
    -------
    ProcessResult
        Native exit/captures after reader tasks, child and owned Linux descendants finish.

    Raises
    ------
    Fault
        Raised for invalid budget/evidence reuse, unavailable Linux/subreaper/exec, timeout or capture overflow.
    """
    if (
        not command
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > LEAF_SECONDS
    ):
        raise Fault("configuration_invalid", exit_code=4)
    observed = observation if observation is not None else ProcessObservation()
    if observed.stdout or observed.stderr or observed.native_exit is not None:
        raise Fault("configuration_invalid", exit_code=4)
    total_deadline = time.monotonic() + timeout
    cleanup = min(4.0, timeout / 2)
    if os.name != "posix" or not Path("/proc/self").is_dir():
        raise Fault("tool_unavailable", exit_code=3)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise Fault("tool_unavailable", exit_code=3)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        with asyncio.Runner() as runner:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            return runner.run(
                execute(command, root, total_deadline, cleanup, observed, environment)
            )
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
