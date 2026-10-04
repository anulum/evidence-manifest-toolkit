# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Exercise actual adapter cleanup deadlines and producer-open interruption."""

import subprocess
from pathlib import Path

import pytest

from local_scaffold.dependencies import native_tool
from tests.conftest import SOURCE, snapshots, source_python
from tests.test_atomic_publication import actual_strace as actual_strace


@pytest.mark.parametrize(
    "stage,fault",
    [
        ("setup-reaping", "kill:delay_enter=6s:when=1"),
        ("view-cleanup", "unlinkat:delay_enter=6s:when=1"),
    ],
)
def test_actual_inclusive_adapter_cleanup(
    root: Path, tmp_path: Path, actual_strace: Path, stage: str, fault: str
) -> None:
    """Native successful children cannot erase an expired inclusive adapter budget."""
    before = snapshots(root)
    trace = tmp_path / (stage + ".native-trace")
    program = """import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.actionlint_view import analyse
from local_scaffold.reports import Fault
try:
    analyse(Path(sys.argv[2]),5.0)
except Fault as fault:
    print(fault.code)
    sys.exit(fault.exit_code)
raise AssertionError('Actual delayed cleanup exceeded the inclusive deadline')
"""
    argv = [
        str(actual_strace),
        "-f",
        "--kill-on-exit",
        "--seccomp-bpf",
        "-s",
        "4096",
        "-o",
        str(trace),
        "-e",
        "trace=kill,unlinkat,execve,exit_group",
        "-e",
        "inject=" + fault,
        *source_python("-B", "-c", program, str(SOURCE / "tools"), str(root)),
    ]
    result = subprocess.run(argv, cwd=SOURCE, capture_output=True, timeout=30)
    assert result.returncode == 3 and result.stdout == b"tool_timeout\n", (
        result.stdout,
        result.stderr,
    )
    assert not result.stderr
    raw = trace.read_bytes()
    assert b"DELAYED" in raw and b"exit_group(0)" in raw
    if stage == "view-cleanup":
        lines = raw.decode().splitlines()
        producer = str(native_tool("actionlint"))
        executions = [line for line in lines if "execve(" in line and producer in line]
        assert len(executions) == 1
        pid = executions[0].split()[0]
        assert any(line.split() == [pid, "+++", "exited", "with", "0", "+++"] for line in lines)
    assert not list((root / ".tool-cache").glob("actionlint-view-*"))
    assert snapshots(root) == before


def test_actual_fixed_main_interrupt_at_producer_open() -> None:
    """A real kernel open notification triggers SIGTERM during fixed input reading."""
    program = """import ctypes,os,select,signal,sys,threading
sys.path.insert(0,sys.argv[1])
from local_scaffold.actionlint_view import main
from local_scaffold.policy import NATIVE_TOOLS
from pathlib import Path
record=next(item for item in NATIVE_TOOLS if item['role']=='actionlint')
producer=Path(sys.argv[2])/record['binary_relative_path']
libc=ctypes.CDLL(None,use_errno=True)
descriptor=libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
assert descriptor>=0
assert libc.inotify_add_watch(descriptor,os.fsencode(producer),0x20)>=0
ready=threading.Event()
delivered=[]
def interrupt_on_open():
    '''Send one actual termination signal after the producer's kernel open event.'''
    ready.set()
    if select.select([descriptor],[],[],5)[0]:
        event=os.read(descriptor,4096)
        assert event
        delivered.append(True)
        os.kill(os.getpid(),signal.SIGTERM)
thread=threading.Thread(target=interrupt_on_open)
thread.start()
assert ready.wait(2)
try:
    result=main()
finally:
    thread.join(6)
    os.close(descriptor)
assert delivered and not thread.is_alive()
sys.exit(result)
"""
    result = subprocess.run(
        source_python("-c", program, str(SOURCE / "tools"), str(SOURCE)),
        cwd=SOURCE,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 3 and not result.stdout and result.stderr == b"interrupted\n"
