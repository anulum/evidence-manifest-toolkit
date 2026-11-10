# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — bounded complete native process captures

"""Exercise exact native pipe ceilings without truncating successful output."""

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from local_scaffold.policy import MAX_CAPTURE, MAX_TREE
from local_scaffold.processes import ProcessObservation, run_process
from local_scaffold.reports import Fault


@pytest.mark.parametrize("pipe", ("stdout", "stderr"))
def test_native_pipe_exact_limit_and_overflow(tmp_path: Path, pipe: str) -> None:
    """Capture the inclusive bound and refuse its next byte from an actual child.

    Parameters
    ----------
    tmp_path : Path
        Owned Samsung native child directory.
    pipe : str
        Independently selected real standard output or standard error.
    """
    program = f"import sys;sys.{pipe}.buffer.write(b'x'*257)"
    exact = run_process([sys.executable, "-I", "-c", program], tmp_path, max_capture_bytes=257)
    assert exact.exit_code == 0
    assert (exact.stdout if pipe == "stdout" else exact.stderr) == b"x" * 257
    observation = ProcessObservation()
    with pytest.raises(Fault) as error:
        run_process(
            [sys.executable, "-I", "-c", program],
            tmp_path,
            max_capture_bytes=256,
            observation=observation,
        )
    assert error.value.code == "tool_output_limit"
    assert len(observation.stdout) <= 256 and len(observation.stderr) <= 256
    assert observation.native_exit is not None


def test_explicit_source_budget_preserves_complete_larger_native_output(tmp_path: Path) -> None:
    """Preserve all native bytes under an explicit source budget, retaining the default refusal.

    Parameters
    ----------
    tmp_path : Path
        Owned Samsung native child directory.
    """
    length = MAX_CAPTURE + 1
    command = [sys.executable, "-I", "-c", f"import sys;sys.stdout.buffer.write(b'x'*{length})"]
    with pytest.raises(Fault) as error:
        run_process(command, tmp_path)
    assert error.value.code == "tool_output_limit"
    actual = run_process(command, tmp_path, max_capture_bytes=length)
    assert actual.exit_code == 0 and actual.stderr == b"" and actual.stdout == b"x" * length


@pytest.mark.parametrize("budget", (False, 0, -1, MAX_TREE // 2 + 1))
def test_invalid_capture_budget_refuses_before_child_exec(tmp_path: Path, budget: int) -> None:
    """Reject malformed resource declarations before an actual marker-producing command runs.

    Parameters
    ----------
    tmp_path : Path
        Owned Samsung native child directory.
    budget : object
        Deliberately wrong independently supplied resource declaration.
    """
    marker = tmp_path / "executed"
    command = [
        sys.executable,
        "-I",
        "-c",
        "from pathlib import Path;Path('executed').write_text('unexpected')",
    ]
    with pytest.raises(Fault) as error:
        run_process(command, tmp_path, max_capture_bytes=budget)
    assert error.value.code == "configuration_invalid" and not marker.exists()


@pytest.mark.parametrize("status", (0, 7))
def test_owned_child_completion_preserves_actual_time_and_exit(tmp_path: Path, status: int) -> None:
    """Observe real completion before consuming the complete process result.

    Parameters
    ----------
    tmp_path : Path
        Owned child execution directory.
    status : int
        Native child exit selected independently of the process result.
    """
    before = datetime.now(UTC)
    observation = ProcessObservation()
    result = run_process(
        [sys.executable, "-I", "-B", "-c", f"raise SystemExit({status})"],
        tmp_path,
        observation=observation,
    )
    after = datetime.now(UTC)
    assert result.exit_code == observation.native_exit == status
    assert observation.native_completed_at is not None
    assert before <= observation.native_completed_at <= after
    with pytest.raises(Fault) as failure:
        run_process(
            [sys.executable, "-I", "-c", "raise SystemExit(99)"], tmp_path, observation=observation
        )
    assert failure.value.code == "configuration_invalid"
