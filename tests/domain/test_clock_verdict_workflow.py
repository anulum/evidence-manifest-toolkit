# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the calculated Clock checks over a whole real workflow

"""Read synchronization and the uncertainty budget from a real Clock calculation.

Each case runs the whole unsigned workflow over a real timesyncd capture, with the acceptance
declaring one calculated check ``pass``. The verdict the verification computed is read back by
wrapping the real function, which still runs unchanged. The fixture's drift record states
1/1000000 and a 1000 ns holdover, below RFC 5905's 15/1000000 floor and short of the capture's
age, so its declared budget is contradicted, while its synchronization reproduces.
"""

from pathlib import Path
from typing import Any

import pytest
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow

import evidence_manifest_toolkit._verification_inputs as verification_inputs
from evidence_manifest_toolkit._clock_verdict import ClockVerdict, clock_verdict


def _recorded(monkeypatch: pytest.MonkeyPatch) -> list[ClockVerdict]:
    """Record each verdict the verification computes, leaving the real function to compute it."""
    verdicts: list[ClockVerdict] = []

    def recording(**inputs: Any) -> ClockVerdict:
        """Compute the verdict with the real function and keep it."""
        verdict = clock_verdict(**inputs)
        verdicts.append(verdict)
        return verdict

    monkeypatch.setattr(verification_inputs, "clock_verdict", recording)
    return verdicts


def test_a_declared_synchronization_reproduces_from_the_real_calculation(
    tmp_path: Path, capfd: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real exchange and samples hold, so synchronization passes; the report is unchanged."""
    verdicts = _recorded(monkeypatch)
    assert_whole_clock_source_workflow(
        "sig_exception",
        tmp_path,
        capfd,
        declared_checks={"synchronization_and_mapping": "pass"},
    )
    assert [verdict.checks["synchronization_and_mapping"] for verdict in verdicts] == ["pass"]
    assert [verdict.checks["proven_uncertainty_budget"] for verdict in verdicts] == ["unavailable"]
    assert not verdicts[0].accepted


def test_a_declared_budget_under_the_drift_floor_is_contradicted(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """At 1/1000000 and a 1000 ns holdover the budget cannot hold, so its pass is refused."""
    assert_whole_clock_source_workflow(
        "sig_exception",
        tmp_path,
        capfd,
        declared_checks={"proven_uncertainty_budget": "pass"},
        contradicted_check="proven_uncertainty_budget",
    )
