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

The qualified cases declare 15/1000000 and derive each sample's holdover from that run's own
capture, so an unsigned caller's time is qualified by consistency and its common mode is
eligible. Like every whole-workflow Clock case, they read the host's real timesyncd sample: they
need systemd-timesyncd with a sample that is not ignored, and the gate runs them held on one
byte-identical NTPMessage, as it runs the unsigned report cases. Without such a sample the
calculation refuses the Clock, the case's expected report does not arise and the case fails at
that refusal; it is never skipped.
"""

import json
import re
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow
from tests.domain.test_unsigned_command_surface import _verify
from tests.domain.unsigned_command_inputs import UnsignedCommandInputs

import evidence_manifest_toolkit._verification_inputs as verification_inputs
from evidence_manifest_toolkit._clock_verdict import CHECK_IDS, ClockVerdict, clock_verdict
from evidence_manifest_toolkit._verification_report import INFORMATIONAL_REASON_CODES

QUALIFIED = Fraction(15, 1_000_000)
"""RFC 5905's frequency tolerance: the least rate the uncertainty budget accepts."""


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


def test_an_unsigned_caller_with_qualified_time_is_common_eligible(
    tmp_path: Path, capfd: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """All six checks hold, the verdict is accepted, and the report says the time is consistency-only."""
    verdicts = _recorded(monkeypatch)
    assert_whole_clock_source_workflow(
        "sig_exception",
        tmp_path,
        capfd,
        declared_checks=dict.fromkeys(CHECK_IDS, "pass"),
        qualified_rate=QUALIFIED,
        qualified_time=True,
    )
    assert [verdict.accepted for verdict in verdicts] == [True]


def _published_with_qualified_time(case: UnsignedCommandInputs) -> None:
    """Assert the command publishes the eligible report with its consistency-only statement, exit 0."""
    code, out, err, report = _verify(case)
    published = json.loads(out)
    assert (code, err) == (0, b"")
    assert report.read_bytes() == out
    assert {name: published[name] for name in case.axes} == dict(case.axes)
    assert published["common_eligibility"] == "eligible"
    assert published["reasons"] == case.reasons
    assert published["reasons"][0]["code"] == "time_consistency_only"


def test_an_unsigned_caller_with_qualified_time_exits_0_at_the_command_line(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """The real command line publishes the qualified unsigned report and exits 0."""
    assert_whole_clock_source_workflow(
        "cli_sig_exception",
        tmp_path,
        capfd,
        command_check=_published_with_qualified_time,
        declared_checks=dict.fromkeys(CHECK_IDS, "pass"),
        qualified_rate=QUALIFIED,
        qualified_time=True,
    )


def test_the_cli_documentation_lists_exactly_the_reasons_that_do_not_refuse() -> None:
    """The documented table and the report's informational codes are the same three codes."""
    text = (Path(__file__).resolve().parents[2] / "docs" / "offline-cli.md").read_text(
        encoding="utf-8"
    )
    section = text.split("### Reasons that do not refuse", 1)[1].split("\n## ", 1)[0]
    documented = tuple(re.findall(r"^\| `(\w+)` \|", section, flags=re.MULTILINE))
    assert documented == INFORMATIONAL_REASON_CODES
