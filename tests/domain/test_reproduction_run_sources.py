# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — native run source correspondence through public verification

"""Exercise whole native run records through the actual public API and module CLI."""

from pathlib import Path

import pytest
from tests.domain.native_run_inputs import NATIVE_RUN_CASES
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow


@pytest.mark.parametrize("condition", NATIVE_RUN_CASES)
def test_whole_native_run_source_graph_before_class_admission(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Retain whole source/schema/graph refusals without inventing independent run acceptance.

    Parameters
    ----------
    condition : str
        One complete matching unqualified graph or independently authored contradiction.
    tmp_path : Path
        Actual owned flat reference store frozen before the original Clock subject.
    capfd : pytest.CaptureFixture
        Real module CLI output, without provider, clock or resolver substitution.

    Notes
    -----
    Matching declared records still reach the unimplemented V2 admission boundary.
    These tests prove source correspondence/refusal, never physical Clock or run truth.
    """
    assert_whole_clock_source_workflow(condition, tmp_path, capfd)
