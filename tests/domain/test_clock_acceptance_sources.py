# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole raw metadata, population, associations and original source identity

"""Exercise whole raw metadata, population, associations and original source identity through genuine API/CLI."""

from pathlib import Path

import pytest
from tests.domain.clock_annual_method_cases import ANNUAL_SOURCE_CASES
from tests.domain.test_clock_subject_sources import (
    test_whole_clock_subject_matches_actual_invocation_and_entry_before_state as verify_clock_source_case,
)


@pytest.mark.parametrize("condition", ANNUAL_SOURCE_CASES)
def test_original_annual_method_sources_through_public_entry(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Verify whole raw metadata, population, associations and original source identity using actual public calls.

    Parameters
    ----------
    condition : str
        Named complete original-source scenario with an independent exact public oracle.
    tmp_path : Path
        Owned immutable inputs retaining genuine before/after captures and daemon bytes.
    capfd : pytest.CaptureFixture
        Actual CLI transport output without a substituted clock, resolver or provider.

    Notes
    -----
    The shared construction invokes Root.verify or the actual CLI. Negative cases
    change declared evidence around genuine observations. Consistent declarations
    retain the ordinary-signature requirement; no physical model or class is admitted.
    """
    verify_clock_source_case(condition, tmp_path, capfd)
