# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — protected whole-use intervals through actual public entry

"""Exercise complete selected authorisations through genuine API and CLI invocations."""

from pathlib import Path

import pytest
from tests.domain.protected_use_interval_inputs import PROTECTED_USE_INTERVAL_CASES
from tests.domain.test_clock_subject_sources import (
    test_whole_clock_subject_matches_actual_invocation_and_entry_before_state as verify_clock_source_case,
)


@pytest.mark.parametrize("condition", PROTECTED_USE_INTERVAL_CASES)
def test_whole_protected_authorization_covers_capture_through_native_entry(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Verify actual full-source windows with the shared whole public invocation construction.

    Parameters
    ----------
    condition : str
        Grant, snapshot, leaf, ancestor, exact common-calendar or signing chronology case.
    tmp_path : Path
        Owned actual immutable sources and original genuine capture/provider observations.
    capfd : pytest.CaptureFixture
        Actual module CLI output, without a mocked process, clock, resolver or provider.

    Notes
    -----
    The shared workflow calls Root.verify or the actual CLI. Every negative case's
    observed centre remains inside the selected window; its full interval fails instead.
    Positive source relations retain the original unfinished class refusal and no
    protected root, key custody, physical Clock or accepted state is fabricated.
    """
    verify_clock_source_case(condition, tmp_path, capfd)
