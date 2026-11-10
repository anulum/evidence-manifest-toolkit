# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — immutable staged native access through public verification

"""Exercise whole earlier capture preservation through actual public API and module CLI."""

from pathlib import Path

import pytest
from tests.domain.native_access_prefix_inputs import NATIVE_ACCESS_PREFIX_CASES
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow


@pytest.mark.parametrize("condition", NATIVE_ACCESS_PREFIX_CASES)
def test_whole_native_access_prefixes(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Retain exact stage sources, original events and located capture contradictions.

    Parameters
    ----------
    condition : str
        Whole matching unqualified prefix or independently authored source conflict.
    tmp_path : Path
        Owned actual source population frozen before the public verification entry.
    capfd : pytest.CaptureFixture
        Original real CLI output without a substituted verifier, provider or Clock.
    """
    assert_whole_clock_source_workflow(condition, tmp_path, capfd)
