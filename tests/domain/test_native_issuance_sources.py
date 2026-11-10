# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole issuer observation through public verification

"""Exercise actual issuer state, source, head and journal contradictions through public API/CLI."""

from pathlib import Path

import pytest
from tests.domain.native_issuance_inputs import ISSUANCE_CASES
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow


@pytest.mark.parametrize("condition", ISSUANCE_CASES)
def test_whole_native_challenge_issuance_sources(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Preserve whole original issuer evidence and exact native source/error outcomes.

    Parameters
    ----------
    condition : str
        Actual matching unqualified source or independent original contradiction.
    tmp_path : Path
        Owned complete source store before Clock and context freeze.
    capfd : pytest.CaptureFixture
        Real module CLI output; no substituted method or accepted source object.
    """
    assert_whole_clock_source_workflow(condition, tmp_path, capfd)
