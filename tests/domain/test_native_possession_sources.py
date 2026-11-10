# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — full native own-key equation through actual public operations

"""Exercise real signature domains and whole declared receiver graphs through public verification."""

from pathlib import Path

import pytest
from tests.domain.native_possession_inputs import POSSESSION_CASES
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow


@pytest.mark.parametrize("condition", POSSESSION_CASES)
def test_actual_native_possession_equation_and_receiver_sources(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Preserve actual whole-source and raw-key equation outcomes without class admission.

    Parameters
    ----------
    condition : str
        Whole matching unqualified source, real signature-domain or receiver contradiction.
    tmp_path : Path
        Owned complete actual file-source population before first sample/context freeze.
    capfd : pytest.CaptureFixture
        Native module CLI output, without substituted production helpers or providers.
    """
    assert_whole_clock_source_workflow(condition, tmp_path, capfd)
