# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — public selected method implementation and environment checks

"""Exercise entire source/environment correspondence through the real public verification path."""

from pathlib import Path

import pytest
from tests.domain.native_method_inputs import NATIVE_METHOD_CASES
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow


@pytest.mark.parametrize("condition", NATIVE_METHOD_CASES)
def test_selected_native_method_sources_through_public_verification(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Refuse exact full method/environment contradictions without native class admission.

    Parameters
    ----------
    condition : str
        One independently authored whole-source fault, including actual CLI counterparts.
    tmp_path : Path
        Owned complete public input store, without a substituted resolver or observation.
    capfd : pytest.CaptureFixture
        Actual public module CLI output when selected by the whole input condition.
    """
    assert_whole_clock_source_workflow(condition, tmp_path, capfd)
