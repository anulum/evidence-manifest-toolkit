# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — full native reproduction method policy relations through public entry

"""Refuse whole comparison-law substitution and contradictory execution non-use policy."""

from pathlib import Path

import pytest
from tests.domain.reproduction_method_policy_inputs import METHOD_POLICY_PUBLIC_CASES
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow


@pytest.mark.parametrize("condition", METHOD_POLICY_PUBLIC_CASES)
def test_original_reproduction_method_policy_relations(
    condition: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Exercise complete API/CLI unsigned and protected input graphs before native admission.

    Parameters
    ----------
    condition : str
        One independent exact full-reference or method-class policy contradiction.
    tmp_path : Path
        Owned complete input/source population constructed before Clock/context freeze.
    capfd : pytest.CaptureFixture
        Actual module CLI output, never a substituted verifier or native clock.
    """
    assert_whole_clock_source_workflow(condition, tmp_path, capfd)
