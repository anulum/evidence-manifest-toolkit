# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete control target API and CLI correspondence

"""Exercise whole native target relations through original public verification."""

from pathlib import Path

import pytest
from tests.domain.protected_control_target_inputs import (
    CONTROL_TARGET_CASES,
    protected_control_target_input,
)
from tests.domain.test_protected_certificate_sources import (
    test_complete_native_parent_source_bounds_through_public_entry as assert_public_sources,
)


@pytest.mark.parametrize(
    "case", (*CONTROL_TARGET_CASES, *("cli_" + c for c in CONTROL_TARGET_CASES))
)
def test_complete_control_target_bounds_through_public_verification(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Check actual whole root, signer and parent joins without accepting controls.

    Parameters
    ----------
    case : str
        Complete source-compatible target or independently authored target contradiction.
    tmp_path : Path
        Owned whole input store prepared before the actual caller/context freeze.
    capfd : pytest.CaptureFixture
        Real API/moduleCLI descriptors, without replaced product resolver or provider.
    """
    chosen = protected_control_target_input(case.removeprefix("cli_"), tmp_path)
    assert_public_sources(case, tmp_path, capfd, chosen=chosen)
