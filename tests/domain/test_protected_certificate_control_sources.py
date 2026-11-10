# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected control certificate source forests

"""Exercise whole control certificate source forests through original public verification."""

from pathlib import Path

import pytest
from tests.domain.protected_control_target_inputs import (
    CERTIFICATE_CONTROL_SOURCE_CASES,
    protected_control_target_input,
)
from tests.domain.test_protected_certificate_sources import (
    test_complete_native_parent_source_bounds_through_public_entry as assert_public_sources,
)


@pytest.mark.parametrize(
    "case",
    (*CERTIFICATE_CONTROL_SOURCE_CASES, *("cli_" + c for c in CERTIFICATE_CONTROL_SOURCE_CASES)),
)
def test_complete_control_certificate_sources_through_public_verification(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Check complete target and ancestor bounds without accepting certificates.

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
