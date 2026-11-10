# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected certificate key API and CLI contracts

"""Exercise whole grant and certificate key sources through original public verification."""

from pathlib import Path

import pytest
from tests.domain.test_protected_certificate_sources import (
    test_complete_native_parent_source_bounds_through_public_entry as assert_public_certificate_sources,
)


@pytest.mark.parametrize(
    "case",
    (
        "key_grant_short",
        "key_grant_long",
        "key_grant_id",
        "key_leaf_short",
        "key_leaf_long",
        "key_leaf_id",
        "key_parent_short",
        "key_parent_long",
        "key_parent_id",
        "cli_key_grant_id",
        "cli_key_leaf_short",
        "cli_key_parent_id",
    ),
)
def test_complete_selected_certificate_key_sources_through_public_verification(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Refuse actual full key contradictions with no ordinary receipts or accepted state.

    Parameters
    ----------
    case : str
        Whole independently authored grant, leaf or rooted parent key counterfactual.
    tmp_path : Path
        Owned complete original source/registry/caller inputs and genuine bounded store.
    capfd : pytest.CaptureFixture
        Original module CLI output descriptors; no substituted verifier/provider.
    """
    assert_public_certificate_sources(case, tmp_path, capfd)
