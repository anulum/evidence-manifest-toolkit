# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected certificate issuer API and CLI contracts

"""Exercise complete parent issuer relations through original public verification."""

from pathlib import Path

import pytest
from tests.domain.test_protected_certificate_sources import (
    test_complete_native_parent_source_bounds_through_public_entry as assert_public_certificate_sources,
)


@pytest.mark.parametrize(
    "case",
    (
        "issuer_parent",
        "issuer_ancestor",
        "issuer_distinct_subject",
        "cli_issuer_parent",
        "cli_issuer_ancestor",
        "cli_issuer_distinct_subject",
    ),
)
def test_complete_selected_certificate_issuers_through_public_verification(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Check full parent issuer sources with no ordinary receipts or accepted state.

    Parameters
    ----------
    case : str
        Whole leaf or ancestor issuer conflict, or a distinct matching subject key.
    tmp_path : Path
        Owned complete original source/registry/caller inputs and genuine bounded store.
    capfd : pytest.CaptureFixture
        Original module CLI output descriptors; no substituted verifier/provider.
    """
    assert_public_certificate_sources(case, tmp_path, capfd)
