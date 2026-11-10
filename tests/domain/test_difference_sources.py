# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete manifest member differences

"""Compare member removal and addition through the public diagnostic operation."""

import base64
import hashlib
import json
from pathlib import Path

from evidence_manifest_toolkit import BlobRef, Difference, Limits, diff


def test_complete_manifest_member_rename_and_reverse() -> None:
    """Retain whole manifest identities and escaped member paths in both directions.

    Notes
    -----
    The retained manifest is an architecture-only declaration. Its member rename
    exercises diagnostic comparison, without asserting native schema acceptance.
    Canonical inputs contain only the original string/container declarations;
    their independent byte hashes supply the complete before-call identity oracle.
    """
    fixture = Path(__file__).parent / "fixtures/diagnostic-source-vectors.json"
    cases: list[dict[str, object]] = json.loads(fixture.read_bytes())
    selected = next(
        case for case in cases if case["case_id"] == "diff-complete-manifest-claim-identity"
    )
    inputs = selected["inputs"]
    assert isinstance(inputs, dict)
    encoded = inputs["left_json"]
    assert isinstance(encoded, str)
    left = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    document: dict[str, object] = json.loads(left)
    assert json.dumps(document, sort_keys=True, separators=(",", ":")).encode() == left
    source = document.pop("source_ref")
    document["source/ref~backup"] = source
    right = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    left_ref = BlobRef(
        "sha256:" + hashlib.sha256(left).hexdigest(),
        str(len(left)),
        "application/json",
        "jcs_content",
    )
    right_ref = BlobRef(
        "sha256:" + hashlib.sha256(right).hexdigest(),
        str(len(right)),
        "application/json",
        "jcs_content",
    )
    changed = ("/source_ref", "/source~1ref~0backup")
    limits = Limits(65536, 65536, 4194304, 128, 64, 64)
    assert diff(left, right, limits=limits) == Difference(
        left_ref, right_ref, False, changed, (), (), True, "not_evaluated"
    )
    assert diff(right, left, limits=limits) == Difference(
        right_ref, left_ref, False, changed, (), (), True, "not_evaluated"
    )
