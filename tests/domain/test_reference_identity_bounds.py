# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original and canonical reference byte bounds

"""Check byte identity bounds and declarations through the complete public reference API."""

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest

from evidence_manifest_toolkit import (
    ConfigurationError,
    DigestBasis,
    InputRefused,
    Limits,
    reference_bytes,
)

_CASES: list[dict[str, object]] = json.loads(
    (Path(__file__).parent / "fixtures/json-reference-source-vectors.json").read_bytes()
)["cases"]
_MANIFEST = next(case for case in _CASES if case["case_id"] == "manifest-reordered")
_ORIGINAL = bytes.fromhex(cast(str, _MANIFEST["raw_hex"]))
_CANONICAL = bytes.fromhex(cast(str, _MANIFEST["expected_canonical_hex"]))
_LIMITS = Limits(**cast(dict[str, int], _MANIFEST["explicit_limits"]))
_SCHEMA_ID = cast(str | None, _MANIFEST["schema_id_declaration"])
_RAW_REFERENCE = cast(dict[str, str | None], _MANIFEST["expected_raw_BlobRef"])
_CANONICAL_REFERENCE = cast(dict[str, str | None], _MANIFEST["expected_canonical_BlobRef"])
_BOUND_REASON = {
    "code": "limit_exceeded",
    "subject_digest": None,
    "claim_id": None,
    "pointer": None,
    "detail": "Blob byte bound exceeded.",
}


def test_canonical_expansion_checks_the_identified_byte_bound() -> None:
    """Bound the canonical output separately while retaining the original raw identity."""
    original = b"1e3"
    canonical = b"1000"
    raw_expected = {
        "digest": "sha256:" + hashlib.sha256(original).hexdigest(),
        "byte_length": "3",
        "media_type": "application/json",
        "digest_basis": "raw_bytes",
        "schema_id": None,
    }
    canonical_expected = {
        "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "byte_length": "4",
        "media_type": "application/json",
        "digest_basis": "jcs_content",
        "schema_id": None,
    }
    limits = replace(_LIMITS, max_blob_bytes=3)
    original_limits = asdict(limits)
    raw_reference = reference_bytes(
        original,
        media_type="application/json",
        digest_basis="raw_bytes",
        schema_id=None,
        limits=limits,
    )
    assert asdict(raw_reference) == raw_expected
    with pytest.raises(InputRefused) as caught:
        reference_bytes(
            original,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id=None,
            limits=limits,
        )
    assert asdict(caught.value.reason) == _BOUND_REASON
    canonical_reference = reference_bytes(
        original,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=None,
        limits=replace(limits, max_blob_bytes=4),
    )
    assert asdict(canonical_reference) == canonical_expected
    assert original == b"1e3" and asdict(limits) == original_limits


def test_original_byte_bound_precedes_canonical_contraction() -> None:
    """Refuse an oversized complete source even when its canonical identity would fit."""
    assert len(_CANONICAL) < len(_ORIGINAL)
    limits = replace(_LIMITS, max_blob_bytes=len(_CANONICAL))
    original_limits = asdict(limits)
    for basis in ("raw_bytes", "jcs_content"):
        with pytest.raises(InputRefused) as caught:
            reference_bytes(
                _ORIGINAL,
                media_type="application/json",
                digest_basis=basis,
                schema_id=_SCHEMA_ID,
                limits=limits,
            )
        assert asdict(caught.value.reason) == _BOUND_REASON
    restored = replace(limits, max_blob_bytes=len(_ORIGINAL))
    for basis, expected in (
        ("raw_bytes", _RAW_REFERENCE),
        ("jcs_content", _CANONICAL_REFERENCE),
    ):
        actual = reference_bytes(
            _ORIGINAL,
            media_type="application/json",
            digest_basis=cast(DigestBasis, basis),
            schema_id=_SCHEMA_ID,
            limits=restored,
        )
        assert asdict(actual) == expected
    assert _ORIGINAL == bytes.fromhex(cast(str, _MANIFEST["raw_hex"]))
    assert asdict(limits) == original_limits


@pytest.mark.parametrize(
    ("media", "basis", "schema"),
    [
        (None, "raw_bytes", _SCHEMA_ID),
        ("", "raw_bytes", _SCHEMA_ID),
        ("application/\ud800", "raw_bytes", _SCHEMA_ID),
        ("application/json", "canonical", _SCHEMA_ID),
        ("application/json", "raw_bytes", 7),
        ("application/json", "raw_bytes", ""),
        ("application/json", "raw_bytes", "schema/\ud800"),
    ],
    ids=[
        "nonstring-media",
        "empty-media",
        "non-UTF8-media",
        "unknown-basis",
        "nonstring-schema",
        "empty-schema",
        "non-UTF8-schema",
    ],
)
def test_invalid_reference_declaration_and_original_recovery(
    media: object, basis: object, schema: object
) -> None:
    """Keep every malformed declaration typed and recover the complete original reference.

    Parameters
    ----------
    media, basis, schema : object
        Deliberately malformed caller selections. Casts retain each actual value
        at the annotated public boundary; they perform no conversion or coercion.
    """
    with pytest.raises(ConfigurationError) as caught:
        reference_bytes(
            _ORIGINAL,
            media_type=cast(str, media),
            digest_basis=cast(DigestBasis, basis),
            schema_id=cast(str | None, schema),
            limits=_LIMITS,
        )
    assert asdict(caught.value.reason) == {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": None,
        "detail": "Invalid reference configuration.",
    }
    recovered = reference_bytes(
        _ORIGINAL,
        media_type="application/json",
        digest_basis="raw_bytes",
        schema_id=_SCHEMA_ID,
        limits=_LIMITS,
    )
    assert asdict(recovered) == _RAW_REFERENCE
    assert _ORIGINAL == bytes.fromhex(cast(str, _MANIFEST["raw_hex"]))
