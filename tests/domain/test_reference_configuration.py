# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — strict public reference metadata and exact recovery

"""Refuse malformed public metadata without losing exact valid Unicode declarations."""

from dataclasses import asdict

import pytest

from evidence_manifest_toolkit import BlobRef, ConfigurationError, Limits, reference_bytes

_LIMITS = Limits(1024, 1024, 4096, 16, 8, 8)
_EXPECTED = BlobRef(
    "sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
    "1",
    "application/μ-data",
    "raw_bytes",
    "δ.😀",
)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [("media_type", ""), ("media_type", "\ud800"), ("schema_id", ""), ("schema_id", "\udfff")],
    ids=["empty-media", "surrogate-media", "empty-schema", "surrogate-schema"],
)
def test_public_metadata_refusal_and_exact_unicode_recovery(field: str, invalid: str) -> None:
    """Check a fixed configuration refusal and entire independent raw identity recovery.

    Parameters
    ----------
    field : str
        Actual public nonempty-string metadata argument being rejected.
    invalid : str
        Complete empty or non-UTF8 Unicode declaration; no private codec is invoked.
    """
    with pytest.raises(ConfigurationError) as caught:
        reference_bytes(
            b"x",
            media_type=invalid if field == "media_type" else "application/μ-data",
            schema_id=invalid if field == "schema_id" else "δ.😀",
            digest_basis="raw_bytes",
            limits=_LIMITS,
        )
    assert asdict(caught.value.reason) == {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": None,
        "detail": "Invalid reference configuration.",
    }
    assert (
        reference_bytes(
            b"x",
            media_type="application/μ-data",
            schema_id="δ.😀",
            digest_basis="raw_bytes",
            limits=_LIMITS,
        )
        == _EXPECTED
    )
