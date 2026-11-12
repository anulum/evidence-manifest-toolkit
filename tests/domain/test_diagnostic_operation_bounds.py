# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — inspection and difference refuse each bound that applies to them

"""Exhaust document size, document depth and identified size through inspection and difference."""

import hashlib
from dataclasses import asdict, replace

import pytest

from evidence_manifest_toolkit import (
    BlobRef,
    Difference,
    InputRefused,
    Inspection,
    Limits,
    diff,
    inspect,
)

_LIMITS = Limits(1048576, 1048576, 16777216, 1024, 32, 64)
_FLAT = b'{"a":"0123456789","b":"0123456789"}'
_OTHER = b'{"a":"0123456789","b":"9876543210"}'
_NESTED = b'{"a":[[0]]}'
_RECEIPT = b'{"signature":"0123456789","statement":{"purpose":"evidence"}}'
_DOCUMENT_REFUSED = {
    "code": "limit_exceeded",
    "subject_digest": None,
    "claim_id": None,
    "pointer": None,
    "detail": "JSON input refused.",
}
_IDENTITY_REFUSED = {
    "code": "limit_exceeded",
    "subject_digest": None,
    "claim_id": None,
    "pointer": None,
    "detail": "Blob byte bound exceeded.",
}


def _reference(canonical: bytes) -> BlobRef:
    """Return the canonical identity of bytes that are already canonical JSON.

    Parameters
    ----------
    canonical : bytes
        A document written without white space and with sorted member names, so that its
        canonical form is the document itself.

    Returns
    -------
    BlobRef
        The identity computed with the standard library alone, with no schema declared.
    """
    return BlobRef(
        "sha256:" + hashlib.sha256(canonical).hexdigest(),
        str(len(canonical)),
        "application/json",
        "jcs_content",
        None,
    )


def _inspected(document: bytes) -> Inspection:
    """Return what inspection reports for a canonical document that declares no schema.

    Parameters
    ----------
    document : bytes
        A canonical document without a ``schema_id`` member.

    Returns
    -------
    Inspection
        Its identity, no claims, no references, no reasons, acceptance not evaluated.
    """
    return Inspection(None, _reference(document), (), (), "not_evaluated", ())


_SPACED = b'{ "a" : "0123456789" }'
_SPACED_CANONICAL = b'{"a":"0123456789"}'
_BOUNDS = {
    "the document is one byte longer than the size bound": (
        _FLAT,
        _FLAT,
        {"max_json_bytes": len(_FLAT) - 1},
        _DOCUMENT_REFUSED,
        {"max_json_bytes": len(_FLAT)},
    ),
    "the document is one level deeper than the depth bound": (
        _NESTED,
        _NESTED,
        {"max_json_depth": 2},
        _DOCUMENT_REFUSED,
        {"max_json_depth": 3},
    ),
    "the document is one byte longer than the identified-size bound": (
        _FLAT,
        _FLAT,
        {"max_blob_bytes": len(_FLAT) - 1},
        _IDENTITY_REFUSED,
        {"max_blob_bytes": len(_FLAT)},
    ),
    "the original bytes are over the identified-size bound although the canonical form fits": (
        _SPACED,
        _SPACED_CANONICAL,
        {"max_blob_bytes": len(_SPACED) - 1},
        _IDENTITY_REFUSED,
        {"max_blob_bytes": len(_SPACED)},
    ),
    "the canonical form is over the identified-size bound although the original bytes fit": (
        b"1e3",
        b"1000",
        {"max_blob_bytes": 3},
        _IDENTITY_REFUSED,
        {"max_blob_bytes": 4},
    ),
}


@pytest.mark.parametrize("bound", sorted(_BOUNDS))
def test_inspection_refuses_at_each_bound_and_completes_exactly_on_it(bound: str) -> None:
    """One byte or one level over the bound refuses; exactly on the bound the whole result returns.

    Parameters
    ----------
    bound : str
        Which bound that applies to inspection is exhausted, and by which bytes.
    """
    document, canonical, exhausted, reason, exact = _BOUNDS[bound]
    assert len(_SPACED_CANONICAL) < len(_SPACED) - 1
    with pytest.raises(InputRefused) as caught:
        inspect(document, limits=replace(_LIMITS, **exhausted))
    assert asdict(caught.value.reason) == reason
    assert inspect(document, limits=replace(_LIMITS, **exact)) == _inspected(canonical)


@pytest.mark.parametrize("side", ("left", "right"))
@pytest.mark.parametrize("bound", sorted(_BOUNDS))
def test_difference_refuses_at_each_bound_on_either_side(bound: str, side: str) -> None:
    """Either document over a bound refuses the comparison; on the bound it completes.

    Parameters
    ----------
    bound : str
        Which bound that applies to difference is exhausted, and by which bytes.
    side : str
        Whether the left or the right document is the one at the bound.
    """
    document, canonical, exhausted, reason, exact = _BOUNDS[bound]
    small = b"0"
    left, right = (document, small) if side == "left" else (small, document)
    with pytest.raises(InputRefused) as caught:
        diff(left, right, limits=replace(_LIMITS, **exhausted))
    assert asdict(caught.value.reason) == reason
    identities = (canonical, small) if side == "left" else (small, canonical)
    assert diff(left, right, limits=replace(_LIMITS, **exact)) == Difference(
        _reference(identities[0]),
        _reference(identities[1]),
        False,
        ("",),
        (),
        (),
        True,
        "not_evaluated",
    )


@pytest.mark.parametrize("side", ("left", "right"))
@pytest.mark.parametrize(
    ("exhausted", "reason", "exact"),
    [
        (
            {"max_json_bytes": len(_RECEIPT) - 1},
            _DOCUMENT_REFUSED,
            {"max_json_bytes": len(_RECEIPT)},
        ),
        ({"max_json_depth": 1}, _DOCUMENT_REFUSED, {"max_json_depth": 2}),
        (
            {"max_blob_bytes": len(_RECEIPT) - 1},
            _IDENTITY_REFUSED,
            {"max_blob_bytes": len(_RECEIPT)},
        ),
    ],
    ids=["size", "depth", "identified-size"],
)
def test_difference_applies_the_same_bounds_to_every_receipt(
    exhausted: dict[str, int], reason: dict[str, object], exact: dict[str, int], side: str
) -> None:
    """A receipt over a bound refuses the comparison of two documents that are within it.

    Parameters
    ----------
    exhausted, exact : dict
        The bound set one below what the receipt needs, and exactly at it.
    reason : dict
        The whole expected refusal.
    side : str
        Whether the receipt accompanies the left or the right document.
    """
    receipts = (
        {"left_envelopes": (_RECEIPT,)} if side == "left" else {"right_envelopes": (_RECEIPT,)}
    )
    small = b"0"
    with pytest.raises(InputRefused) as caught:
        diff(small, small, limits=replace(_LIMITS, **exhausted), **receipts)
    assert asdict(caught.value.reason) == reason
    completed = diff(small, small, limits=replace(_LIMITS, **exact), **receipts)
    expected_receipts = (_reference(_RECEIPT),)
    assert completed == Difference(
        _reference(small),
        _reference(small),
        True,
        (),
        expected_receipts if side == "left" else (),
        expected_receipts if side == "right" else (),
        False,
        "not_evaluated",
    )


def test_two_documents_within_every_bound_differ_where_they_differ() -> None:
    """The bounds refuse nothing here: one member differs and its pointer is reported."""
    exact = Limits(len(_FLAT), len(_FLAT), 16777216, 1024, 32, 1)
    assert diff(_FLAT, _OTHER, limits=exact) == Difference(
        _reference(_FLAT), _reference(_OTHER), False, ("/b",), (), (), True, "not_evaluated"
    )
