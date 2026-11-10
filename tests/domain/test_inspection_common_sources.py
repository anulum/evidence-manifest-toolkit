# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete common declaration inspection correspondence

"""Exercise every common reference declaration through the root inspection API."""

import base64
import copy
import hashlib
import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Literal, TypedDict

import pytest

from evidence_manifest_toolkit import InputRefused, Limits, inspect


class _Case(TypedDict):
    """Retain one whole original common inspection input and its fixed six-field oracle."""

    case_id: str
    content_json: str
    limits: dict[str, int]
    expected: dict[str, object]


_CASES: list[_Case] = json.loads(
    (Path(__file__).parent / "fixtures/inspection-common-source-vectors.json").read_text(
        encoding="utf-8"
    )
)


def _consumer_value(value: object) -> object:
    """Serialize public diagnostic containers without using private toolkit helpers.

    Parameters
    ----------
    value : object
        Entire returned public value.

    Returns
    -------
    object
        Full field mapping/arrays preserving documented nulls and values.
    """
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _consumer_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {key: _consumer_value(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_consumer_value(child) for child in value]
    return value


@pytest.mark.parametrize("case", _CASES, ids=[case["case_id"] for case in _CASES])
def test_complete_common_declarations_and_immutable_recovery(case: _Case) -> None:
    """Compare the complete initial/refusal/recovery results with original fixed oracles.

    Parameters
    ----------
    case : dict
        Entire original or declaration-only document and its before-call six-field oracle.
        Synthetic declaration documents supply no native-schema or scientific acceptance.
    """
    encoded = case["content_json"]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    limits = Limits(**case["limits"])
    assert _consumer_value(inspect(raw, limits=limits)) == case["expected"]
    with pytest.raises(InputRefused) as caught:
        inspect(b"\xff", limits=limits)
    assert _consumer_value(caught.value.reason) == {
        "code": "invalid_json",
        "subject_digest": None,
        "claim_id": None,
        "pointer": None,
        "detail": "Input is not valid strict JSON.",
    }
    assert _consumer_value(inspect(raw, limits=limits)) == case["expected"]


def test_malformed_manifest_reference_preserves_other_declarations() -> None:
    """Omit one malformed payload declaration and retain the complete remaining manifest.

    Notes
    -----
    The entire source oracle fixes the payload's position among eleven references.
    Its malformed replacement supplies no native-schema or scientific acceptance.
    Whole before-call byte hashes are independent of the toolkit's reference helpers.
    """
    case = next(row for row in _CASES if row["case_id"] == "manifest-all-declarations")
    encoded = case["content_json"]
    original = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    document: dict[str, object] = json.loads(original)
    expected = copy.deepcopy(case["expected"])
    references = expected["declared_references"]
    assert isinstance(references, list) and len(references) == 11
    payload = document["payload_ref"]
    assert isinstance(payload, dict)
    assert references[9] == {**payload, "schema_id": None}
    del references[9]
    document["payload_ref"] = {}
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    expected["content_ref"] = {
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "byte_length": str(len(raw)),
        "media_type": "application/json",
        "digest_basis": "jcs_content",
        "schema_id": "evidence_manifest_toolkit.manifest.v1",
    }
    limits = Limits(**case["limits"])
    assert _consumer_value(inspect(raw, limits=limits)) == expected
    assert _consumer_value(inspect(original, limits=limits)) == case["expected"]


@pytest.mark.parametrize("shape", ["nonarray", "mixed"], ids=["nonarray-claims", "mixed-claims"])
def test_manifest_claim_container_preserves_literal_selection(
    shape: Literal["nonarray", "mixed"],
) -> None:
    """Keep whole declared claims and references tied to their actual array positions.

    Parameters
    ----------
    shape : {"nonarray", "mixed"}
        A complete source manifest with a dictionary claim container, or its original
        claim surrounded by scalar items. Neither mutation asserts evidence acceptance.
    """
    case = next(row for row in _CASES if row["case_id"] == "manifest-all-declarations")
    encoded = case["content_json"]
    original = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    document: dict[str, object] = json.loads(original)
    expected = copy.deepcopy(case["expected"])
    claims = document["claims"]
    assert isinstance(claims, list) and len(claims) == 1
    if shape == "nonarray":
        document["claims"] = {"retained_declaration": claims[0]}
        expected["declared_claims"] = []
        references = expected["declared_references"]
        assert isinstance(references, list) and len(references) == 11
        expected["declared_references"] = references[7:]
    else:
        document["claims"] = [None, claims[0], "not_a_claim"]
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    expected["content_ref"] = {
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "byte_length": str(len(raw)),
        "media_type": "application/json",
        "digest_basis": "jcs_content",
        "schema_id": "evidence_manifest_toolkit.manifest.v1",
    }
    limits = Limits(**case["limits"])
    assert _consumer_value(inspect(raw, limits=limits)) == expected
    assert _consumer_value(inspect(original, limits=limits)) == case["expected"]
