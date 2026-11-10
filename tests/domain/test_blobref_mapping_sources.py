# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — entire fixed public reference mapping correspondence

"""Exercise the public immutable value methods against complete before-call source oracles."""

import json
from collections.abc import Mapping, MutableMapping
from dataclasses import FrozenInstanceError, asdict
from pathlib import Path
from types import MappingProxyType
from typing import NotRequired, TypedDict, cast

import pytest

from evidence_manifest_toolkit import BlobRef, DigestBasis, InputRefused


class _Case(TypedDict):
    """Retain a whole original declaration and its exact complete success/refusal oracle."""

    case_id: str
    source_kind: str
    input_kind: str
    input: object
    applies_to: list[str]
    expected_fields: NotRequired[dict[str, object]]
    expected_wire: NotRequired[dict[str, str]]
    expected_exception: NotRequired[str]
    expected_reason: NotRequired[dict[str, object]]
    recovery_case_id: NotRequired[str]


class _ConstructorCase(TypedDict):
    """Retain the explicit original constructor-None omission oracle."""

    input_fields: dict[str, object]
    expected_wire: dict[str, str]
    applies_to: str


class _Packet(TypedDict):
    """Retain the entire original mapping corpus and separate constructor distinction."""

    cases: list[_Case]
    constructor_optional_none: _ConstructorCase


_PACKET: _Packet = json.loads(
    (Path(__file__).parent / "fixtures/blobref-mapping-source-vectors.json").read_text(
        encoding="utf-8"
    )
)
_SUCCESS = [case for case in _PACKET["cases"] if case["source_kind"] == "public_mapping_success"]
_REFUSALS = [case for case in _PACKET["cases"] if case["source_kind"] == "public_mapping_refusal"]
_BY_ID = {case["case_id"]: case for case in _PACKET["cases"]}


def _declared(fields: Mapping[str, object]) -> BlobRef:
    """Construct the actual public declaration with unchanged source fixture field values.

    Parameters
    ----------
    fields : Mapping
        Complete supplied constructor fields, including deliberate malformed-type specimens.
        Typed casts describe negative boundary injection; they do not coerce any value.

    Returns
    -------
    BlobRef
        Original immutable declared record, without a validation or acceptance substitute.
    """
    return BlobRef(
        cast(str, fields["digest"]),
        cast(str, fields["byte_length"]),
        cast(str, fields["media_type"]),
        cast(DigestBasis, fields["digest_basis"]),
        cast(str | None, fields.get("schema_id")),
    )


@pytest.mark.parametrize("readonly", [False, True], ids=["dict", "read-only-input"])
@pytest.mark.parametrize("case", _SUCCESS, ids=[case["case_id"] for case in _SUCCESS])
def test_entire_success_and_detached_immutable_roundtrip(case: _Case, readonly: bool) -> None:
    """Check every full field and wire value plus the actual snapshot/read-only obligations.

    Parameters
    ----------
    case : dict
        Entire original successful input and both before-call output oracles.
    readonly : bool
        Select the source's ordinary or read-only Mapping representation.
    """
    original = dict(cast(Mapping[str, object], case["input"]))
    selected = MappingProxyType(original) if readonly else original
    reference = BlobRef.from_mapping(selected)
    assert type(reference) is BlobRef
    assert asdict(reference) == case["expected_fields"]
    exported = reference.to_mapping()
    assert dict(exported) == case["expected_wire"]
    assert exported is not reference.to_mapping()
    assert BlobRef.from_mapping(exported) == reference
    with pytest.raises(TypeError):
        cast(MutableMapping[str, str], exported)["digest"] = "changed"
    for name in case["expected_fields"]:
        with pytest.raises(FrozenInstanceError):
            setattr(reference, name, "changed")
    original["media_type"] = "later caller mutation"
    assert asdict(reference) == case["expected_fields"]
    assert dict(exported) == case["expected_wire"]
    assert dict(_declared(case["expected_fields"]).to_mapping()) == case["expected_wire"]


@pytest.mark.parametrize("case", _REFUSALS, ids=[case["case_id"] for case in _REFUSALS])
def test_whole_refusal_and_original_complete_recovery(case: _Case) -> None:
    """Exercise every selected public boundary and the fixed original repair afterward.

    Parameters
    ----------
    case : dict
        Whole original malformed declaration, exact five-field Reason and repair reference.
        No private codec, mock, optional default or helper result substitutes for the methods.
    """
    value = case["input"]
    if case["input_kind"] == "mapping_nonstring_key":
        descriptor = cast(dict[str, list[list[object]]], value)
        value = {cast(str, pair[0]): pair[1] for pair in descriptor["entries"]}
    with pytest.raises(InputRefused) as caught:
        BlobRef.from_mapping(cast(Mapping[str, object], value))
    assert type(caught.value).__name__ == case["expected_exception"]
    assert asdict(caught.value.reason) == case["expected_reason"]
    if "to_mapping" in case["applies_to"]:
        declaration = _declared(cast(Mapping[str, object], value))
        with pytest.raises(InputRefused) as constructor_failure:
            declaration.to_mapping()
        assert asdict(constructor_failure.value.reason) == case["expected_reason"]
    repair = _BY_ID[case["recovery_case_id"]]
    recovered = BlobRef.from_mapping(cast(Mapping[str, object], repair["input"]))
    assert asdict(recovered) == repair["expected_fields"]
    assert dict(recovered.to_mapping()) == repair["expected_wire"]


def test_constructor_none_omits_only_the_optional_wire_field() -> None:
    """Preserve the explicit source distinction between constructor None and received null."""
    case = _PACKET["constructor_optional_none"]
    declaration = _declared(case["input_fields"])
    assert dict(declaration.to_mapping()) == case["expected_wire"]
    assert BlobRef.from_mapping(declaration.to_mapping()) == declaration
