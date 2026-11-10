# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete fixed diagnostic source correspondence

"""Exercise public inspection/difference against whole independently fixed sources."""

import base64
import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Literal, NotRequired, TypedDict

import pytest

from evidence_manifest_toolkit import BlobRef, InputRefused, Limits, diff, inspect


class _Inputs(TypedDict):
    """Retain complete original operation inputs and explicit limits."""

    limits: dict[str, int]
    content_json: NotRequired[str]
    left_json: NotRequired[str]
    right_json: NotRequired[str]
    left_envelopes: NotRequired[list[str]]
    right_envelopes: NotRequired[list[str]]


class _Case(TypedDict):
    """Retain complete diagnostic initial/refusal/recovery source expectations."""

    case_id: str
    operation: Literal["inspect", "diff"]
    inputs: _Inputs
    expected: dict[str, object] | None
    error: dict[str, object] | None
    recovery_inputs: _Inputs
    recovery_expected: dict[str, object]


_CASES: list[_Case] = json.loads(
    (Path(__file__).parent / "fixtures/diagnostic-source-vectors.json").read_text(encoding="utf-8")
)


def _bytes(value: str) -> bytes:
    """Decode an original fixed source fixture without changing its bytes.

    Parameters
    ----------
    value : str
        Entire fixture Base64URL encoding.

    Returns
    -------
    bytes
        Exact original complete input.
    """
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _consumer_mapping(value: object) -> object:
    """Project complete public results into their unchanged source wire shape.

    Parameters
    ----------
    value : object
        Entire returned public diagnostic value.

    Returns
    -------
    object
        Full field mapping/arrays, omitting only an absent BlobRef schema declaration.
    """
    if isinstance(value, BlobRef):
        return {
            field.name: _consumer_mapping(getattr(value, field.name))
            for field in fields(value)
            if field.name != "schema_id" or value.schema_id is not None
        }
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _consumer_mapping(getattr(value, field.name)) for field in fields(value)
        }
    if isinstance(value, Mapping):
        return {key: _consumer_mapping(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_consumer_mapping(child) for child in value]
    return value


@pytest.mark.parametrize("case", _CASES, ids=[case["case_id"] for case in _CASES])
@pytest.mark.parametrize("recovery", [False, True], ids=["initial", "immutable-recovery"])
def test_entire_diagnostic_source_and_recovery(case: _Case, recovery: bool) -> None:
    """Compare each complete public result or thrown reason with its fixed whole source.

    Parameters
    ----------
    case : dict
        Complete before-execution input and independent whole output/refusal oracle.
    recovery : bool
        Whether to exercise the separately supplied corrected immutable input.
    """
    inputs = case["recovery_inputs"] if recovery else case["inputs"]
    expected = case["recovery_expected"] if recovery else case["expected"]
    limits = Limits(**inputs["limits"])
    try:
        if case["operation"] == "inspect":
            result = _consumer_mapping(inspect(_bytes(inputs["content_json"]), limits=limits))
        else:
            result = _consumer_mapping(
                diff(
                    _bytes(inputs["left_json"]),
                    _bytes(inputs["right_json"]),
                    limits=limits,
                    left_envelopes=tuple(_bytes(v) for v in inputs["left_envelopes"]),
                    right_envelopes=tuple(_bytes(v) for v in inputs["right_envelopes"]),
                )
            )
    except InputRefused as error:
        assert not recovery
        assert expected is None
        assert {"class": type(error).__name__, "reason": _consumer_mapping(error.reason)} == case[
            "error"
        ]
    else:
        assert expected is not None
        assert result == expected
