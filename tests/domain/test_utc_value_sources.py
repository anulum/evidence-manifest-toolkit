# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact original public UTC value sources

"""Exercise genuine public UTC values against complete independently fixed source oracles."""

import base64
import json
from dataclasses import asdict
from pathlib import Path
from typing import Literal, NotRequired, TypedDict

import pytest

from evidence_manifest_toolkit import InputRefused, Utc


class _Constructor(TypedDict):
    """Retain every original scalar input, refusal and unchanged valid recovery."""

    constructor_input_kind: str
    entire_constructor_input: object
    expected_entire_wire_string: NotRequired[str]
    expected_exception_class: NotRequired[str]
    expected_entire_Reason: NotRequired[dict[str, object]]
    entire_valid_constructor_recovery: NotRequired[str]


class _Pair(TypedDict):
    """Retain complete original comparison tokens and their exact instant-order oracle."""

    left: str
    right: str
    expected_exact_order: Literal["less", "equal", "greater"]


class _Sources(TypedDict):
    """Retain the whole before-call constructor and comparison source populations."""

    entire_constructor_cases: list[_Constructor]
    entire_original86_comparison_pairs: list[_Pair]


_SOURCES: _Sources = json.loads(
    (Path(__file__).parent / "fixtures/utc-value-source-vectors.json").read_bytes()
)


@pytest.mark.parametrize("case", _SOURCES["entire_constructor_cases"])
def test_entire_original_constructor_and_recovery(case: _Constructor) -> None:
    """Compare the complete real public value or all five original refusal fields.

    Parameters
    ----------
    case : dict
        Entire original unchanged scalar declaration and its independently authored oracle.
    """
    raw = case["entire_constructor_input"]
    if case["constructor_input_kind"] == "bytes":
        assert isinstance(raw, dict) and isinstance(raw["base64url"], str)
        token = raw["base64url"]
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    if "expected_exception_class" in case:
        with pytest.raises(InputRefused) as failure:
            Utc(raw)
        assert type(failure.value).__name__ == case["expected_exception_class"]
        assert asdict(failure.value.reason) == case["expected_entire_Reason"]
        recovery = case["entire_valid_constructor_recovery"]
        repaired = Utc(recovery)
        assert type(repaired) is Utc and isinstance(repaired, str)
        assert repaired == recovery
        assert not hasattr(repaired, "__dict__")
    else:
        value = Utc(raw)
        assert type(value) is Utc and isinstance(value, str)
        assert value == case["expected_entire_wire_string"]
        assert str(value) == raw
        assert not hasattr(value, "__dict__")


@pytest.mark.parametrize("pair", _SOURCES["entire_original86_comparison_pairs"])
def test_entire_original_exact_instant_order(pair: _Pair) -> None:
    """Compare complete original tokens without replacing wire equality or precision.

    Parameters
    ----------
    pair : dict
        Whole before-call original tokens and independently selected chronological order.
    """
    left, right = Utc(pair["left"]), Utc(pair["right"])
    expected = {"less": -1, "equal": 0, "greater": 1}[pair["expected_exact_order"]]
    assert left.compare(right) == expected
    assert left.compare(pair["right"]) == expected
    assert right.compare(left) == -expected
    assert str(left) == pair["left"] and str(right) == pair["right"]
