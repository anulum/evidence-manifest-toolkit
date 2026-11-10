# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original public six-bound validation sources

"""Exercise original68 complete Limits cases through its real public value method."""

import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from typing import cast

import pytest

from evidence_manifest_toolkit import ConfigurationError, Limits

_FIXTURE = Path(__file__).parent / "fixtures/limits-validate-source-vectors.json"
_DATA = json.loads(_FIXTURE.read_bytes())
_CASES = cast(list[dict[str, object]], _DATA["cases"])
_BY_ID = {cast(str, case["case_id"]): case for case in _CASES}


def _declared_limits(case: dict[str, object]) -> Limits:
    """Construct the real declaration from each original native test-data value.

    Parameters
    ----------
    case : dict
        Entire source case. The explicit tuple_items encoding means a native tuple;
        type casts deliberately inject invalid controlled arguments without coercion.

    Returns
    -------
    Limits
        Actual root-exported unvalidated constructor value, not a fake validation class.
    """
    fields = dict(cast(dict[str, object], case["fields"]))
    if case["input_kind"] == "Limits_fields_tuple_placeholder":
        for name, value in fields.items():
            if isinstance(value, dict) and set(value) == {"tuple_items"}:
                fields[name] = tuple(cast(list[object], value["tuple_items"]))
    return Limits(**{name: cast(int, value) for name, value in fields.items()})


def _exercise(case: dict[str, object]) -> None:
    """Compare the complete frozen source oracle and unchanged declaration at the public method.

    Parameters
    ----------
    case : dict
        Original success, malformed field, untyped unbound self or first-failure-order case.
        All five expected reason fields were frozen independently before calls.
    """
    unbound = case["input_kind"] == "untyped_unbound_self"
    value = case["input"] if unbound else _declared_limits(case)
    before = deepcopy(value) if unbound else asdict(cast(Limits, value))
    if case.get("expected") == "None":
        validate: Callable[[], object] = cast(Limits, value).validate
        assert validate() is None
    else:
        with pytest.raises(ConfigurationError) as caught:
            if unbound:
                Limits.validate(cast(Limits, value))
            else:
                cast(Limits, value).validate()
        assert type(caught.value).__name__ == case["expected_exception"]
        assert asdict(caught.value.reason) == case["expected_reason"]
    after = value if unbound else asdict(cast(Limits, value))
    assert after == before


@pytest.mark.parametrize("case", _CASES, ids=[cast(str, row["case_id"]) for row in _CASES])
def test_limits_public_complete_fields_reason_order_and_recovery(case: dict[str, object]) -> None:
    """Validate original complete bounds and recover after each actual refused public call.

    Parameters
    ----------
    case : dict
        One of the original68 source-bound cases, with unchanged large integer/tuple values.
    """
    _exercise(case)
    recovery = case.get("recovery_id")
    if recovery is not None:
        _exercise(_BY_ID[cast(str, recovery)])
