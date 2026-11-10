# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual complete software interval source controls

"""Choose whole authorization rows before real S0 without claiming physical support."""

import time
from datetime import UTC, datetime, timedelta

from tests.domain.test_verification_report_sources import _array, _object

SOFTWARE_INTERVAL_CASES = (
    "software_receipt_interval_lower",
    "software_receipt_interval_upper",
    "software_receipt_interval_split",
    "software_receipt_interval_one_full_row",
    "software_receipt_interval_issued_after_capture",
    "software_receipt_interval_issued_after_signature",
    "software_receipt_interval_year_zero_lower",
    "cli_software_receipt_interval_split",
    "software_receipt_historical_interval_split",
)


def software_interval_table(condition: str, table: dict[str, object]) -> dict[str, object]:
    """Select complete rows around an actual earlier observation, before first S0.

    Parameters
    ----------
    condition : str
        Whole public source case, including the actual CLI or archive selection.
    table : dict
        Entire original software source, retaining scope, stream and raw key bytes.

    Returns
    -------
    dict
        Complete independent input table. Narrow rows contain both actual point
        times but cannot each cover the later four-second conditional interval.
        That radius is explicitly unqualified, never a measured physical bound.

    Notes
    -----
    No wall/monotonic clock is mocked or moved and no sleep chooses native E.
    Original sources and broad rows remain immutable caller inputs. An actual
    overloaded capture that violates the original five-second contract still
    fails rather than extending the budget or disguising the source failure.
    """
    if condition not in SOFTWARE_INTERVAL_CASES:
        return table
    now = time.time_ns()

    def utc(value: int) -> str:
        """Encode exact real integer UTC without a floating-point timestamp."""
        seconds, fraction = divmod(value, 1_000_000_000)
        stamp = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
        return stamp.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"

    key = _object(_array(table["authorized_keys"])[0])
    lower = {**key, "group": "lower-complete-row", "valid_from": utc(now - 1_000_000_000)}
    upper = {**key, "group": "upper-complete-row", "valid_until": utc(now + 3_000_000_000)}
    if condition.endswith("_year_zero_lower"):
        rows = [{**key, "valid_from": "0000-01-01T00:00:00Z"}]
    elif condition.endswith("_lower"):
        rows = [lower]
    elif condition.endswith("_upper"):
        rows = [upper]
    elif condition.endswith("_split"):
        rows = [upper, lower]
    elif condition.endswith("_one_full_row"):
        rows = [upper, lower, {**key, "group": "one-whole-covering-row"}]
    else:
        rows = [key]
    result = {**table, "authorized_keys": rows}
    if condition.endswith("_issued_after_capture"):
        result["issued_at"] = utc(now + 2_000_000_000)
    elif condition.endswith("_issued_after_signature"):
        result["issued_at"] = utc(now - 10_000_000_000)
    return result
