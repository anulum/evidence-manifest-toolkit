# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete fixed raw clock sample interpretation

"""Check original realtime/raw brackets without granting physical uncertainty support."""

from fractions import Fraction
from math import ceil
from typing import cast

from ._budget import ReferenceBudget
from ._clock_method_types import ClockMethodSource
from ._clock_method_values import CLOCK_POINTER, method_configuration_refusal, method_object
from ._clock_values import clock_integer, clock_unavailable, elapsed_nanoseconds
from ._errors import InputRefused
from ._json import acquire_document
from ._values import Reason


def read_raw_clock_sample(
    source: ClockMethodSource,
    *,
    expected_ticks: int,
    ticks_per_second: Fraction,
    subject: str,
    budget: ReferenceBudget,
) -> tuple[int, int]:
    """Check the whole fixed raw realtime capture and its actual monotonic bracket.

    Parameters
    ----------
    source : ClockMethodSource
        Whole original source; its uncertainty token remains a declaration.
    expected_ticks : int
        Exact original annual or invocation sample endpoint, without a later substitution.
    ticks_per_second : Fraction
        Exact positive calibration for this original sample domain, without a new default.
    subject : str
        Original policy for unsupported source mapping.
    budget : ReferenceBudget
        SAME bounds for strict source parsing.

    Returns
    -------
    tuple of int
        Exact UTC coordinate and outward-rounded acquisition bracket nanoseconds.

    Raises
    ------
    ConfigurationError
        Closed raw shape or field types are invalid.
    InputRefused
        Original parsing, capture, order or numeric mapping fails.
    """
    try:
        document = acquire_document(source.raw_bytes, limits=budget.limits)
    except InputRefused as error:
        why = error.reason
        raise InputRefused(
            Reason(why.code, source.reference.digest, why.claim_id, why.pointer, why.detail)
        ) from error
    value = method_object(
        document.value,
        frozenset({"clock", "utc_ns", "raw_before", "raw_after", "physical_uncertainty"}),
        subject=source.reference.digest,
        pointer="",
    )
    if value["clock"] != "CLOCK_REALTIME":
        raise clock_unavailable(subject, CLOCK_POINTER)
    if not isinstance(value["physical_uncertainty"], str) or not value["physical_uncertainty"]:
        raise method_configuration_refusal(source.reference.digest, "/physical_uncertainty")
    for field in ("utc_ns", "raw_before", "raw_after"):
        if not isinstance(value[field], str):
            raise method_configuration_refusal(source.reference.digest, "/" + field)
    utc = clock_integer(
        cast(str, value["utc_ns"]), signed=True, subject=subject, pointer=CLOCK_POINTER
    )
    start = clock_integer(
        cast(str, value["raw_before"]), signed=False, subject=subject, pointer=CLOCK_POINTER
    )
    end = clock_integer(
        cast(str, value["raw_after"]), signed=False, subject=subject, pointer=CLOCK_POINTER
    )
    if end != expected_ticks:
        raise clock_unavailable(subject, CLOCK_POINTER)
    bracket = elapsed_nanoseconds(
        start, end, ticks_per_second=ticks_per_second, subject=subject, pointer=CLOCK_POINTER
    )
    return utc, ceil(bracket)
