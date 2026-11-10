# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact conditional Clock source and entry calculations

"""Recompute declared source/use terms without promoting them to physical admission."""

from collections.abc import Mapping
from dataclasses import dataclass
from math import ceil
from typing import cast

from ._budget import ReferenceBudget
from ._clock_acceptance_derivation import (
    ClockAcceptanceCalculation,
    calculate_acceptance_derivation,
)
from ._clock_bounds import NtpEstimate
from ._clock_method_types import ClockBoundDatum, ClockMethodInputs
from ._clock_method_values import CLOCK_POINTER
from ._clock_raw_sample import read_raw_clock_sample
from ._clock_sample_estimate import calculate_sample_estimate
from ._clock_subject import BoundClockSubject
from ._clock_values import clock_integer, clock_unavailable, elapsed_nanoseconds
from ._clock_windows import (
    ClockHandoff,
    ClockUse,
    UseErrorTerms,
    extend_interval,
    require_five_second_budget,
    require_half_open_window,
)
from ._immutable import FrozenJson
from ._json import JsonValue
from ._values import BlobRef


@dataclass(frozen=True, slots=True)
class ClockMethodCalculation:
    """Keep complete conditional calculations separate from source/model qualification.

    Attributes
    ----------
    methods : ClockMethodInputs
        Whole selected records, numerical declarations and actual source bytes.
    before, after : NtpEstimate
        Complete actual packet calculations with all eight declared source terms.
    use : ClockUse
        Full capture, H, actual E and complete union, without a moved origin.
    acceptance : ClockAcceptanceCalculation
        Both entire original annual source estimates and complete capture interval.
        Conditional derivations supply no physical model or six-predicate admission.
    """

    methods: ClockMethodInputs
    before: NtpEstimate
    after: NtpEstimate
    use: ClockUse
    acceptance: ClockAcceptanceCalculation


def _use_terms(values: Mapping[str, ClockBoundDatum], reference: BlobRef) -> UseErrorTerms:
    """Retain all four additions and their entire original derivation identity.

    Parameters
    ----------
    values : Mapping
        Complete explicit acquisition, mapping, quantization and adjustment population.
    reference : BlobRef
        Whole derivation, also retaining each term's individual full source.

    Returns
    -------
    UseErrorTerms
        All four conditional terms, without a missing-value or zero fallback.
    """
    return UseErrorTerms(
        values["acquisition"].nanoseconds,
        values["mapping"].nanoseconds,
        values["quantization"].nanoseconds,
        values["adjustment"].nanoseconds,
        reference,
    )


def calculate_clock_methods(
    methods: ClockMethodInputs,
    *,
    clock: BoundClockSubject,
    policy_reference: BlobRef,
    signature_rule: Mapping[str, FrozenJson],
    budget: ReferenceBudget,
) -> ClockMethodCalculation:
    """Calculate whole capture/use/entry bounds and every actual selected time window.

    Parameters
    ----------
    methods : ClockMethodInputs
        Entire matching records, declarations and actual source/graph observations.
    clock : BoundClockSubject
        Original frozen invocation with actual native E.
    policy_reference : BlobRef
        Whole selected policy for the original Clock diagnostic.
    signature_rule : Mapping
        Complete selected signature rule and exact validity interval.
    budget : ReferenceBudget
        SAME original quota for every source/packet parse.

    Returns
    -------
    ClockMethodCalculation
        Complete eight-term N and S0..S1..H..E interval. Numerical consistency supplies
        no independent physical support, source version/rotation/renewal, accepted
        Clock, native authority or class/report verdict.

    Raises
    ------
    InputRefused
        Original source/packet/mapping fails or any full error/window is understated,
        unsupported, outside the fixed-origin budget or outside exact half-open validity.
    ConfigurationError
        A selected raw capture has invalid fixed shape or field types.
    """
    subject = policy_reference.digest
    annual_calculation = calculate_acceptance_derivation(
        methods.acceptance, clock=clock, policy_reference=policy_reference, budget=budget
    )
    mapping = dict(methods.uncertainty.evidence)["/daemon_field_mapping_rule_ref"].reference
    evidence = dict(methods.use.evidence)
    before = calculate_sample_estimate(
        clock.before,
        methods.before_bounds,
        ntp=evidence["/before_ntp_ref"],
        raw=evidence["/before_raw_ref"],
        ticks_per_second=clock.ticks_per_second,
        mapping_rule_ref=mapping,
        subject=subject,
        budget=budget,
    )
    after = calculate_sample_estimate(
        clock.after,
        methods.after_bounds,
        ntp=evidence["/after_ntp_ref"],
        raw=evidence["/after_raw_ref"],
        ticks_per_second=clock.ticks_per_second,
        mapping_rule_ref=mapping,
        subject=subject,
        budget=budget,
    )
    use_utc, use_bracket = read_raw_clock_sample(
        evidence["/use_raw_ref"],
        expected_ticks=clock.use_ticks,
        ticks_per_second=clock.ticks_per_second,
        subject=subject,
        budget=budget,
    )
    entry_bracket = ceil(
        elapsed_nanoseconds(
            clock.native_entry.observation.entry_ticks,
            clock.native_entry.observation.acquired_through_ticks,
            ticks_per_second=clock.ticks_per_second,
            subject=subject,
            pointer=CLOCK_POINTER,
        )
    )
    if (
        methods.use_terms["acquisition"].nanoseconds < use_bracket
        or methods.entry_terms["acquisition"].nanoseconds < entry_bracket
    ):
        raise clock_unavailable(subject, CLOCK_POINTER)
    witness = cast(dict[str, JsonValue], clock.sources.documents["witness"].value)
    declared = clock_integer(
        cast(str, witness["use_error_bound_ns"]),
        signed=False,
        subject=subject,
        pointer=CLOCK_POINTER,
    )
    handoff = ClockHandoff(
        clock.use_ticks,
        clock.native_entry.observation.entry_ticks,
        clock.ticks_per_second,
        methods.maximum_error_rate,
        declared,
        _use_terms(methods.use_terms, methods.use.source.reference),
        _use_terms(methods.entry_terms, methods.use.source.reference),
    )
    use = extend_interval(
        clock.capture, clock.after, handoff, subject=subject, pointer=CLOCK_POINTER
    )
    upper = clock_integer(
        cast(str, witness["use_utc_upper_ns"]), signed=True, subject=subject, pointer=CLOCK_POINTER
    )
    if upper < use.at_use.upper_ns or not use.at_use.lower_ns <= use_utc <= use.at_use.upper_ns:
        raise clock_unavailable(subject, CLOCK_POINTER)
    require_five_second_budget(
        use.whole,
        evaluation_origin_ns=clock.evaluation_origin_ns,
        subject=subject,
        pointer=CLOCK_POINTER,
    )
    acceptance = cast(dict[str, JsonValue], clock.sources.documents["acceptance"].value)
    windows = (
        acceptance,
        methods.uncertainty.declaration,
        methods.drift.declaration,
        methods.use.declaration,
        signature_rule,
    )
    for window in windows:
        require_half_open_window(
            use.whole,
            valid_from=cast(str, window["valid_from"]),
            valid_until=cast(str, window["valid_until"]),
            origin=clock.native_entry.origin,
            subject=subject,
            pointer=CLOCK_POINTER,
        )
    return ClockMethodCalculation(methods, before, after, use, annual_calculation)
