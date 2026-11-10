# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole frozen Clock invocation and first-sample joins

"""Bind entire invocation sources without treating matching declarations as qualified time."""

from dataclasses import dataclass
from fractions import Fraction
from typing import cast

from ._budget import ReferenceBudget
from ._clock_policy import bind_clock_policies
from ._clock_sources import ClockSources
from ._clock_values import ClockSample, clock_integer, clock_unavailable
from ._clock_windows import (
    ClockInterval,
    capture_interval,
    require_civil_year,
    require_five_second_budget,
    require_half_open_window,
)
from ._codecs import decode_reference, reference_value
from ._configuration_wire import decode_limits
from ._entry_binding import BoundNativeEntry
from ._errors import InputRefused, ReferenceUnavailable
from ._immutable import thaw_json
from ._invocation_wire import SuccessorTrust, registry_value, successor_trust_value
from ._json import AcquiredDocument, JsonValue
from ._policy_literals import CLOCK_FIELD
from ._registry_types import SchemaRegistry
from ._values import BlobRef, Limits


@dataclass(frozen=True, slots=True)
class BoundClockSubject:
    """Retain complete joined sources and the exact original witness samples.

    Attributes
    ----------
    sources : ClockSources
        Every whole acquired configuration, source reference, original edge and document.
    before, after : ClockSample
        Full coordinate-matching witness samples; their declared errors/raw sources still
        require the independent selected physical source and uncertainty predicates.
    evaluation_origin_ns : int
        Exact actual first-sample coordinate declaration, matching the frozen caller lexeme.
        Matching bytes do not establish its capture chronology or actual source provenance.
    capture : ClockInterval
        Entire declared capture interval after checking that it contains the complete
        recomputed before/after bounds, fits the original inclusive five-second budget,
        and lies wholly inside the selected exact civil-year half-open acceptance window.
        Declared error terms still need their actual independent physical source proofs.
    ticks_per_second : Fraction
        Whole exact positive reported calibration, retaining both original source integers.
        Calculation consistency alone does not qualify the actual monotonic mapping.
    native_entry : BoundNativeEntry
        Whole actual E and installed native method/source matches, never inserted into
        an earlier witness. Full uncertainty propagation through this E remains required.
    use_ticks : int
        Original witness H, checked between its S1 and the actual E in the fixed domain.
    """

    sources: ClockSources
    before: ClockSample
    after: ClockSample
    evaluation_origin_ns: int
    capture: ClockInterval
    ticks_per_second: Fraction
    native_entry: BoundNativeEntry
    use_ticks: int


def bind_clock_subject(
    sources: ClockSources,
    *,
    trust: SuccessorTrust,
    content_reference: BlobRef,
    envelopes: tuple[bytes, ...],
    registry: SchemaRegistry,
    limits: Limits,
    final_policy: AcquiredDocument,
    policy_reference: BlobRef,
    budget: ReferenceBudget,
    native_entry: BoundNativeEntry,
) -> BoundClockSubject:
    """Match every whole selected invocation value and its exact first-sample bindings.

    Parameters
    ----------
    sources : ClockSources
        Complete bounded fixed/configuration acquisition and closure from the owning method.
        Every ordered receipt already has its full identity checked in the same byte cache;
        charging the supplied receipt enforces exact agreement with those original bytes.
    trust : successor context
        Actual frozen original caller selection, including every class-specific field.
    content_reference : BlobRef
        Entire actual prepared content reference under the independently selected schema.
    envelopes : tuple of bytes
        Original complete ordinary receipt population, in its actual supplied order.
    registry : SchemaRegistry
        Entire independently validated caller registry, including raw bytes and all entries.
    limits : Limits
        Actual six positive operation bounds; no rounded JSON number chooses a bound.
    final_policy : AcquiredDocument
        Whole actual final ordinary policy named by the enclosing selected authority policy.
    policy_reference : BlobRef
        Entire selected enclosing policy for the original evaluation-time diagnostic.
    budget : ReferenceBudget
        SAME operation budget, including all original receipt bytes committed by the subject.
    native_entry : BoundNativeEntry
        Actual E and full fixed-method/source binding. Its explicit native origin and tick
        calibration apply only to this installed method, without a global wire default.

    Returns
    -------
    BoundClockSubject
        Entire matching subject/sources and full samples. Original source failures raise
        their typed diagnostic before binding; matching supplies no physical Clock,
        source, custody or authority acceptance.

    Raises
    ------
    ConfigurationError
        A complete earlier/final policy or entire Limits configuration is malformed.
    InputRefused
        A whole invocation/reference/source/sample join or the shared receipt budget fails.
        Original malformed/metadata/identity failures retain their separate typed reasons.
    ReferenceUnavailable
        An exact selected whole source is missing from the acquired Clock closure.
    """
    if sources.reasons:
        if sources.closure.missing_references:
            raise ReferenceUnavailable(sources.closure.missing_references[0])
        raise InputRefused(sources.reasons[0])
    origin = native_entry.origin
    subject = policy_reference.digest
    pointer = "/" + CLOCK_FIELD + "/clock_qualification_ref"
    documents = sources.documents
    witness = cast(dict[str, JsonValue], documents["witness"].value)
    whole_subject = cast(dict[str, JsonValue], documents["subject"].value)
    first = cast(dict[str, JsonValue], documents["first_sample"].value)
    profile = cast(dict[str, JsonValue], documents["profile"].value)
    acceptance = cast(dict[str, JsonValue], documents["acceptance"].value)
    binding = trust.clock_entry_binding
    selected = sources.fixed
    first_ref = reference_value(selected["first_sample"].source.reference)
    profile_ref = reference_value(selected["profile"].source.reference)
    joins: tuple[tuple[object, object], ...] = (
        (documents["context"].value, successor_trust_value(trust)),
        (documents["registry"].value, registry_value(registry)),
        (whole_subject["content_ref"], reference_value(content_reference)),
        (witness["request_id"], binding["request_id"]),
        (whole_subject["request_id"], binding["request_id"]),
        (first["request_id"], binding["request_id"]),
        (witness["caller_utc_lexeme"], trust.evaluation_time),
        (first["utc_lexeme"], trust.evaluation_time),
        (witness["first_sample_source_ref"], first_ref),
        (whole_subject["first_sample_source_ref"], first_ref),
        (binding["first_sample_source_ref"], first_ref),
        (first["source_profile_ref"], profile_ref),
        (witness["profile_ref"], profile_ref),
        (acceptance["profile_ref"], profile_ref),
        (first["boot_domain_ref"], thaw_json(binding["boot_domain_ref"])),
        (first["process_start_identity_ref"], thaw_json(binding["process_start_identity_ref"])),
        (
            first["verification_controller_identity_ref"],
            thaw_json(binding["verification_controller_identity_ref"]),
        ),
        (whole_subject["verification_controller_identity_ref"], profile["controller_identity_ref"]),
        (
            profile["controller_identity_ref"],
            thaw_json(binding["verification_controller_identity_ref"]),
        ),
        (
            profile["implementation_environment_ref"],
            thaw_json(binding["implementation_environment_ref"]),
        ),
        (witness["controller_identity_ref"], profile["controller_identity_ref"]),
        (acceptance["controller_identity_ref"], profile["controller_identity_ref"]),
        (acceptance["host_identity_ref"], profile["host_identity_ref"]),
        (witness["observer_identity_ref"], profile["observer_identity_ref"]),
        (acceptance["observer_identity_ref"], profile["observer_identity_ref"]),
        (acceptance["issuer_identity_ref"], profile["issuer_identity_ref"]),
        (acceptance["issuer_authorization_ref"], profile["issuer_authorization_ref"]),
    )
    if any(actual != expected for actual, expected in joins) or any(
        value["custody_class"] != trust.profile_class
        for value in (witness, whole_subject, profile, acceptance)
    ):
        raise clock_unavailable(subject, pointer)
    if decode_limits(documents["limits"]) != limits:
        raise clock_unavailable(subject, pointer)
    bind_clock_policies(
        documents["base_policy"],
        final_policy,
        witness_reference=selected["witness"].source.reference,
        subject=subject,
    )
    receipt_refs = cast(list[JsonValue], whole_subject["ordered_receipt_refs"])
    if len(receipt_refs) != len(envelopes):
        raise clock_unavailable(subject, pointer)
    for index, (value, raw) in enumerate(zip(receipt_refs, envelopes, strict=True)):
        location = "/ordered_receipt_refs/" + str(index)
        reference = decode_reference(
            value, subject=selected["subject"].source.reference.digest, pointer=location
        )
        budget.charge(
            reference, raw, subject=selected["subject"].source.reference.digest, pointer=location
        )
    before = ClockSample.from_value(
        cast(dict[str, JsonValue], witness["before"]),
        origin=origin,
        subject=selected["witness"].source.reference.digest,
        pointer="/before",
    )
    after = ClockSample.from_value(
        cast(dict[str, JsonValue], witness["after"]),
        origin=origin,
        subject=selected["witness"].source.reference.digest,
        pointer="/after",
    )
    original_before = cast(dict[str, JsonValue], witness["before"])
    if any(
        actual != expected
        for actual, expected in (
            (original_before["utc_lexeme"], first["utc_lexeme"]),
            (original_before["utc_epoch_ns"], first["utc_epoch_ns"]),
            (original_before["monotonic_ticks"], first["monotonic_ticks"]),
            (original_before["clock_sample_raw_ref"], first["raw_sample_ref"]),
        )
    ):
        raise clock_unavailable(subject, pointer)
    first_coordinate = before.utc_ns
    raw_rate = cast(dict[str, JsonValue], witness["ticks_per_second"])
    rate = Fraction(
        clock_integer(
            cast(str, raw_rate["numerator"]),
            signed=False,
            subject=selected["witness"].source.reference.digest,
            pointer="/ticks_per_second/numerator",
        ),
        clock_integer(
            cast(str, raw_rate["denominator"]),
            signed=False,
            subject=selected["witness"].source.reference.digest,
            pointer="/ticks_per_second/denominator",
        ),
    )
    use_ticks = clock_integer(
        cast(str, witness["use_monotonic_ticks"]),
        signed=False,
        subject=selected["witness"].source.reference.digest,
        pointer="/use_monotonic_ticks",
    )
    if rate != Fraction(1_000_000_000) or not (
        after.monotonic_ticks <= use_ticks <= native_entry.observation.entry_ticks
    ):
        raise clock_unavailable(subject, pointer)
    recomputed = capture_interval(
        before, after, ticks_per_second=rate, subject=subject, pointer=pointer
    )
    declared = ClockInterval(
        clock_integer(
            cast(str, witness["event_utc_lower_ns"]),
            signed=True,
            subject=selected["witness"].source.reference.digest,
            pointer="/event_utc_lower_ns",
        ),
        clock_integer(
            cast(str, witness["event_utc_upper_ns"]),
            signed=True,
            subject=selected["witness"].source.reference.digest,
            pointer="/event_utc_upper_ns",
        ),
    )
    if declared.lower_ns > recomputed.lower_ns or declared.upper_ns < recomputed.upper_ns:
        raise clock_unavailable(subject, pointer)
    require_five_second_budget(
        declared, evaluation_origin_ns=first_coordinate, subject=subject, pointer=pointer
    )
    valid_from = cast(str, acceptance["valid_from"])
    valid_until = cast(str, acceptance["valid_until"])
    require_civil_year(valid_from, valid_until, subject=subject, pointer=pointer)
    require_half_open_window(
        declared,
        valid_from=valid_from,
        valid_until=valid_until,
        origin=origin,
        subject=subject,
        pointer=pointer,
    )
    return BoundClockSubject(
        sources, before, after, first_coordinate, declared, rate, native_entry, use_ticks
    )
