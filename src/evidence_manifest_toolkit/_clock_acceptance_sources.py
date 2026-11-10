# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original annual Clock method sources

"""Bind original annual associations without substituting later invocation evidence."""

from dataclasses import replace
from fractions import Fraction
from typing import cast

from ._clock_method_read import ClockMethodReader
from ._clock_method_types import ClockAcceptanceInputs, ClockMethodRecord, ClockMethodSource
from ._clock_method_values import CLOCK_POINTER, SAMPLE_TERMS, method_integer, method_object
from ._clock_subject import BoundClockSubject
from ._clock_values import clock_integer, clock_unavailable
from ._codecs import decode_reference
from ._json import JsonValue

_RULE_FIELDS = (
    "holdover_rule_ref",
    "daemon_field_mapping_rule_ref",
    "accepted_ntp_configuration_ref",
    "acquisition_rule_ref",
    "ntp_resolution_and_rotation_rule_ref",
    "sample_mapping_and_quantization_rule_ref",
)
_ANNUAL_FIELDS = frozenset(
    {
        "monotonic_domain_ref",
        "ticks_per_second",
        "before",
        "after",
        "raw_synchronization_refs",
        "measured_offset_source_ref",
        "sample_bounds",
        *_RULE_FIELDS,
    }
)


def acquire_acceptance_inputs(
    clock: BoundClockSubject,
    *,
    uncertainty: ClockMethodRecord,
    reader: ClockMethodReader,
) -> ClockAcceptanceInputs:
    """Read the whole selected annual dependency with both original sample associations.

    Parameters
    ----------
    clock : BoundClockSubject
        Entire matched original profile/annual acceptance and later invocation sources.
        Original annual coordinates and rate remain separate from later native entry.
    uncertainty : ClockMethodRecord
        Whole independently selected fixed uncertainty method carrying annual_derivation_ref.
        This reference selects data under the installed method, never executable code.
    reader : ClockMethodReader
        Original resolver, structural dispatch and SAME cumulative operation budget.

    Returns
    -------
    ClockAcceptanceInputs
        Complete original annual child, raw sources, packet associations and all six
        bounds per sample. Matching sources supplies no physical support or class verdict.

    Raises
    ------
    ConfigurationError
        The raw container metadata, closed method or complete association/term shape fails.
    ReferenceUnavailable
        An actual selected original method or required source descendant is absent.
    InputRefused
        Original source/identity/schema/quota fails or an annual association/context conflicts.
    """
    annual = cast(dict[str, JsonValue], clock.sources.documents["acceptance"].value)
    profile = cast(dict[str, JsonValue], clock.sources.documents["profile"].value)
    model = cast(dict[str, JsonValue], uncertainty.document.value)
    subject = reader.policy_subject
    reference = decode_reference(
        model["annual_derivation_ref"],
        subject=uncertainty.source.reference.digest,
        pointer="/annual_derivation_ref",
    )
    expected = {
        name: profile[name]
        for name in (
            "custody_class",
            "host_identity_ref",
            "controller_identity_ref",
            "implementation_environment_ref",
        )
    }
    expected.update({name: model[name] for name in _RULE_FIELDS})
    expected.update(
        assumptions_and_limitations_ref=model["assumptions_and_limitations_ref"],
        monotonic_domain_ref=annual["monotonic_domain_ref"],
        raw_synchronization_refs=annual["raw_synchronization_refs"],
    )
    record = reader.record(
        reference,
        parent_subject=uncertainty.source.reference.digest,
        pointer="/annual_derivation_ref",
        method="emt_clock_acceptance_bounds_v1",
        units="integer_nanoseconds",
        fields=_ANNUAL_FIELDS,
        expected=expected,
    )
    value = cast(dict[str, JsonValue], record.document.value)
    rate = method_object(
        value["ticks_per_second"],
        frozenset({"numerator", "denominator"}),
        subject=reference.digest,
        pointer="/ticks_per_second",
    )
    components = tuple(
        method_integer(
            rate[name],
            subject=reference.digest,
            policy_subject=subject,
            pointer="/ticks_per_second/" + name,
        )
        for name in ("numerator", "denominator")
    )
    if min(components) == 0:
        raise clock_unavailable(subject, CLOCK_POINTER)
    original_rate = cast(dict[str, JsonValue], annual["ticks_per_second"])
    original_components = tuple(
        clock_integer(
            cast(str, original_rate[name]), signed=False, subject=subject, pointer=CLOCK_POINTER
        )
        for name in ("numerator", "denominator")
    )
    if Fraction(components[0], components[1]) != Fraction(
        original_components[0], original_components[1]
    ):
        raise clock_unavailable(subject, CLOCK_POINTER)
    edges: list[tuple[str, ClockMethodSource]] = list(record.evidence)
    for field in ("monotonic_domain_ref", *_RULE_FIELDS):
        pointer = "/" + field
        edges.append(
            (pointer, reader.field_source(value[field], subject=reference.digest, pointer=pointer))
        )
    synchronization = cast(list[JsonValue], annual["raw_synchronization_refs"])
    for index, raw in enumerate(synchronization):
        pointer = "/raw_synchronization_refs/" + str(index)
        edges.append((pointer, reader.field_source(raw, subject=reference.digest, pointer=pointer)))
    samples: list[ClockMethodSource] = []
    packets: list[ClockMethodSource] = []
    for name in ("before", "after"):
        pointer = "/" + name
        association = method_object(
            value[name],
            frozenset({"clock_sample_raw_ref", "ntp_ref"}),
            subject=reference.digest,
            pointer=pointer,
        )
        original = cast(dict[str, JsonValue], annual[name])
        if (
            association["clock_sample_raw_ref"] != original["clock_sample_raw_ref"]
            or association["ntp_ref"] not in synchronization
        ):
            raise clock_unavailable(subject, CLOCK_POINTER)
        for field, population in (("clock_sample_raw_ref", samples), ("ntp_ref", packets)):
            location = pointer + "/" + field
            source = reader.field_source(
                association[field], subject=reference.digest, pointer=location
            )
            edges.append((location, source))
            population.append(source)
    offset = reader.field_source(
        value["measured_offset_source_ref"],
        subject=reference.digest,
        pointer="/measured_offset_source_ref",
    )
    if offset.reference not in (packets[0].reference, packets[1].reference):
        raise clock_unavailable(subject, CLOCK_POINTER)
    edges.append(("/measured_offset_source_ref", offset))
    bounds = method_object(
        value["sample_bounds"],
        frozenset({"before", "after"}),
        subject=reference.digest,
        pointer="/sample_bounds",
    )
    before = reader.bounds(
        bounds["before"], SAMPLE_TERMS, subject=reference.digest, pointer="/sample_bounds/before"
    )
    after = reader.bounds(
        bounds["after"], SAMPLE_TERMS, subject=reference.digest, pointer="/sample_bounds/after"
    )
    for name, terms in (("before", before), ("after", after)):
        edges.extend(
            ("/sample_bounds/" + name + "/" + field + "/source_ref", term.source)
            for field, term in terms.items()
        )
    return ClockAcceptanceInputs(
        replace(record, evidence=tuple(edges)),
        (samples[0], samples[1]),
        (packets[0], packets[1]),
        before,
        after,
        offset,
    )
