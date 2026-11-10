# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete selected Clock uncertainty drift and use methods

"""Bind all three whole fixed raw method records without granting physical Clock support."""

from collections.abc import Mapping
from dataclasses import replace
from fractions import Fraction
from typing import cast

from ._budget import ReferenceBudget
from ._clock_acceptance_sources import acquire_acceptance_inputs
from ._clock_method_read import ClockMethodReader
from ._clock_method_types import ClockMethodInputs, ClockMethodRecord, ClockMethodSource
from ._clock_method_values import (
    CLOCK_POINTER,
    SAMPLE_TERMS,
    USE_TERMS,
    method_integer,
    method_object,
)
from ._clock_subject import BoundClockSubject
from ._clock_values import clock_unavailable
from ._codecs import decode_reference, reference_value
from ._format_sources import native_format_lookup
from ._interfaces import Resolver
from ._json import JsonValue
from ._subject_formats import SubjectFormat
from ._values import BlobRef

_DRIFT_FIELDS = frozenset(
    {
        "maximum_error_rate",
        "rate_source_ref",
        "calibration_source_ref",
        "monotonic_mapping_rule_ref",
        "adjustment_rule_ref",
    }
)
_UNCERTAINTY_FIELDS = frozenset(
    {
        "holdover_rule_ref",
        "daemon_field_mapping_rule_ref",
        "accepted_ntp_configuration_ref",
        "acquisition_rule_ref",
        "ntp_resolution_and_rotation_rule_ref",
        "sample_mapping_and_quantization_rule_ref",
        "annual_derivation_ref",
    }
)
_USE_FIELDS = frozenset(
    {
        "subject_ref",
        "profile_ref",
        "first_sample_source_ref",
        "request_id",
        "uncertainty_rule_ref",
        "holdover_rule_ref",
        "before_ntp_ref",
        "after_ntp_ref",
        "before_raw_ref",
        "after_raw_ref",
        "use_raw_ref",
        "use_monotonic_ticks",
        "use_error_bound_ns",
        "sample_bounds",
        "use_terms",
        "entry_terms",
    }
)


def _value(record: ClockMethodRecord) -> dict[str, JsonValue]:
    """Retain the whole parsed object after its complete closed record validation.

    Parameters
    ----------
    record : ClockMethodRecord
        Actual complete bounded source after known method/context validation.

    Returns
    -------
    dict
        Entire original parsed object, without reconstructing a selected projection.
    """
    return cast(dict[str, JsonValue], record.document.value)


def _sources(
    record: ClockMethodRecord, names: tuple[str, ...], *, reader: ClockMethodReader
) -> ClockMethodRecord:
    """Retain every named full source edge in addition to all original common evidence.

    Parameters
    ----------
    record : ClockMethodRecord
        Entire actual fixed method record, without replacing its raw bytes.
    names : tuple of str
        Literal complete source-reference field population selected by the known method.
    reader : ClockMethodReader
        Original resolver, formats and SAME cumulative invocation budget.

    Returns
    -------
    ClockMethodRecord
        Full original record plus each actual field/source edge in the fixed method order.
    """
    value = _value(record)
    edges = tuple(
        (
            "/" + name,
            reader.field_source(
                value[name], subject=record.source.reference.digest, pointer="/" + name
            ),
        )
        for name in names
    )
    return replace(record, evidence=(*record.evidence, *edges))


def acquire_clock_methods(
    clock: BoundClockSubject,
    *,
    conditions_reference: BlobRef,
    policy_reference: BlobRef,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> ClockMethodInputs:
    """Acquire and join complete earlier models and the later actual invocation derivation.

    Parameters
    ----------
    clock : BoundClockSubject
        Entire matching original subject, context, profile, samples and actual native E.
    conditions_reference : BlobRef
        Full independently selected earlier limitations from the enclosing class policy.
    policy_reference : BlobRef
        Entire original policy for the prescribed unsupported Clock diagnostic.
    formats : Mapping
        Original independently validated structural dispatch, without new registry roles.
    resolver : Resolver
        Sole original bounded source, without executable/provider discovery.
    budget : ReferenceBudget
        SAME invocation budget, including every earlier graph/native/receipt acquisition.

    Returns
    -------
    ClockMethodInputs
        Whole source-matched closed records, actual evidence bytes and exact conditional
        parameters. Reading declarations supplies no independently supported N, rho,
        source/version/calibration, authority, Clock or current eligibility verdict.

    Raises
    ------
    ConfigurationError
        Raw method metadata, closed field population, units or source field type is invalid.
    ReferenceUnavailable
        An exact original model/term/provenance root or required descendant is unavailable.
    InputRefused
        Original schema/quota/identity/UTC fails, or selected source/context/rate is unsupported.
    """
    subject = policy_reference.digest
    reader = ClockMethodReader(
        resolver, budget, native_format_lookup(formats, budget=budget), subject
    )
    profile = cast(dict[str, JsonValue], clock.sources.documents["profile"].value)
    witness = cast(dict[str, JsonValue], clock.sources.documents["witness"].value)
    if witness["whole_conditions_and_limitations_ref"] != reference_value(conditions_reference):
        raise clock_unavailable(subject, CLOCK_POINTER)
    common: dict[str, JsonValue] = {
        name: profile[name]
        for name in (
            "custody_class",
            "host_identity_ref",
            "controller_identity_ref",
            "implementation_environment_ref",
        )
    }
    common.update(
        boot_domain_ref=reference_value(clock.native_entry.boot_reference),
        assumptions_and_limitations_ref=reference_value(conditions_reference),
    )
    profile_ref = clock.sources.fixed["profile"].source.reference
    witness_ref = clock.sources.fixed["witness"].source.reference
    drift_ref = decode_reference(
        profile["holdover_drift_bound_rule_ref"],
        subject=profile_ref.digest,
        pointer="/holdover_drift_bound_rule_ref",
    )
    drift = reader.record(
        drift_ref,
        parent_subject=profile_ref.digest,
        pointer="/holdover_drift_bound_rule_ref",
        method="emt_monotonic_raw_drift_v1",
        units="nanoseconds_per_elapsed_nanosecond",
        fields=_DRIFT_FIELDS,
        expected=common | {"monotonic_mapping_rule_ref": profile["monotonic_mapping_rule_ref"]},
    )
    drift = _sources(
        drift,
        (
            "rate_source_ref",
            "calibration_source_ref",
            "monotonic_mapping_rule_ref",
            "adjustment_rule_ref",
        ),
        reader=reader,
    )
    ratio = method_object(
        _value(drift)["maximum_error_rate"],
        frozenset({"numerator", "denominator"}),
        subject=drift_ref.digest,
        pointer="/maximum_error_rate",
    )
    components = tuple(
        method_integer(
            ratio[name],
            subject=drift_ref.digest,
            policy_subject=subject,
            pointer="/maximum_error_rate/" + name,
        )
        for name in ("numerator", "denominator")
    )
    if components[1] == 0:
        raise clock_unavailable(subject, CLOCK_POINTER)
    rate = Fraction(components[0], components[1])
    uncertainty_ref = decode_reference(
        profile["uncertainty_derivation_rule_ref"],
        subject=profile_ref.digest,
        pointer="/uncertainty_derivation_rule_ref",
    )
    selected = common | {
        name: profile[name]
        for name in (
            "daemon_field_mapping_rule_ref",
            "accepted_ntp_configuration_ref",
            "acquisition_rule_ref",
            "ntp_resolution_and_rotation_rule_ref",
        )
    }
    selected["holdover_rule_ref"] = reference_value(drift_ref)
    uncertainty = reader.record(
        uncertainty_ref,
        parent_subject=profile_ref.digest,
        pointer="/uncertainty_derivation_rule_ref",
        method="emt_timesyncd_uncertainty_v2",
        units="integer_nanoseconds",
        fields=_UNCERTAINTY_FIELDS,
        expected=selected,
    )
    uncertainty = _sources(
        uncertainty,
        (
            "holdover_rule_ref",
            "daemon_field_mapping_rule_ref",
            "accepted_ntp_configuration_ref",
            "acquisition_rule_ref",
            "ntp_resolution_and_rotation_rule_ref",
            "sample_mapping_and_quantization_rule_ref",
        ),
        reader=reader,
    )
    use_ref = decode_reference(
        witness["holdover_and_use_error_derivation_ref"],
        subject=witness_ref.digest,
        pointer="/holdover_and_use_error_derivation_ref",
    )
    expected = common | {
        "subject_ref": witness["subject_ref"],
        "profile_ref": reference_value(profile_ref),
        "first_sample_source_ref": witness["first_sample_source_ref"],
        "request_id": witness["request_id"],
        "uncertainty_rule_ref": reference_value(uncertainty_ref),
        "holdover_rule_ref": reference_value(drift_ref),
        "before_raw_ref": cast(dict[str, JsonValue], witness["before"])["clock_sample_raw_ref"],
        "after_raw_ref": cast(dict[str, JsonValue], witness["after"])["clock_sample_raw_ref"],
        "use_raw_ref": witness["use_sample_raw_ref"],
        "use_monotonic_ticks": witness["use_monotonic_ticks"],
        "use_error_bound_ns": witness["use_error_bound_ns"],
    }
    use = reader.record(
        use_ref,
        parent_subject=witness_ref.digest,
        pointer="/holdover_and_use_error_derivation_ref",
        method="emt_clock_use_bounds_v1",
        units="integer_nanoseconds",
        fields=_USE_FIELDS,
        expected=expected,
    )
    use_value = _value(use)
    synchronization = cast(list[JsonValue], witness["raw_synchronization_refs"])
    if any(use_value[name] not in synchronization for name in ("before_ntp_ref", "after_ntp_ref")):
        raise clock_unavailable(subject, CLOCK_POINTER)
    use = _sources(
        use,
        (
            "subject_ref",
            "profile_ref",
            "first_sample_source_ref",
            "uncertainty_rule_ref",
            "holdover_rule_ref",
            "before_ntp_ref",
            "after_ntp_ref",
            "before_raw_ref",
            "after_raw_ref",
            "use_raw_ref",
        ),
        reader=reader,
    )
    samples = method_object(
        use_value["sample_bounds"],
        frozenset({"before", "after"}),
        subject=use_ref.digest,
        pointer="/sample_bounds",
    )
    before = reader.bounds(
        samples["before"], SAMPLE_TERMS, subject=use_ref.digest, pointer="/sample_bounds/before"
    )
    after = reader.bounds(
        samples["after"], SAMPLE_TERMS, subject=use_ref.digest, pointer="/sample_bounds/after"
    )
    use_terms = reader.bounds(
        use_value["use_terms"], USE_TERMS, subject=use_ref.digest, pointer="/use_terms"
    )
    entry_terms = reader.bounds(
        use_value["entry_terms"], USE_TERMS, subject=use_ref.digest, pointer="/entry_terms"
    )
    bound_edges: list[tuple[str, ClockMethodSource]] = []
    for pointer, values in (
        ("/sample_bounds/before", before),
        ("/sample_bounds/after", after),
        ("/use_terms", use_terms),
        ("/entry_terms", entry_terms),
    ):
        bound_edges.extend(
            (pointer + "/" + name + "/source_ref", term.source) for name, term in values.items()
        )
    use = replace(use, evidence=(*use.evidence, *bound_edges))
    acceptance = acquire_acceptance_inputs(clock, uncertainty=uncertainty, reader=reader)
    uncertainty = replace(
        uncertainty,
        evidence=(*uncertainty.evidence, ("/annual_derivation_ref", acceptance.record.source)),
    )
    return ClockMethodInputs(
        uncertainty,
        drift,
        use,
        rate,
        before,
        after,
        use_terms,
        entry_terms,
        acceptance,
    )
