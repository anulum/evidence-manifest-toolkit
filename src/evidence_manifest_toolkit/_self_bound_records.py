# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the records of one self-bound unsigned verification request

"""Build and stage, in memory, every record a self-bound unsigned V2 request consists of.

Each builder writes one record of the r4 Clock formats or the V2 policy from values the child
captured and the launcher declared, in the order the formats bind them: identity sources, the
annual acceptance and its models, the first sample, the entry binding, the trust context and
the evaluation subject, then the later captures, the use method, the witness, the final local
policy and the V2 policy. Records are canonical JSON (RFC 8785) or the exact captured bytes,
held by digest until the launch decides whether to publish them.
"""

import hashlib
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from math import ceil
from typing import cast

import rfc8785

from ._clock_values import NANOSECONDS_PER_SECOND
from ._clock_windows import EVALUATION_BUDGET_NS
from ._errors import StorageError
from ._json import JsonValue
from ._self_bound_declaration import SelfBoundDeclaration
from ._timesyncd_capture import capture_ntp_message
from ._values import BlobRef, Reason

UNSIGNED_CLASS = "unsigned_declared"
IDENTITY_CLASS = "declared_by_launcher_under_the_seat_account"
POLICY_SCHEMA_ID = "evidence_manifest_toolkit.authority_policy.v2"
TICKS_PER_SECOND: dict[str, JsonValue] = {"numerator": "1000000000", "denominator": "1"}
"""CLOCK_MONOTONIC_RAW counts nanoseconds."""

type Wire = dict[str, JsonValue]


class StagedObjects:
    """Hold every record of one request by digest, before anything is written.

    Attributes
    ----------
    objects : dict of str to bytes
        Each staged record's bytes, keyed by its 64-hex-digit sha256.
    """

    def __init__(self) -> None:
        """Start with no staged record."""
        self.objects: dict[str, bytes] = {}

    def raw(self, data: bytes, media_type: str) -> BlobRef:
        """Stage exact bytes under their raw identity.

        Parameters
        ----------
        data : bytes
            The whole record.
        media_type : str
            Its media type.

        Returns
        -------
        BlobRef
            Its raw-bytes reference.
        """
        digest = hashlib.sha256(data).hexdigest()
        self.objects[digest] = data
        return BlobRef("sha256:" + digest, str(len(data)), media_type, "raw_bytes")

    def json(self, value: Wire, *, schema_id: str | None = None) -> BlobRef:
        """Stage one record as canonical JSON under its raw identity.

        Parameters
        ----------
        value : dict
            The whole record.
        schema_id : str or None
            The schema its reference asserts, if any.

        Returns
        -------
        BlobRef
            Its raw-bytes reference.
        """
        data = rfc8785.dumps(value)
        digest = hashlib.sha256(data).hexdigest()
        self.objects[digest] = data
        return BlobRef(
            "sha256:" + digest, str(len(data)), "application/json", "raw_bytes", schema_id
        )


def wire(reference: BlobRef) -> Wire:
    """Return a reference's wire form.

    Parameters
    ----------
    reference : BlobRef
        The reference.

    Returns
    -------
    dict
        Its mapping.
    """
    return cast(Wire, dict(reference.to_mapping()))


def utc_lexeme(nanoseconds: int) -> str:
    """Encode a CLOCK_REALTIME reading as a nine-digit UTC lexeme.

    Parameters
    ----------
    nanoseconds : int
        Nanoseconds since 1970-01-01T00:00:00Z.

    Returns
    -------
    str
        The lexeme ``YYYY-MM-DDTHH:MM:SS.fffffffffZ``.
    """
    seconds, remainder = divmod(nanoseconds, 1_000_000_000)
    value = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    return value.strftime("%Y-%m-%dT%H:%M:%S") + f".{remainder:09d}Z"


def acceptance_window(first_ns: int) -> tuple[str, str]:
    """Return the one-civil-year window of an acceptance whose first sample reads ``first_ns``.

    The window starts the verification's evaluation budget (``EVALUATION_BUDGET_NS``) before
    that sample's whole second. Every interval the verification checks against the window lies
    within that budget of an evaluation origin taken after that sample, so none can begin
    before the window does.

    Parameters
    ----------
    first_ns : int
        The acceptance's first sample, in UTC nanoseconds.

    Returns
    -------
    tuple of str
        The window's start, and the same instant one civil year later, 29 February clamped to 28.
    """
    start = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
        seconds=first_ns // NANOSECONDS_PER_SECOND - EVALUATION_BUDGET_NS // NANOSECONDS_PER_SECOND
    )
    end = start.replace(
        year=start.year + 1,
        day=28 if (start.month, start.day) == (2, 29) else start.day,
    )
    return start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class CapturedSample:
    """One CLOCK_REALTIME reading bracketed by two CLOCK_MONOTONIC_RAW readings.

    Attributes
    ----------
    raw_ref : BlobRef
        The staged raw sample record.
    utc_ns, raw_before, raw_after : int
        The three readings, in nanoseconds.
    """

    raw_ref: BlobRef
    utc_ns: int
    raw_before: int
    raw_after: int


@dataclass(frozen=True, slots=True)
class CapturedExchange:
    """One staged timesyncd reply and what the records derive from it.

    Attributes
    ----------
    reference : BlobRef
        The staged whole reply.
    destination_ns : int
        The exchange's destination time T4, in nanoseconds.
    offset_ns : int
        The reported offset ((T2 - T1) + (T3 - T4)) / 2, in nanoseconds.
    """

    reference: BlobRef
    destination_ns: int
    offset_ns: int


def capture_sample(store: StagedObjects) -> CapturedSample:
    """Read the realtime clock between two raw monotonic readings and stage the raw record.

    Parameters
    ----------
    store : StagedObjects
        The request's staged records.

    Returns
    -------
    CapturedSample
        The reading.
    """
    start = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    utc = time.clock_gettime_ns(time.CLOCK_REALTIME)
    end = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    raw = store.json(
        {
            "clock": "CLOCK_REALTIME",
            "utc_ns": str(utc),
            "raw_before": str(start),
            "raw_after": str(end),
            "physical_uncertainty": "unavailable",
        }
    )
    return CapturedSample(raw, utc, start, end)


def exchange_from_reply(store: StagedObjects, raw: bytes) -> CapturedExchange:
    """Stage one whole timesyncd reply and read its destination time and reported offset.

    Parameters
    ----------
    store : StagedObjects
        The request's staged records.
    raw : bytes
        The whole reply as ``busctl`` printed it.

    Returns
    -------
    CapturedExchange
        The reply with its destination time and reported offset.

    Raises
    ------
    StorageError
        The reply is not the fixed 20-token NTPMessage form with integer timestamps.
    """
    tokens = raw.decode("ascii", errors="replace").split()
    timestamps = tokens[13:17]
    if (
        len(tokens) != 20
        or tokens[0] != "(uuuuittayttttbtt)"
        or not all(token.isdigit() for token in timestamps)
    ):
        raise StorageError(
            Reason(
                "storage_error",
                None,
                None,
                "/clock/ntp_capture",
                "The timesyncd NTP capture is unavailable.",
            )
        )
    t1, t2, t3, t4 = map(int, timestamps)
    return CapturedExchange(store.raw(raw, "text/plain"), t4 * 1000, ((t2 - t1) + (t3 - t4)) * 500)


def capture_exchange(store: StagedObjects) -> CapturedExchange:
    """Capture timesyncd's last NTP exchange and stage the whole reply.

    A reply is captured before the samples that are aged from it, so the exchange it records
    cannot complete after them, even when the daemon polls during the launch.

    Parameters
    ----------
    store : StagedObjects
        The request's staged records.

    Returns
    -------
    CapturedExchange
        The reply with its destination time and reported offset.

    Raises
    ------
    StorageError
        The capture is unavailable, or the reply is not the fixed NTPMessage form.
    """
    return exchange_from_reply(store, capture_ntp_message())


def sample_declaration(sample: CapturedSample, declaration: SelfBoundDeclaration) -> Wire:
    """Return a sample as the Clock formats declare it.

    Parameters
    ----------
    sample : CapturedSample
        The reading.
    declaration : SelfBoundDeclaration
        The launcher's declared per-sample bounds.

    Returns
    -------
    dict
        The sample declaration.
    """
    bounds = declaration.sample_bounds
    return {
        "utc_lexeme": utc_lexeme(sample.utc_ns),
        "utc_epoch_ns": str(sample.utc_ns),
        "monotonic_ticks": str(sample.raw_after),
        "clock_sample_raw_ref": wire(sample.raw_ref),
        "accuracy_radius_ns": str(bounds["accuracy_radius_ns"]),
        "mapping_error_bound_ns": str(bounds["mapping_ns"]),
        "quantization_error_bound_ns": str(bounds["quantization_ns"]),
    }


def sample_radius(declaration: SelfBoundDeclaration) -> int:
    """Return a sample's whole declared error radius: accuracy, mapping and quantization.

    Parameters
    ----------
    declaration : SelfBoundDeclaration
        The launcher's declared per-sample bounds.

    Returns
    -------
    int
        The radius in nanoseconds.
    """
    bounds = declaration.sample_bounds
    return bounds["accuracy_radius_ns"] + bounds["mapping_ns"] + bounds["quantization_ns"]


def _term(bound: int, source: Wire) -> Wire:
    """Return one declared error term with its source.

    Parameters
    ----------
    bound : int
        The term's bound in nanoseconds.
    source : dict
        The reference of its source.

    Returns
    -------
    dict
        The term.
    """
    return {"bound_ns": str(bound), "source_ref": source}


def sample_terms(
    sample: CapturedSample, exchange: CapturedExchange, declaration: SelfBoundDeclaration
) -> Wire:
    """Return the six error terms of one sample against the exchange it is aged from.

    The holdover is the declared drift rate times the sample's age since the exchange's
    destination time plus the declared post-exchange adjustment, rounded up; the acquisition is
    the sample's own bracketing duration. The other terms are the launcher's declarations.

    Parameters
    ----------
    sample : CapturedSample
        The reading.
    exchange : CapturedExchange
        The exchange the sample's holdover is measured from.
    declaration : SelfBoundDeclaration
        The launcher's declared rate, bounds and term source.

    Returns
    -------
    dict
        The terms ``source_encoding``, ``elapsed_holdover``, ``post_exchange_adjustment``,
        ``acquisition``, ``mapping`` and ``quantization``.
    """
    bounds = declaration.sample_bounds
    source = wire(declaration.rule_references["term_source_ref"])
    adjustment = bounds["post_exchange_adjustment_ns"]
    age = sample.utc_ns - exchange.destination_ns + adjustment
    return {
        "source_encoding": _term(bounds["source_encoding_ns"], source),
        "elapsed_holdover": _term(max(ceil(declaration.drift_rate * age), 0), source),
        "post_exchange_adjustment": _term(adjustment, source),
        "acquisition": _term(sample.raw_after - sample.raw_before, wire(sample.raw_ref)),
        "mapping": _term(bounds["mapping_ns"], source),
        "quantization": _term(bounds["quantization_ns"], source),
    }


@dataclass(frozen=True, slots=True)
class IdentitySources:
    """The child's own staged identity sources.

    Attributes
    ----------
    environment, boot, process, method, identity : BlobRef
        The implementation environment, the boot domain, the process start identity, the
        installed native entry method and the launcher-declared identity naming this process.
    """

    environment: BlobRef
    boot: BlobRef
    process: BlobRef
    method: BlobRef
    identity: BlobRef


def common_model_fields(sources: IdentitySources, declaration: SelfBoundDeclaration) -> Wire:
    """Return the fields every Clock model record shares.

    Parameters
    ----------
    sources : IdentitySources
        The child's identity sources.
    declaration : SelfBoundDeclaration
        The launcher's declared validity window and provenance.

    Returns
    -------
    dict
        The shared fields.
    """
    identity = wire(sources.identity)
    return {
        "custody_class": UNSIGNED_CLASS,
        "host_identity_ref": identity,
        "controller_identity_ref": identity,
        "implementation_environment_ref": wire(sources.environment),
        "boot_domain_ref": wire(sources.boot),
        "valid_from": str(declaration.model_valid_from),
        "valid_until": str(declaration.model_valid_until),
        "renewal_rule": "fresh_source_model_before_expiry_no_implicit_extension",
        "assumptions_and_limitations_ref": wire(
            declaration.rule_references["assumptions_and_limitations_ref"]
        ),
        "provenance_refs": [wire(reference) for reference in declaration.provenance_refs],
    }


def _rules(declaration: SelfBoundDeclaration, *names: str) -> Wire:
    """Return the named declared rule references in wire form.

    Parameters
    ----------
    declaration : SelfBoundDeclaration
        The launcher's declaration.
    *names : str
        The rule fields.

    Returns
    -------
    dict
        Each field with its reference.
    """
    return {name: wire(declaration.rule_references[name]) for name in names}


_NTP_RULES = (
    "daemon_field_mapping_rule_ref",
    "accepted_ntp_configuration_ref",
    "acquisition_rule_ref",
    "ntp_resolution_and_rotation_rule_ref",
    "sample_mapping_and_quantization_rule_ref",
)


@dataclass(frozen=True, slots=True)
class AnnualAcceptance:
    """The staged annual acceptance of this launch and its models.

    Attributes
    ----------
    drift, annual_derivation, uncertainty, profile, acceptance : BlobRef
        The drift model, the annual derivation, the uncertainty model, the profile and the
        acceptance body.
    before, after : CapturedSample
        The acceptance's two samples.
    exchange : CapturedExchange
        Its NTP reply.
    """

    drift: BlobRef
    annual_derivation: BlobRef
    uncertainty: BlobRef
    profile: BlobRef
    acceptance: BlobRef
    before: CapturedSample
    after: CapturedSample
    exchange: CapturedExchange


def stage_annual_acceptance(
    store: StagedObjects,
    sources: IdentitySources,
    declaration: SelfBoundDeclaration,
    checks: Callable[[Mapping[str, BlobRef]], list[JsonValue]],
) -> AnnualAcceptance:
    """Capture and stage this launch's acceptance: an NTP reply, two samples, and its models.

    The acceptance holds for this launch's boot only: its reply and its samples are taken now,
    and its monotonic domain is this boot. The reply comes first, so neither sample can be
    older than the exchange it is aged from.

    Parameters
    ----------
    store : StagedObjects
        The request's staged records.
    sources : IdentitySources
        The child's identity sources.
    declaration : SelfBoundDeclaration
        The launcher's declarations.
    checks : callable
        Given the records stored before the acceptance body, by evidence role, returns the six
        declared checks with their evidence resolved, in wire form.

    Returns
    -------
    AnnualAcceptance
        The staged records and captures.
    """
    exchange = capture_exchange(store)
    before = capture_sample(store)
    after = capture_sample(store)
    common = common_model_fields(sources, declaration)
    rate = declaration.drift_rate
    drift = store.json(
        {
            **common,
            "method_id": "emt_monotonic_raw_drift_v1",
            "units": "nanoseconds_per_elapsed_nanosecond",
            "maximum_error_rate": {
                "numerator": str(rate.numerator),
                "denominator": str(rate.denominator),
            },
            **_rules(
                declaration,
                "rate_source_ref",
                "calibration_source_ref",
                "monotonic_mapping_rule_ref",
                "adjustment_rule_ref",
            ),
        }
    )
    annual_derivation = store.json(
        {
            **common,
            "method_id": "emt_clock_acceptance_bounds_v1",
            "units": "integer_nanoseconds",
            "monotonic_domain_ref": wire(sources.boot),
            "ticks_per_second": TICKS_PER_SECOND,
            "before": {
                "clock_sample_raw_ref": wire(before.raw_ref),
                "ntp_ref": wire(exchange.reference),
            },
            "after": {
                "clock_sample_raw_ref": wire(after.raw_ref),
                "ntp_ref": wire(exchange.reference),
            },
            "raw_synchronization_refs": [wire(exchange.reference)],
            "measured_offset_source_ref": wire(exchange.reference),
            "sample_bounds": {
                "before": sample_terms(before, exchange, declaration),
                "after": sample_terms(after, exchange, declaration),
            },
            "holdover_rule_ref": wire(drift),
            **_rules(declaration, *_NTP_RULES),
        }
    )
    uncertainty = store.json(
        {
            **common,
            "method_id": "emt_timesyncd_uncertainty_v2",
            "units": "integer_nanoseconds",
            "holdover_rule_ref": wire(drift),
            **_rules(declaration, *_NTP_RULES),
            "annual_derivation_ref": wire(annual_derivation),
        }
    )
    identity = wire(sources.identity)
    profile = store.json(
        {
            "format_version": "autonomous-evaluation-clock-profile-source-r4",
            "time_source": declaration.time_source,
            "host_identity_ref": identity,
            "controller_identity_ref": identity,
            "observer_identity_ref": identity,
            "implementation_environment_ref": wire(sources.environment),
            "uncertainty_derivation_rule_ref": wire(uncertainty),
            "issuer_identity_ref": None,
            "issuer_authorization_ref": None,
            "maximum_uncertainty_ns": str(declaration.maximum_uncertainty_ns),
            "renewal_rule": "one_utc_civil_year_feb29_clamped_to_feb28",
            "coordinate_encoding": (
                "exact_proleptic_gregorian_civil_nanoseconds_without_leap_second_lexemes"
            ),
            "custody_class": UNSIGNED_CLASS,
            "holdover_drift_bound_rule_ref": wire(drift),
            "handoff_rule": (
                "fixed_at_verify_entry_extend_by_actual_monotonic_elapsed_and_complete_error_budget"
            ),
            **_rules(
                declaration,
                "accepted_ntp_configuration_ref",
                "acquisition_rule_ref",
                "monotonic_mapping_rule_ref",
                "independence_rule_ref",
                "daemon_field_mapping_rule_ref",
                "ntp_resolution_and_rotation_rule_ref",
                "automatic_reacceptance_rule_ref",
            ),
        }
    )
    roles = {
        "environment": sources.environment,
        "boot_domain": sources.boot,
        "process_start": sources.process,
        "entry_method": sources.method,
        "identity_declaration": sources.identity,
        "annual_before_raw_sample": before.raw_ref,
        "annual_ntp_reply": exchange.reference,
        "annual_after_raw_sample": after.raw_ref,
        "drift_method": drift,
        "annual_derivation": annual_derivation,
        "uncertainty_method": uncertainty,
        "profile": profile,
    }
    radius = sample_radius(declaration)
    valid_from, valid_until = acceptance_window(before.utc_ns)
    acceptance = store.json(
        {
            "format_version": "autonomous-evaluation-clock-acceptance-source-r4",
            "raw_synchronization_refs": [wire(exchange.reference)],
            "monotonic_domain_ref": wire(sources.boot),
            "ticks_per_second": TICKS_PER_SECOND,
            "before": sample_declaration(before, declaration),
            "after": sample_declaration(after, declaration),
            "acceptance_utc_lower_ns": str(before.utc_ns - radius),
            "acceptance_utc_upper_ns": str(after.utc_ns + radius),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "measured_ntp_offset_ns": str(exchange.offset_ns),
            "profile_ref": wire(profile),
            "host_identity_ref": identity,
            "controller_identity_ref": identity,
            "observer_identity_ref": identity,
            "issuer_identity_ref": None,
            "issuer_authorization_ref": None,
            "rule_implementation_ref": wire(declaration.rule_references["rule_implementation_ref"]),
            "checks": checks(roles),
            "custody_class": UNSIGNED_CLASS,
        }
    )
    return AnnualAcceptance(
        drift, annual_derivation, uncertainty, profile, acceptance, before, after, exchange
    )


def use_error_bound(
    after: CapturedSample, use: CapturedSample, declaration: SelfBoundDeclaration
) -> int:
    """Return the declared error of the use instant against the "after" sample.

    Parameters
    ----------
    after, use : CapturedSample
        The "after" sample and the use sample.
    declaration : SelfBoundDeclaration
        The launcher's declared rate and bounds.

    Returns
    -------
    int
        ceil(rate * elapsed ticks) plus the use sample's acquisition, mapping, quantization and
        adjustment, in nanoseconds.
    """
    bounds = declaration.sample_bounds
    return (
        ceil(declaration.drift_rate * (use.raw_after - after.raw_after))
        + (use.raw_after - use.raw_before)
        + bounds["mapping_ns"]
        + bounds["quantization_ns"]
        + bounds["use_adjustment_ns"]
    )


def use_method_record(
    *,
    sources: IdentitySources,
    declaration: SelfBoundDeclaration,
    annual: AnnualAcceptance,
    subject: BlobRef,
    first: BlobRef,
    request_id: str,
    exchange: CapturedExchange,
    samples: tuple[CapturedSample, CapturedSample, CapturedSample],
) -> Wire:
    """Return the use method of one request: every per-invocation term, before the witness.

    Parameters
    ----------
    sources : IdentitySources
        The child's identity sources.
    declaration : SelfBoundDeclaration
        The launcher's declarations.
    annual : AnnualAcceptance
        The launch's acceptance and models.
    subject, first : BlobRef
        The evaluation subject and the first sample record.
    request_id : str
        The request's identifier.
    exchange : CapturedExchange
        The request's NTP reply, captured before its first sample.
    samples : tuple of CapturedSample
        The first sample, the "after" sample and the use sample.

    Returns
    -------
    dict
        The use method record.
    """
    before, after, use = samples
    source = wire(declaration.rule_references["term_source_ref"])
    bounds = declaration.sample_bounds
    entry = declaration.entry_bounds
    return {
        **common_model_fields(sources, declaration),
        "method_id": "emt_clock_use_bounds_v1",
        "units": "integer_nanoseconds",
        "subject_ref": wire(subject),
        "profile_ref": wire(annual.profile),
        "first_sample_source_ref": wire(first),
        "request_id": request_id,
        "uncertainty_rule_ref": wire(annual.uncertainty),
        "holdover_rule_ref": wire(annual.drift),
        "before_ntp_ref": wire(exchange.reference),
        "after_ntp_ref": wire(exchange.reference),
        "before_raw_ref": wire(before.raw_ref),
        "after_raw_ref": wire(after.raw_ref),
        "use_raw_ref": wire(use.raw_ref),
        "use_monotonic_ticks": str(use.raw_after),
        "use_error_bound_ns": str(use_error_bound(after, use, declaration)),
        "sample_bounds": {
            "before": sample_terms(before, exchange, declaration),
            "after": sample_terms(after, exchange, declaration),
        },
        "use_terms": {
            "acquisition": _term(use.raw_after - use.raw_before, wire(use.raw_ref)),
            "mapping": _term(bounds["mapping_ns"], source),
            "quantization": _term(bounds["quantization_ns"], source),
            "adjustment": _term(bounds["use_adjustment_ns"], source),
        },
        "entry_terms": {
            "acquisition": _term(entry["acquisition_ns"], source),
            "mapping": _term(entry["mapping_ns"], source),
            "quantization": _term(entry["quantization_ns"], source),
            "adjustment": _term(entry["adjustment_ns"], source),
        },
    }


def witness_record(
    *,
    sources: IdentitySources,
    declaration: SelfBoundDeclaration,
    annual: AnnualAcceptance,
    subject: BlobRef,
    first: BlobRef,
    request_id: str,
    exchange: CapturedExchange,
    samples: tuple[CapturedSample, CapturedSample, CapturedSample],
    use_method: BlobRef,
) -> Wire:
    """Return the witness that ties the subject, the acceptance and every capture together.

    Parameters
    ----------
    sources : IdentitySources
        The child's identity sources.
    declaration : SelfBoundDeclaration
        The launcher's declarations.
    annual : AnnualAcceptance
        The launch's acceptance and models.
    subject, first : BlobRef
        The evaluation subject and the first sample record.
    request_id : str
        The request's identifier.
    exchange : CapturedExchange
        The request's NTP reply, captured before its first sample.
    samples : tuple of CapturedSample
        The first sample, the "after" sample and the use sample.
    use_method : BlobRef
        The staged use method.

    Returns
    -------
    dict
        The witness record.
    """
    before, after, use = samples
    radius = sample_radius(declaration)
    error = use_error_bound(after, use, declaration)
    identity = wire(sources.identity)
    return {
        "format_version": "autonomous-evaluation-clock-witness-source-r4",
        "subject_ref": wire(subject),
        "request_id": request_id,
        "caller_utc_lexeme": utc_lexeme(before.utc_ns),
        "profile_ref": wire(annual.profile),
        "acceptance_body_ref": wire(annual.acceptance),
        "acceptance_statement_ref": None,
        "ordered_acceptance_receipt_refs": [],
        "controller_identity_ref": identity,
        "observer_identity_ref": identity,
        "raw_synchronization_refs": [wire(exchange.reference)],
        "monotonic_domain_ref": wire(sources.boot),
        "ticks_per_second": TICKS_PER_SECOND,
        "before": sample_declaration(before, declaration),
        "after": sample_declaration(after, declaration),
        "use_sample_raw_ref": wire(use.raw_ref),
        "use_monotonic_ticks": str(use.raw_after),
        "event_utc_lower_ns": str(before.utc_ns - radius),
        "event_utc_upper_ns": str(after.utc_ns + radius),
        "use_utc_upper_ns": str(after.utc_ns + use.raw_after - after.raw_after + radius + error),
        "assurance": "captured_unqualified_until_full_predicate_passes",
        "custody_class": UNSIGNED_CLASS,
        "identity_class": IDENTITY_CLASS,
        "whole_conditions_and_limitations_ref": wire(
            cast(BlobRef, declaration.policy_references["whole_conditions_and_limitations_ref"])
        ),
        "holdover_and_use_error_derivation_ref": wire(use_method),
        "complete_authorization_obligations_ref": wire(
            declaration.rule_references["complete_authorization_obligations_ref"]
        ),
        "use_error_bound_ns": str(error),
        "first_sample_source_ref": wire(first),
        "evaluation_origin": "first_actual_before_sample_frozen_before_whole_context",
    }


def policy_record(declaration: SelfBoundDeclaration, final: BlobRef) -> Wire:
    """Return the unsigned V2 policy over the final local policy.

    Parameters
    ----------
    declaration : SelfBoundDeclaration
        The launcher's declared rules.
    final : BlobRef
        The final local policy, whose Clock qualification names this request's witness.

    Returns
    -------
    dict
        The V2 policy record.
    """
    references: Mapping[str, BlobRef | None] = declaration.policy_references
    return {
        "schema_id": POLICY_SCHEMA_ID,
        "namespace": "EMT_AUTHORITY_SUCCESSOR_POLICY_V2",
        "profile_class": UNSIGNED_CLASS,
        "whole_legacy_artifact_policy_ref": wire(final),
        "authority_rule_ref": None,
        "root_grant_ref": None,
        **{
            name: None if reference is None else wire(reference)
            for name, reference in references.items()
        },
        "minimum_identity_class": declaration.minimum_identity_class,
        "allowed_nonuse_classes": list(declaration.allowed_nonuse_classes),
    }
