# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete explicitly unqualified Clock model declarations

"""Retain real capture provenance and conditional parameters without fabricating model support."""

import json
from fractions import Fraction
from math import ceil
from pathlib import Path

from tests.domain.clock_annual_method_inputs import capture_holdover, clock_annual_method_input
from tests.domain.clock_method_cases import clock_method_body, clock_method_reference
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef


def _common(
    identity: BlobRef, environment: BlobRef, boot: BlobRef, custody_class: str
) -> dict[str, object]:
    """Declare complete earlier source context while preserving its unqualified provenance.

    Parameters
    ----------
    identity, environment, boot : BlobRef
        Whole actual already retained sources; identity explicitly has qualified_rule=false.
    custody_class : str
        Actual independently paired caller class, without a stronger observation claim.

    Returns
    -------
    dict
        Complete common data-only source declaration; no accepted/supported flag exists.
    """
    return {
        "custody_class": custody_class,
        "host_identity_ref": dict(identity.to_mapping()),
        "controller_identity_ref": dict(identity.to_mapping()),
        "implementation_environment_ref": dict(environment.to_mapping()),
        "boot_domain_ref": dict(boot.to_mapping()),
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z",
        "renewal_rule": "fresh_source_model_before_expiry_no_implicit_extension",
        "assumptions_and_limitations_ref": dict(identity.to_mapping()),
        "provenance_refs": [dict(identity.to_mapping())],
    }


def clock_model_inputs(
    directory: Path,
    *,
    condition: str,
    identity: BlobRef,
    environment: BlobRef,
    boot: BlobRef,
    custody_class: str,
    annual: dict[str, object],
    ntp: BlobRef,
    original_samples: tuple[dict[str, object], dict[str, object]],
    qualified_rate: Fraction | None = None,
) -> tuple[BlobRef, BlobRef]:
    """Store whole original annual data and both models before profile/context creation.

    Parameters
    ----------
    directory : Path
        Owned immutable raw input store.
    condition : str
        Named whole model fault, or an unchanged existing source condition.
    identity, environment, boot : BlobRef
        Entire genuine retained sources, without a qualified calibration/model claim.
    custody_class : str
        Actual explicit independent caller selection.
    annual : dict
        Original annual capture fields after deliberate source faults, never a stored partial body.
    ntp : BlobRef
        Explicit actual annual daemon acquisition, without list-position packet selection.
    original_samples : tuple of dict
        Genuine original captures retained before any deliberate malformed raw substitution.
    qualified_rate : Fraction or None
        When set, the drift record declares this rate and the annual holdovers follow it.

    Returns
    -------
    tuple
        Full uncertainty and drift references. The explicit test ratio and source refs
        are UNQUALIFIED declarations for conditional arithmetic, never physical rho proof.
    """
    common = _common(identity, environment, boot, custody_class)
    ref: dict[str, object] = dict(identity.to_mapping())
    rate = Fraction(1, 1_000_000) if qualified_rate is None else qualified_rate
    drift = _stored(
        clock_method_body(
            condition,
            "drift",
            {
                **common,
                "method_id": "emt_monotonic_raw_drift_v1",
                "units": "nanoseconds_per_elapsed_nanosecond",
                "maximum_error_rate": {
                    "numerator": str(rate.numerator),
                    "denominator": str(rate.denominator),
                },
                "rate_source_ref": ref,
                "calibration_source_ref": ref,
                "monotonic_mapping_rule_ref": ref,
                "adjustment_rule_ref": ref,
            },
            directory,
        ),
        directory,
    )
    drift = clock_method_reference(condition, drift, directory)
    annual_derivation = clock_annual_method_input(
        directory,
        condition=condition,
        common=common,
        identity=identity,
        drift=drift,
        ntp=ntp,
        annual=annual,
        original_samples=original_samples,
        qualified_rate=qualified_rate,
    )
    uncertainty = _stored(
        clock_method_body(
            condition,
            "uncertainty",
            {
                **common,
                "method_id": "emt_timesyncd_uncertainty_v2",
                "units": "integer_nanoseconds",
                "holdover_rule_ref": dict(drift.to_mapping()),
                "daemon_field_mapping_rule_ref": ref,
                "accepted_ntp_configuration_ref": ref,
                "acquisition_rule_ref": ref,
                "ntp_resolution_and_rotation_rule_ref": ref,
                "sample_mapping_and_quantization_rule_ref": ref,
                "annual_derivation_ref": dict(annual_derivation.to_mapping()),
            },
            directory,
        ),
        directory,
    )
    return uncertainty, drift


def clock_use_input(
    directory: Path,
    *,
    condition: str,
    identity: BlobRef,
    environment: BlobRef,
    boot: BlobRef,
    custody_class: str,
    profile: BlobRef,
    subject: BlobRef,
    first: BlobRef,
    uncertainty: BlobRef,
    drift: BlobRef,
    ntp: BlobRef,
    before: dict[str, object],
    after: dict[str, object],
    use: dict[str, object],
    request_id: str,
    qualified_rate: Fraction | None = None,
) -> BlobRef:
    """Store all full per-invocation terms after actual S1/H and before the witness.

    Parameters
    ----------
    directory : Path
        Owned actual raw source store.
    condition : str
        Named whole use/error/window fault, or an unchanged source condition.
    identity, environment, boot : BlobRef
        Entire original source context, retaining explicitly unqualified model provenance.
    custody_class : str
        Exact actual caller class.
    profile, subject, first : BlobRef
        Whole already frozen earlier sources, without future witness or E.
    uncertainty, drift : BlobRef
        Complete earlier independent model selections.
    ntp : BlobRef
        Entire genuine retained structured daemon observation.
    before, after, use : dict
        Actual bracketed local captures, whose numerical error declarations are unqualified.
    request_id : str
        Whole original request from the actual first-sample source.
    qualified_rate : Fraction or None
        When set, the sample holdovers and the declared use error follow this drift rate.

    Returns
    -------
    BlobRef
        Entire later derivation. All unknown physical/model premises remain unqualified;
        explicit positive test terms are not asserted independently supported bounds.
    """
    ref: dict[str, object] = dict(identity.to_mapping())

    def term(number: str, source: dict[str, object]) -> dict[str, object]:
        """Retain an explicit numerical declaration and its entire original source.

        Parameters
        ----------
        number : str
            Exact conditional test integer, without a missing-value default.
        source : dict
            Whole actual original reference.

        Returns
        -------
        dict
            Both mandatory bound fields, without a supported/accepted claim.
        """
        return {"bound_ns": number, "source_ref": source}

    def bracket(sample: dict[str, object]) -> tuple[dict[str, object], str]:
        """Read an actual retained acquisition bracket independently of production helpers.

        Parameters
        ----------
        sample : dict
            Complete original actual capture declaration.

        Returns
        -------
        tuple
            Whole source reference and exact observed nonnegative RAW duration.
        """
        source = _object(sample["clock_sample_raw_ref"])
        raw = _object(json.loads((directory / str(source["digest"])[7:]).read_bytes()))
        return source, str(int(str(raw["raw_after"])) - int(str(raw["raw_before"])))

    samples: dict[str, object] = {}
    for name, sample in (("before", before), ("after", after)):
        source, duration = bracket(sample)
        samples[name] = {
            "source_encoding": term("6000", ref),
            "elapsed_holdover": term(
                "1000"
                if qualified_rate is None
                else capture_holdover(directory, ntp, sample, qualified_rate),
                ref,
            ),
            "post_exchange_adjustment": term("1000", ref),
            "acquisition": term(duration, source),
            "mapping": term("1000", ref),
            "quantization": term("1000", ref),
        }
    use_source, use_duration = bracket(use)
    rate = Fraction(1, 1_000_000) if qualified_rate is None else qualified_rate
    declared_use_error = str(
        ceil(rate * (int(str(use["monotonic_ticks"])) - int(str(after["monotonic_ticks"]))))
        + int(use_duration)
        + 3000
    )
    return _stored(
        clock_method_body(
            condition,
            "use",
            {
                **_common(identity, environment, boot, custody_class),
                "method_id": "emt_clock_use_bounds_v1",
                "units": "integer_nanoseconds",
                "subject_ref": dict(subject.to_mapping()),
                "profile_ref": dict(profile.to_mapping()),
                "first_sample_source_ref": dict(first.to_mapping()),
                "request_id": request_id,
                "uncertainty_rule_ref": dict(uncertainty.to_mapping()),
                "holdover_rule_ref": dict(drift.to_mapping()),
                "before_ntp_ref": dict(ntp.to_mapping()),
                "after_ntp_ref": dict(ntp.to_mapping()),
                "before_raw_ref": before["clock_sample_raw_ref"],
                "after_raw_ref": after["clock_sample_raw_ref"],
                "use_raw_ref": use["clock_sample_raw_ref"],
                "use_monotonic_ticks": use["monotonic_ticks"],
                "use_error_bound_ns": declared_use_error,
                "sample_bounds": samples,
                "use_terms": {
                    "acquisition": term(use_duration, use_source),
                    "mapping": term("1000", ref),
                    "quantization": term("1000", ref),
                    "adjustment": term("1000", ref),
                },
                "entry_terms": {
                    "acquisition": term("100000000", ref),
                    "mapping": term("1000", ref),
                    "quantization": term("1000", ref),
                    "adjustment": term("1000", ref),
                },
            },
            directory,
        ),
        directory,
    )
