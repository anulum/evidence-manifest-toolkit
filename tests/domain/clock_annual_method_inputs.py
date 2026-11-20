# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original annual raw method public inputs

"""Keep genuine original captures and deliberately unqualified annual bound declarations."""

import json
from collections.abc import Mapping
from fractions import Fraction
from math import ceil
from pathlib import Path

from tests.domain.clock_annual_method_cases import clock_annual_method_source
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef


def capture_holdover(
    directory: Path, ntp: BlobRef, sample: Mapping[str, object], rate: Fraction
) -> str:
    """Return the holdover a sample needs at ``rate`` since the exchange its capture records.

    Parameters
    ----------
    directory : Path
        Owned source store holding the capture's whole busctl reply under its digest.
    ntp : BlobRef
        The capture whose destination time T4 (microseconds) the sample's age is measured from.
    sample : Mapping
        The sample, with its ``utc_epoch_ns``.
    rate : Fraction
        The drift rate the case declares.

    Returns
    -------
    str
        ceil(rate * (UTC - T4 + the fixture's 1000 ns post-exchange adjustment)), in ns.
    """
    tokens = (directory / str(ntp.digest)[7:]).read_bytes().decode("ascii").split()
    age = int(str(sample["utc_epoch_ns"])) - int(tokens[16]) * 1000 + 1000
    return str(ceil(rate * age))


def clock_annual_method_input(
    directory: Path,
    *,
    condition: str,
    common: dict[str, object],
    identity: BlobRef,
    drift: BlobRef,
    ntp: BlobRef,
    annual: dict[str, object],
    original_samples: tuple[dict[str, object], dict[str, object]],
    qualified_rate: Fraction | None = None,
) -> BlobRef:
    """Store the whole original annual dependency before its profile and acceptance body.

    Parameters
    ----------
    directory : Path
        Owned immutable source store, retaining the true captures and every deliberate fault.
    condition : str
        Original public scenario, including named malformed raw-source controls.
    common : dict
        Complete earlier host/controller/environment/model context, explicitly unqualified.
    identity, drift : BlobRef
        Whole actual earlier source and selected conditional drift declaration.
    ntp : BlobRef
        Explicit actual original daemon reply from this annual acquisition, not list position.
    annual : dict
        In-memory original capture fields, after deliberate source faults and before the
        later profile/acceptance identity exists. This partial draft is never persisted.
    original_samples : tuple of dict
        Both complete genuine captures retained before a negative-source substitution.
        A malformed replacement is not parsed in the helper before the public invocation.
    qualified_rate : Fraction or None
        When set, each sample's holdover is derived from its own age at this rate.

    Returns
    -------
    BlobRef
        Complete fixed data-only annual method. Every numeric test term and physical
        source/model premise remains UNQUALIFIED; none is a calibration or Clock pass.
    """
    ref: dict[str, object] = dict(identity.to_mapping())
    rows: dict[str, object] = {}
    associations: dict[str, object] = {}
    for index, name in enumerate(("before", "after")):
        sample = _object(annual[name])
        raw_reference = _object(sample["clock_sample_raw_ref"])
        matches = [
            value for value in original_samples if value["clock_sample_raw_ref"] == raw_reference
        ]
        if matches:
            genuine = matches[0]
        else:
            assert condition.removeprefix("cli_").startswith("acceptance_capture_raw_")
            assert name == "before"
            genuine = original_samples[index]
        source = _object(genuine["clock_sample_raw_ref"])
        raw = _object(json.loads((directory / str(source["digest"])[7:]).read_bytes()))
        duration = int(str(raw["raw_after"])) - int(str(raw["raw_before"]))
        assert duration >= 0
        declared: dict[str, object] = {}
        for field, number, provenance in (
            ("source_encoding", "6000", ref),
            (
                "elapsed_holdover",
                "1000"
                if qualified_rate is None
                else capture_holdover(directory, ntp, sample, qualified_rate),
                ref,
            ),
            ("post_exchange_adjustment", "1000", ref),
            ("acquisition", str(duration), source),
            ("mapping", "1000", ref),
            ("quantization", "1000", ref),
        ):
            declared[field] = {"bound_ns": number, "source_ref": provenance}
        rows[name] = declared
        associations[name] = {
            "clock_sample_raw_ref": raw_reference,
            "ntp_ref": dict(ntp.to_mapping()),
        }
    return clock_annual_method_source(
        condition,
        {
            **common,
            "method_id": "emt_clock_acceptance_bounds_v1",
            "units": "integer_nanoseconds",
            "monotonic_domain_ref": annual["monotonic_domain_ref"],
            "ticks_per_second": annual["ticks_per_second"],
            "before": associations["before"],
            "after": associations["after"],
            "raw_synchronization_refs": annual["raw_synchronization_refs"],
            "measured_offset_source_ref": dict(ntp.to_mapping()),
            "sample_bounds": rows,
            "holdover_rule_ref": dict(drift.to_mapping()),
            "daemon_field_mapping_rule_ref": ref,
            "accepted_ntp_configuration_ref": ref,
            "acquisition_rule_ref": ref,
            "ntp_resolution_and_rotation_rule_ref": ref,
            "sample_mapping_and_quantization_rule_ref": ref,
        },
        directory,
    )
