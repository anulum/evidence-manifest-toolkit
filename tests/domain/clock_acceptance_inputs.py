# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original annual clock capture public source controls

"""Construct whole acceptance-source faults while preserving actual captures and unavailable proof."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef

CLOCK_ACCEPTANCE_CASES = (
    "acceptance_capture_lower",
    "acceptance_capture_upper",
    "acceptance_capture_reversed",
    "acceptance_capture_rate",
    "acceptance_capture_raw_utc",
    "acceptance_capture_raw_ticks",
    "acceptance_capture_raw_order",
    "acceptance_capture_accuracy",
    "acceptance_capture_budget_lower",
    "acceptance_capture_budget_upper",
    "acceptance_capture_raw_shape",
    "acceptance_capture_raw_json",
    "acceptance_capture_raw_clock",
    "acceptance_capture_raw_uncertainty",
    "acceptance_capture_raw_field_type",
    "cli_acceptance_capture_upper",
    "acceptance_capture_exact",
    "acceptance_capture_equivalent_rate",
    "acceptance_capture_prior_to_validity",
)


def clock_acceptance_input(
    condition: str, value: dict[str, object], directory: Path
) -> dict[str, object]:
    """Materialise one complete original annual source before the later first sample exists.

    Parameters
    ----------
    condition : str
        Named actual capture/source contradiction or an unchanged existing scenario.
    value : dict
        Entire original acceptance with real before/after observations and all six
        outcomes explicitly unavailable. Error declarations never become physical proof.
    directory : Path
        Owned immutable source store; original captures are retained when adding a fault.

    Returns
    -------
    dict
        Full original source with the exact selected change, without a sampler/provider
        replacement, later observation, accepted model or fabricated class result.
    """
    condition = condition.removeprefix("cli_")
    if condition not in CLOCK_ACCEPTANCE_CASES:
        return value
    before = _object(value["before"])
    if condition == "acceptance_capture_lower":
        value["acceptance_utc_lower_ns"] = str(int(str(value["acceptance_utc_lower_ns"])) + 1)
    if condition == "acceptance_capture_upper":
        value["acceptance_utc_upper_ns"] = str(int(str(value["acceptance_utc_upper_ns"])) - 1)
    if condition == "acceptance_capture_reversed":
        value["before"], value["after"] = value["after"], value["before"]
    if condition == "acceptance_capture_rate":
        value["ticks_per_second"] = {"numerator": "1", "denominator": "1"}
    if condition == "acceptance_capture_equivalent_rate":
        value["ticks_per_second"] = {"numerator": "2000000000", "denominator": "2"}
    if condition == "acceptance_capture_accuracy":
        value["before"] = {**before, "accuracy_radius_ns": "0"}
    if condition == "acceptance_capture_budget_lower":
        value["acceptance_utc_lower_ns"] = str(int(str(before["utc_epoch_ns"])) - 5_000_000_001)
    if condition == "acceptance_capture_budget_upper":
        value["acceptance_utc_upper_ns"] = str(int(str(before["utc_epoch_ns"])) + 5_000_000_001)
    if condition == "acceptance_capture_prior_to_validity":
        after = _object(value["after"])
        value["before"] = {**before, "accuracy_radius_ns": "3000000000"}
        value["after"] = {**after, "accuracy_radius_ns": "3000000000"}
        value["acceptance_utc_lower_ns"] = str(int(str(before["utc_epoch_ns"])) - 3_000_002_000)
        value["acceptance_utc_upper_ns"] = str(int(str(after["utc_epoch_ns"])) + 3_000_002_000)
        seconds, fraction = divmod(int(str(before["utc_epoch_ns"])) - 2_000_000_000, 1_000_000_000)
        start = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
        end = start.replace(
            year=start.year + 1, day=28 if start.month == 2 and start.day == 29 else start.day
        )
        value["valid_from"] = start.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"
        value["valid_until"] = end.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"
        assert int(str(value["acceptance_utc_lower_ns"])) < seconds * 1_000_000_000 + fraction
    if condition.startswith("acceptance_capture_raw_"):
        original = BlobRef.from_mapping(_object(before["clock_sample_raw_ref"]))
        raw = _object(json.loads((directory / original.digest[7:]).read_bytes()))
        if condition == "acceptance_capture_raw_utc":
            raw["utc_ns"] = str(int(str(raw["utc_ns"])) + 1)
        if condition == "acceptance_capture_raw_ticks":
            raw["raw_after"] = str(int(str(raw["raw_after"])) + 1)
        if condition == "acceptance_capture_raw_order":
            raw["raw_before"] = str(int(str(raw["raw_after"])) + 1)
        if condition == "acceptance_capture_raw_shape":
            raw["unexpected_member"] = False
        if condition == "acceptance_capture_raw_clock":
            raw["clock"] = "CLOCK_MONOTONIC"
        if condition == "acceptance_capture_raw_uncertainty":
            raw["physical_uncertainty"] = ""
        if condition == "acceptance_capture_raw_field_type":
            raw["utc_ns"] = 1
        replacement = (
            _native_source(b'{"clock":', directory, "application/json")
            if condition == "acceptance_capture_raw_json"
            else _stored(raw, directory)
        )
        value["before"] = {**before, "clock_sample_raw_ref": dict(replacement.to_mapping())}
    return value


def clock_acceptance_expected(
    condition: str, *, acceptance: BlobRef, policy: BlobRef, content: BlobRef, directory: Path
) -> tuple[str, dict[str, object]] | None:
    """Specify the exact original public diagnostic independently of production calculations.

    Parameters
    ----------
    condition : str
        Named original acceptance-capture source scenario.
    acceptance, policy, content : BlobRef
        Whole actual acceptance, independently selected policy and complete content identities.
    directory : Path
        Owned complete source population used only to locate the selected raw argument.

    Returns
    -------
    tuple or None
        Expected typed boundary and all five actual reason fields, or None for an
        unchanged existing scenario. Consistent annual sources retain the actual required
        ordinary signature; no waiver or final V2 admission is manufactured.
    """
    condition = condition.removeprefix("cli_")
    if condition not in CLOCK_ACCEPTANCE_CASES:
        return None
    expected: dict[str, object] = {
        "code": "policy_unavailable",
        "subject_digest": policy.digest,
        "claim_id": None,
        "pointer": "/required_evaluation_time_qualification/clock_qualification_ref",
        "detail": "The required evaluation-time qualification is unavailable.",
    }
    if condition in {
        "acceptance_capture_exact",
        "acceptance_capture_equivalent_rate",
        "acceptance_capture_prior_to_validity",
    }:
        return "refused", {
            "code": "signature_required",
            "subject_digest": content.digest,
            "claim_id": None,
            "pointer": None,
            "detail": "The required evidence signature is unavailable.",
        }
    fields = {
        "acceptance_capture_raw_shape": "",
        "acceptance_capture_raw_uncertainty": "/physical_uncertainty",
        "acceptance_capture_raw_field_type": "/utc_ns",
    }
    if condition in fields or condition == "acceptance_capture_raw_json":
        value = _object(json.loads((directory / acceptance.digest[7:]).read_bytes()))
        raw = _object(_object(value["before"])["clock_sample_raw_ref"])
        if condition == "acceptance_capture_raw_json":
            expected.update(
                code="invalid_json",
                subject_digest=raw["digest"],
                pointer=None,
                detail="Input is not valid strict JSON.",
            )
        else:
            expected.update(
                code="configuration_error",
                subject_digest=raw["digest"],
                pointer=fields[condition],
                detail="Invalid Clock method configuration.",
            )
            return "configuration", expected
    return "refused", expected
