# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole staged native access capture inputs

"""Preserve entire earlier access events across declared run, release and comparison stages."""

from copy import deepcopy
from pathlib import Path

from tests.domain.test_successor_provider_boundary import _stored

from evidence_manifest_toolkit import BlobRef

_ORIGINS = {
    "method": "access_method_ref",
    "qualification": "access_method_qualification_ref",
    "recorder": "recorder_process_identity_ref",
    "environment": "environment_ref",
    "boundary": "policy_and_input_boundary_ref",
}
_CASES = (
    "matching",
    "unchanged",
    "empty",
    "observed_processes",
    *(
        stage + "_" + fault
        for stage in ("release", "comparison")
        for fault in (
            "dropped",
            "rewritten",
            "event_process",
            "event_time",
            "prepended",
            "reordered",
            *_ORIGINS,
        )
    ),
)
NATIVE_ACCESS_PREFIX_CASES = tuple("reproduction_run_access_prefix_" + x for x in _CASES) + (
    "cli_reproduction_run_access_prefix_matching",
    "cli_reproduction_run_access_prefix_release_dropped",
    "cli_reproduction_run_access_prefix_release_rewritten",
    "cli_reproduction_run_access_prefix_comparison_rewritten",
    "protected_reproduction_run_access_prefix_matching",
    "protected_reproduction_run_access_prefix_comparison_recorder",
    "cli_protected_reproduction_run_access_prefix_release_rewritten",
)


def native_access_prefix_input(
    access: dict[str, object], *, subject: object, directory: Path, case: str
) -> tuple[tuple[BlobRef, BlobRef, BlobRef], tuple[BlobRef, str] | None]:
    """Build complete growing prefixes and one exact independently authored contradiction.

    Parameters
    ----------
    access : dict
        Entire earlier unqualified access record with its independently selected request.
    subject : object
        Complete earlier subject reference retained by every original event.
    directory : Path
        Owned real flat store used by the public Resolver.
    case : str
        Explicit access_prefix case selected by this test-owned native run builder.

    Returns
    -------
    tuple
        Entire run/release/comparison access references and exact conflicting field,
        or no conflict. No capture, process, time or native method is qualified.
    """
    name = case.removeprefix("access_prefix_")
    declaration = access["access_method_ref"]
    alternate = dict(
        _stored({"limitation": "Different unqualified capture source."}, directory).to_mapping()
    )
    events: list[dict[str, object]] = [
        {
            "sequence": str(123456789012345678901234567890 + index),
            "event_kind": kind,
            "subject_ref": subject,
            "before_time_source_ref": declaration,
            "after_time_source_ref": declaration,
            "native_operation_source_ref": declaration,
            "native_outcome_source_ref": declaration,
            "observed_process_identity_ref": alternate
            if name == "observed_processes" and index >= 3
            else declaration,
        }
        for index, kind in enumerate(
            (
                "input_open",
                "independent_output_publish",
                "producer_output_release",
                "comparison_start",
                "comparison_finish",
            )
        )
    ]
    populations = [events[:2], events[:3], events]
    if name == "unchanged":
        populations = [events[:2], events[:2], events[:2]]
    if name == "empty":
        populations = [[], events[:3], events]
    records = [{**access, "events": deepcopy(rows)} for rows in populations]
    selected = 1 if name.startswith("release_") else 2
    fault = name.removeprefix("release_").removeprefix("comparison_")
    rows = deepcopy(populations[selected])
    field: str | None = None
    if fault == "dropped":
        rows = rows[1:]
        field = "events"
    elif fault == "rewritten":
        rows[0]["native_outcome_source_ref"] = alternate
        field = "events"
    elif fault == "event_process":
        rows[0]["observed_process_identity_ref"] = alternate
        field = "events"
    elif fault == "event_time":
        rows[0]["before_time_source_ref"] = alternate
        field = "events"
    elif fault == "prepended":
        rows = [{**rows[0], "sequence": "0"}, *rows]
        field = "events"
    elif fault == "reordered":
        rows[:2] = [
            {**rows[1], "sequence": rows[0]["sequence"]},
            {**rows[0], "sequence": rows[1]["sequence"]},
        ]
        field = "events"
    elif fault in _ORIGINS:
        field = _ORIGINS[fault]
        records[selected][field] = alternate
    records[selected]["events"] = rows
    references = tuple(_stored(record, directory) for record in records)
    run, release, comparison = references
    return (run, release, comparison), (references[selected], field) if field else None
