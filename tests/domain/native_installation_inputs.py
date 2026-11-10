# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — independent whole installed native source fault expectations

"""Keep full public input/oracle selection separate from actual isolated filesystem mutations."""

import json
from pathlib import Path
from typing import TYPE_CHECKING

from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef

if TYPE_CHECKING:
    from tests.domain.reproduction_record_inputs import ReproductionOutcome

NATIVE_INSTALLATION_CASES = tuple(
    "native_binding_installation_" + case
    for case in (
        "descriptor_missing",
        "descriptor_changed",
        "descriptor_truncated",
        "selected_invalid_json",
        "selected_invalid_utf8",
        "selected_extra",
        "selected_version",
        "selected_omitted",
        "selected_added",
        "selected_reordered",
        "selected_pin_length",
        "selected_pin_hash",
        "selected_pin_oversized",
        "selected_depth_limit",
        "selected_remaining_bound",
        "source_missing",
        "source_changed",
        "source_truncated",
        "source_unreadable",
        "listing_unreadable",
        "unexpected_directory",
        "extension_layout",
        "schema_python",
        "ignored_noncode",
        "blob_bound",
    )
)


def native_installation_input(
    condition: str, rules: dict[str, object], directory: Path
) -> "ReproductionOutcome":
    """Specify the entire independent original diagnostic before public execution.

    Parameters
    ----------
    condition : str
        Actual isolated installed-file fault or explicitly allowed noncode population.
    rules : dict
        Whole original independent method selections, including the frozen descriptor input.
    directory : Path
        Owned real source population used by the unchanged public Resolver.

    Returns
    -------
    tuple
        Full independently authored error and absent missing-reference argument.
        Physical missing installation resources are configuration faults, not missing caller refs.
    """
    case = condition.removeprefix("native_binding_installation_")
    identity_ref = BlobRef.from_mapping(_object(rules["identity_rule_ref"]))
    identity = _object(json.loads((directory / identity_ref.digest[7:]).read_bytes()))
    launcher_ref = BlobRef.from_mapping(_object(identity["launcher_or_observer_procedure_ref"]))
    launcher = _object(json.loads((directory / launcher_ref.digest[7:]).read_bytes()))
    descriptor_ref = BlobRef.from_mapping(_object(launcher["implementation_ref"]))
    reason: dict[str, object] = {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": "/implementation_ref",
        "detail": "Invalid local configuration.",
    }
    if case in {"descriptor_changed", "descriptor_truncated"}:
        reason.update(
            code="policy_unavailable",
            subject_digest=launcher_ref.digest,
            detail="Native method implementation sources conflict.",
        )
        return "refused", reason, None
    if case == "selected_version":
        reason["pointer"] = "/implementation_ref/method_version"
    if case == "ignored_noncode":
        reason["pointer"] = "/trust"
    if case in {"blob_bound", "selected_pin_oversized", "selected_remaining_bound"}:
        value = _object(json.loads((directory / descriptor_ref.digest[7:]).read_bytes()))
        population = value["implementation_files"]
        assert isinstance(population, list)
        index = (
            0
            if case in {"selected_pin_oversized", "selected_remaining_bound"}
            else next(
                i
                for i, row in enumerate(population)
                if _object(row)["filename"] == "_qpu_registry_bindings.json"
            )
        )
        reason.update(
            code="limit_exceeded",
            subject_digest=descriptor_ref.digest,
            pointer="/implementation_files/" + str(index),
            detail="Native installation source bound exceeded.",
        )
        return "refused", reason, None
    if case == "selected_depth_limit":
        reason.update(
            code="limit_exceeded", subject_digest=None, pointer=None, detail="JSON input refused."
        )
        return "refused", reason, None
    return "configuration", reason, None
