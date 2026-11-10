# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — independent whole comparison and execution policy fixtures

"""Bind declared record inputs to independently frozen full method references."""

import json
from pathlib import Path

from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef, Limits, reference_bytes

METHOD_POLICY_BASE_CASES = (
    "reproduction_comparison_rule_base",
    "reproduction_comparison_rule_alternate",
    "reproduction_comparison_rule_jcs",
    "reproduction_execution_nonuse_rule",
    "reproduction_validation_nonuse_rule",
)
METHOD_POLICY_CASES = METHOD_POLICY_BASE_CASES + tuple(
    "cli_" + case for case in METHOD_POLICY_BASE_CASES
)
METHOD_POLICY_PUBLIC_CASES = (
    METHOD_POLICY_CASES
    + tuple("protected_" + case for case in METHOD_POLICY_BASE_CASES)
    + tuple("cli_protected_" + case for case in METHOD_POLICY_BASE_CASES)
)


def comparison_policy_input(
    condition: str, rules: dict[str, object], base: BlobRef, directory: Path, *, limits: Limits
) -> dict[str, str]:
    """Retain the actual full selected rule or one independently authored contradiction.

    Parameters
    ----------
    condition : str
        Original record condition, with no received method or executable dispatch.
    rules : dict
        Whole independent selected method inputs, mutable only before context capture.
    base : BlobRef
        Entire earlier artifact policy; it is deliberately NOT a comparison method.
    directory : Path
        Actual owned whole source population, including each independently selected rule.
    limits : Limits
        Original complete public bounds, also used for the explicit JCS alias control.

    Returns
    -------
    dict
        Whole original comparison reference with every basis/length/media/schema assertion.
        A matching reference grants no actual comparison or qualified non-use.
    """
    validation_ref = BlobRef.from_mapping(_object(rules["validation_rule_ref"]))
    validation = _object(json.loads((directory / validation_ref.digest[7:]).read_bytes()))
    if condition in ("reproduction_execution_nonuse_rule", "reproduction_validation_nonuse_rule"):
        if condition == "reproduction_execution_nonuse_rule":
            execution_ref = BlobRef.from_mapping(
                _object(validation["run_and_seal_before_comparison_procedure_ref"])
            )
            execution = _object(json.loads((directory / execution_ref.digest[7:]).read_bytes()))
            execution["permitted_nonuse_classes"] = ["enforced_isolation"]
            validation["run_and_seal_before_comparison_procedure_ref"] = dict(
                _stored(execution, directory).to_mapping()
            )
        else:
            validation["required_nonuse_classes"] = ["enforced_isolation"]
            rules["allowed_nonuse_classes"] = ["procedural_nonuse", "enforced_isolation"]
        rules["validation_rule_ref"] = dict(_stored(validation, directory).to_mapping())
    selected = BlobRef.from_mapping(_object(validation["comparison_rule_ref"]))
    raw = (directory / selected.digest[7:]).read_bytes()
    if condition == "reproduction_comparison_rule_base":
        return dict(base.to_mapping())
    if condition == "reproduction_comparison_rule_alternate":
        alternate = _object(json.loads(raw))
        alternate["outcome_mapping_ref"] = alternate["implementation_environment_ref"]
        return dict(_stored(alternate, directory).to_mapping())
    if condition == "reproduction_comparison_rule_jcs":
        alias = reference_bytes(
            raw,
            media_type=selected.media_type,
            digest_basis="jcs_content",
            schema_id=selected.schema_id,
            limits=limits,
        )
        (directory / alias.digest[7:]).write_bytes(raw)
        return dict(alias.to_mapping())
    return dict(selected.to_mapping())
