# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — real native method binding source inputs

"""Materialise real native method source faults without asserting method qualification."""

import hashlib
import json
from pathlib import Path

from tests.domain.native_installation_inputs import (
    NATIVE_INSTALLATION_CASES,
    native_installation_input,
)
from tests.domain.native_method_inputs import NATIVE_METHOD_CASES, native_method_input
from tests.domain.reproduction_record_inputs import ReproductionOutcome
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef

NATIVE_BINDING_CASES = NATIVE_METHOD_CASES + (
    "native_binding_matching",
    "software_receipt_native_binding_matching",
    "protected_ordinary_native_binding_matching",
    "native_binding_observer",
    "native_binding_launcher_extra",
    "native_binding_possession_extra",
    "native_binding_execution_extra",
    "native_binding_comparison_extra",
    "native_binding_possession_version",
    "native_binding_primitive",
    "native_binding_invalid_json",
    "native_binding_descendant_missing",
    "native_binding_descendant_metadata",
    "native_binding_ref_lexeme",
    "native_binding_resource_missing",
    "native_binding_resource_changed",
    "native_binding_resource_truncated",
    "native_binding_remaining_total",
    "native_binding_launcher_missing",
    "native_binding_possession_missing",
    "native_binding_execution_missing",
    "native_binding_comparison_missing",
    "cli_native_binding_launcher_missing",
    "cli_native_binding_possession_missing",
    "cli_native_binding_execution_missing",
    "cli_native_binding_comparison_missing",
    "cli_native_binding_matching",
    "cli_native_binding_comparison_extra",
    "cli_native_binding_descendant_missing",
)


def native_binding_input(
    condition: str, rules: dict[str, object], directory: Path
) -> ReproductionOutcome | None:
    """Change one entire selected binding or source under the original full public workflow.

    Parameters
    ----------
    condition : str
        Named whole matching declaration, actual source fault or module CLI counterpart.
    rules : dict
        Entire independent identity/validation selections, updated before Clock freeze.
    directory : Path
        Real owned source store; no resolver, source bytes or native method is mocked.

    Returns
    -------
    tuple or None
        Independent complete original diagnostic and missing full Ref, or None outside
        this owning surface. Matching declarations remain explicitly unqualified.
    """
    if condition in NATIVE_INSTALLATION_CASES:
        return native_installation_input(condition, rules, directory)
    if condition in NATIVE_METHOD_CASES:
        return native_method_input(condition, rules, directory)
    if condition not in NATIVE_BINDING_CASES:
        return None
    case = (
        condition.removeprefix("cli_")
        .removeprefix("software_receipt_")
        .removeprefix("protected_ordinary_")
        .removeprefix("native_binding_")
    )
    reason: dict[str, object] = {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": "/trust",
        "detail": "Invalid local configuration.",
    }
    if case in {
        "matching",
        "resource_missing",
        "resource_changed",
        "resource_truncated",
        "remaining_total",
    }:
        if case.startswith("resource_"):
            reason["pointer"] = "/launcher_or_observer_procedure_ref"
        if case != "remaining_total":
            return "configuration", reason, None
        reason.update(
            code="limit_exceeded",
            subject_digest=BlobRef.from_mapping(_object(rules["identity_rule_ref"])).digest,
            pointer="/launcher_or_observer_procedure_ref",
            detail="Reference acquisition bound exceeded.",
        )
        return "refused", reason, None
    role = (
        "possession"
        if case.startswith("possession_")
        else "execution"
        if case.startswith("execution_")
        else "comparison"
        if case.startswith(("comparison_", "descendant_", "ref_"))
        else "launcher"
    )
    rule_field = (
        "identity_rule_ref" if role in {"launcher", "possession"} else "validation_rule_ref"
    )
    selected_field = {
        "launcher": "launcher_or_observer_procedure_ref",
        "possession": "actual_key_possession_rule_ref",
        "execution": "run_and_seal_before_comparison_procedure_ref",
        "comparison": "comparison_rule_ref",
    }[role]
    rule_ref = BlobRef.from_mapping(_object(rules[rule_field]))
    rule = _object(json.loads((directory / rule_ref.digest[7:]).read_bytes()))
    binding_ref = BlobRef.from_mapping(_object(rule[selected_field]))
    binding = _object(json.loads((directory / binding_ref.digest[7:]).read_bytes()))
    missing: BlobRef | None = None
    pointer = ""
    detail = "Input violates its selected schema."
    if case == "observer":
        binding = {
            key: value
            for key, value in binding.items()
            if key not in {"record_contract_ref", "vendor_source", "key_source"}
        }
        declaration = binding["semantic_law_ref"]
        binding.update(
            capture_contract_ref=declaration,
            observer_authority_policy_ref=declaration,
            endpoint_rule_ref=declaration,
        )
    elif case.endswith("_extra"):
        binding["unexpected"] = True
    elif case == "possession_version":
        binding["method_version"] = "2"
        pointer = "/method_version"
    elif case == "descendant_metadata":
        binding["whole_comparison_parameters_ref"] = {
            **_object(binding["semantic_law_ref"]),
            "media_type": "text/plain",
        }
        pointer = "/whole_comparison_parameters_ref"
        detail = "Reference metadata conflicts."
    elif case == "ref_lexeme":
        binding["whole_comparison_parameters_ref"] = {
            **_object(binding["semantic_law_ref"]),
            "byte_length": "01",
        }
        pointer = "/whole_comparison_parameters_ref/byte_length"
    elif case == "descendant_missing":
        raw = b"Actually missing native comparison parameter source; never a comparison result."
        missing = BlobRef(
            "sha256:" + hashlib.sha256(raw).hexdigest(), str(len(raw)), "text/plain", "raw_bytes"
        )
        binding["whole_comparison_parameters_ref"] = dict(missing.to_mapping())
    raw = (
        b"[ ]"
        if case == "primitive"
        else b"{"
        if case == "invalid_json"
        else json.dumps(binding).encode()
    )
    binding_ref = BlobRef(
        "sha256:" + hashlib.sha256(raw).hexdigest(), str(len(raw)), "application/json", "raw_bytes"
    )
    root_missing = case.endswith("_missing") and case != "descendant_missing"
    if root_missing:
        raw = b"\n" + raw
        binding_ref = BlobRef(
            "sha256:" + hashlib.sha256(raw).hexdigest(),
            str(len(raw)),
            "application/json",
            "raw_bytes",
        )
        missing = binding_ref
        assert not (directory / binding_ref.digest[7:]).exists()
    else:
        (directory / binding_ref.digest[7:]).write_bytes(raw)
    rule[selected_field] = dict(binding_ref.to_mapping())
    rules[rule_field] = dict(_stored(rule, directory).to_mapping())
    if rule_field == "identity_rule_ref":
        validation_ref = BlobRef.from_mapping(_object(rules["validation_rule_ref"]))
        validation = _object(json.loads((directory / validation_ref.digest[7:]).read_bytes()))
        validation["independent_identity_policy_ref"] = rules["identity_rule_ref"]
        rules["validation_rule_ref"] = dict(_stored(validation, directory).to_mapping())
    if case == "observer":
        return "configuration", reason, None
    if missing is not None:
        reason.update(
            code="reference_unavailable",
            subject_digest=None,
            pointer=None,
            detail="Required reference unavailable.",
        )
        return "unavailable", reason, missing
    if case == "primitive":
        detail = "Complete context object is required."
    if case == "invalid_json":
        detail = "Input is not valid strict JSON."
    reason.update(
        code="invalid_json" if case == "invalid_json" else "invalid_schema",
        subject_digest=binding_ref.digest,
        pointer=pointer,
        detail=detail,
    )
    return "refused", reason, None
