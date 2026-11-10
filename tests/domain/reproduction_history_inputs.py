# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole causal parent history public inputs

"""Preserve complete source histories and independently specified public diagnostics."""

import base64
import json
from copy import deepcopy
from pathlib import Path

from tests.domain.reproduction_history_build import HistorySources
from tests.domain.reproduction_record_inputs import ReproductionOutcome
from tests.domain.test_verification_report_sources import _array, _bytes, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, canonicalize_json, reference_bytes

PARENT_HISTORY_CASES = tuple(
    "reproduction_history_" + name
    for name in (
        "two_claims",
        "renewal",
        "two_claims_no_schema",
        "renewal_no_schema",
        "other_claim",
        "wrong_subject",
        "replace_inherited",
        "old_origin",
        "old_body_claim",
        "old_package_subject",
        "old_manifest_schema",
        "old_subject_descendant_missing",
        "old_validation_schema",
        "old_validation_identity",
        "old_validation_descendant_missing",
        "depth_no_schema",
        "validation_depth_no_schema",
        "validation_within_depth_no_schema",
    )
) + ("cli_reproduction_history_two_claims_no_schema", "cli_reproduction_history_other_claim")


def parent_history_input(
    condition: str, inputs: dict[str, object], directory: Path, *, limits: Limits
) -> tuple[dict[str, object], ReproductionOutcome]:
    """Build successive complete native parents for the real public API or module CLI.

    Parameters
    ----------
    condition : str
        Whole chain or a named original source/transition contradiction.
    inputs : dict
        Complete original native inputs after unqualified base-record construction.
    directory : Path
        Actual owned immutable source store before first S0.
    limits : Limits
        Original operation bounds, never a larger history allowance.

    Returns
    -------
    tuple
        Whole final inputs and independently specified complete diagnostic. Structural
        matching reaches the remaining V2 guard, never independent execution acceptance.
    """
    case = condition.removeprefix("cli_").removeprefix("reproduction_history_")
    hidden = case.startswith("old_") or case == "depth_no_schema" or case.endswith("no_schema")
    store = HistorySources(directory, limits, without_metadata=hidden)
    missing = (
        store.store({"unavailable_historical_descendant": case})
        if case in {"old_subject_descendant_missing", "old_validation_descendant_missing"}
        else None
    )
    parent = _object(json.loads(_bytes(inputs["content_json"])))
    declared = _object(_array(parent["claims"])[1])
    original_record = store.read(store.child(_object(declared["validation"]), "record_ref"))
    original_body = store.read(store.child(original_record, "body_ref"))
    base = store.read(store.child(original_body, "subject_ref"))
    claims = [_object(item) for item in _array(base["claims"])]
    for claim in claims:
        claim.update(origin="executed", evidence_maturity="executed")
    if case == "old_origin":
        claims[1].update(origin="architecture_only", evidence_maturity="architecture_only")
    base["claims"] = claims
    current = base
    current_ref = store.store(base)
    initial_ref = current_ref
    runner = _text(store.read(store.child(original_body, "runner_binding_ref"))["principal_id"])
    renewal = case.startswith("renewal") or case.startswith("old_") or case == "depth_no_schema"
    steps = 12 if case == "depth_no_schema" else 2
    if case in {"validation_depth_no_schema", "validation_within_depth_no_schema"}:
        renewal, steps = True, 9 if case == "validation_depth_no_schema" else 7
    parent_refs: list[BlobRef] = []
    body_refs: list[BlobRef] = []
    record_refs: list[BlobRef] = []
    error_source: BlobRef | None = None
    error_field = "/claims"
    error_claim: str | None = None
    error_code = "invalid_claim"
    detail = "Independent validation parent does not reconstruct its whole earlier subject."
    for step in range(steps):
        index = 1 if renewal or step == 0 else 0
        selected = _object(_array(current["claims"])[index])
        body = deepcopy(original_body)
        body.update(subject_ref=dict(current_ref.to_mapping()), claim_id=selected["claim_id"])
        if step == 0 and case == "old_body_claim":
            body["claim_id"] = "different-historical-declared-claim"
        if step == 0 and case in {"old_manifest_schema", "old_subject_descendant_missing"}:
            malformed_base = deepcopy(base)
            if case == "old_manifest_schema":
                malformed_base["unexpected"] = False
            else:
                assert missing is not None
                malformed_base["environment_ref"] = dict(missing.to_mapping())
            current_ref = store.store(malformed_base)
            initial_ref = current_ref
            body["subject_ref"] = dict(current_ref.to_mapping())
        body_ref = store.store(body)
        body_refs.append(body_ref)
        record = deepcopy(original_record)
        record.update(
            body_ref=dict(body_ref.to_mapping()),
            subject_ref=dict(current_ref.to_mapping()),
            claim_id=selected["claim_id"],
        )
        if case in {"validation_depth_no_schema", "validation_within_depth_no_schema"}:
            validation = deepcopy(base)
            validation["producer"] = {**_object(validation["producer"]), "principal": runner}
            validation["source_ref"] = dict(body_ref.to_mapping())
            record["validation_C0_statement_ref"] = dict(store.store(validation).to_mapping())
        if step == 0 and case == "old_package_subject":
            other = deepcopy(base)
            other["source_ref"] = other["payload_ref"]
            record["subject_ref"] = dict(store.store(other).to_mapping())
        if step == 0 and case in {
            "old_validation_schema",
            "old_validation_identity",
            "old_validation_descendant_missing",
        }:
            validation = deepcopy(base)
            validation["source_ref"] = dict(body_ref.to_mapping())
            if case == "old_validation_schema":
                validation["unexpected"] = False
            elif case == "old_validation_descendant_missing":
                assert missing is not None
                validation["environment_ref"] = dict(missing.to_mapping())
            else:
                first = _object(_array(validation["claims"])[0])
                principal = _object(validation["producer"])["principal"]
                first.update(
                    evidence_maturity="validated",
                    verdict="agree",
                    validation={
                        "status": "independently_reproduced",
                        "record_ref": _array(body["raw_output_and_diagnostics_refs"])[0],
                        "runner_id": principal,
                        "independent_of_producer": True,
                    },
                )
                validation["claims"] = [first, _array(validation["claims"])[1]]
            validation_ref = store.store(validation)
            record["validation_C0_statement_ref"] = dict(validation_ref.to_mapping())
            error_source = validation_ref
        record_ref = store.store(record)
        record_refs.append(record_ref)
        current = store.parent(
            current, index, record_ref, runner, change_origin=case == "old_origin" and step == 0
        )
        current_ref = store.store(current)
        parent_refs.append(current_ref)
    final_claims = [_object(item) for item in _array(current["claims"])]
    if case == "other_claim":
        final_claims[1]["statement"] = "Changed inherited claim statement."
    if case == "wrong_subject":
        last_record = store.read(record_refs[-1])
        last_body = store.read(body_refs[-1])
        last_body["subject_ref"] = dict(initial_ref.to_mapping())
        last_record.update(
            body_ref=dict(store.store(last_body).to_mapping()),
            subject_ref=dict(initial_ref.to_mapping()),
        )
        changed_validation = _object(final_claims[0]["validation"])
        changed_validation["record_ref"] = dict(store.store(last_record).to_mapping())
        final_claims[0]["validation"] = changed_validation
    if case == "replace_inherited":
        old = store.read(record_refs[0])
        changed_body = store.read(body_refs[0])
        changed_body["raw_output_and_diagnostics_refs"] = list(
            reversed(_array(changed_body["raw_output_and_diagnostics_refs"]))
        ) + [_object(changed_body["sealed_independent_output_ref"])]
        old["body_ref"] = dict(store.store(changed_body).to_mapping())
        changed_validation = _object(final_claims[1]["validation"])
        changed_validation["record_ref"] = dict(store.store(old).to_mapping())
        final_claims[1]["validation"] = changed_validation
    current["claims"] = final_claims
    raw = canonicalize_json(json.dumps(current).encode(), limits=limits)
    inputs["content_json"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    if missing is not None:
        (directory / missing.digest[7:]).unlink()
        return inputs, (
            "unavailable",
            {
                "code": "reference_unavailable",
                "subject_digest": None,
                "claim_id": None,
                "pointer": None,
                "detail": "Required reference unavailable.",
            },
            missing,
        )
    root_ref = reference_bytes(
        raw,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id="evidence_manifest_toolkit.manifest.v1",
        limits=limits,
    )
    if case == "validation_depth_no_schema":
        from tests.domain.reproduction_history_depth_inputs import overdepth_digests

        return inputs, (
            "refused",
            {
                "code": "limit_exceeded",
                "subject_digest": overdepth_digests(root_ref, directory, inputs, limits=limits),
                "claim_id": None,
                "pointer": None,
                "detail": "Reference graph depth bound exceeded.",
            },
            None,
        )
    if case in {
        "two_claims",
        "renewal",
        "two_claims_no_schema",
        "renewal_no_schema",
        "validation_within_depth_no_schema",
    }:
        return inputs, (
            "configuration",
            {
                "code": "configuration_error",
                "subject_digest": None,
                "claim_id": None,
                "pointer": "/trust",
                "detail": "Invalid local configuration.",
            },
            None,
        )
    if case == "old_origin":
        error_source = parent_refs[0]
    if case in {"old_body_claim", "old_package_subject"}:
        error_source = body_refs[0] if case == "old_body_claim" else record_refs[0]
        error_field = "/claim_id" if case == "old_body_claim" else "/subject_ref"
        error_claim = _text(_object(_array(base["claims"])[1])["claim_id"])
        detail = "Independent validation sources conflict."
    if case in {"old_manifest_schema", "old_validation_schema"}:
        error_source = initial_ref if case == "old_manifest_schema" else error_source
        error_code, error_field = "invalid_schema", ""
        detail = "Input violates its selected schema."
    if case == "old_validation_identity":
        error_claim = _text(_object(_array(base["claims"])[0])["claim_id"])
        error_field = "/claims/0/validation/runner_id"
        detail = "Producer cannot independently reproduce its own claim."
    if case == "depth_no_schema":
        error_source, error_code, error_field = parent_refs[0], "limit_exceeded", ""
        detail = "Reference graph depth bound exceeded."
    return inputs, (
        "refused",
        {
            "code": error_code,
            "subject_digest": (error_source or root_ref).digest,
            "claim_id": error_claim,
            "pointer": None if case == "depth_no_schema" else error_field,
            "detail": detail,
        },
        None,
    )
