# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete ordinary signature obligation input cases

"""Prepare explicit unqualified scope declarations for genuine public verification."""

import base64
import json
import os
from pathlib import Path

from tests.domain.test_cli_evidence_sources import _transport
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _array, _bytes, _object, _text

from evidence_manifest_toolkit import BlobRef

SIGNATURE_OBLIGATION_CASES = (
    "obligation_partial_claims",
    "obligation_empty_claims",
    "obligation_empty_purposes",
    "obligation_missing_required_claim",
    "obligation_missing_record",
    "obligation_record_scope",
    "obligation_record_no_evidence",
    "obligation_control_target",
    "software_receipt_obligation_partial",
    "software_receipt_obligation_purpose",
    "software_receipt_obligation_global_purpose",
    "software_receipt_obligation_intrinsic",
    "software_receipt_obligation_record",
    "software_receipt_obligation_unknown_required",
    "cli_obligation_partial_claims",
    "cli_obligation_missing_record",
    "protected_unprotected_scope",
)
_RECORD_CASES = {
    "obligation_missing_record",
    "obligation_record_scope",
    "obligation_record_no_evidence",
    "software_receipt_obligation_intrinsic",
    "software_receipt_obligation_record",
}


def obligation_inputs(
    condition: str, inputs: dict[str, object], directory: Path
) -> dict[str, object]:
    """Retain entire sources while changing the actual selected obligation or declaration.

    Parameters
    ----------
    condition : str
        Named full-scope fault, or an unchanged previous source condition.
    inputs : dict
        Whole original input inventory; its on-disk source and every object stay intact.
    directory : Path
        Actual owned input store for a separately declared unqualified record.

    Returns
    -------
    dict
        Full source with deliberate scope/declaration controls. Claimed reproduction is
        an explicitly unverified negative input, never an actual accepted run or verdict.
    """
    condition = condition.removeprefix("cli_")
    if condition not in SIGNATURE_OBLIGATION_CASES:
        return inputs
    policy = _object(inputs["policy"])
    raw = _bytes(inputs["content_json"])
    document = _object(json.loads(raw))
    if condition in _RECORD_CASES:
        claims = [_object(item) for item in _array(document["claims"])]
        record = _stored(
            {"declared_validation_input": condition, "pid": str(os.getpid()), "qualified": False},
            directory,
        )
        claims[1].update(
            origin="executed",
            evidence_maturity="validated",
            validation={
                "status": "independently_reproduced",
                "record_ref": dict(record.to_mapping()),
                "runner_id": "deliberately-unverified-other-runner",
                "independent_of_producer": True,
            },
        )
        document["claims"] = claims
        raw = _transport(document)
    if condition in {
        "obligation_missing_required_claim",
        "software_receipt_obligation_unknown_required",
    }:
        policy["required_claim_ids"] = ["deliberately-missing-required-claim"]
    if condition == "software_receipt_obligation_intrinsic":
        policy["required_claim_ids"] = [_text(_object(_array(document["claims"])[0])["claim_id"])]
    if condition == "software_receipt_obligation_global_purpose":
        policy["required_claim_ids"] = []
    if condition == "obligation_record_no_evidence":
        policy["required_purposes"] = ["human_review"]
    if condition == "obligation_control_target":
        objects = Path(__file__).parent / "fixtures/evidence-command-sources/objects"
        for item in _object(inputs["resolver_input_population"]).values():
            candidate = (objects / _text(_object(item)["sha256"])).read_bytes()
            try:
                value = json.loads(candidate)
            except (json.JSONDecodeError, UnicodeError):
                continue
            if isinstance(value, dict) and value.get("schema_id") == (
                "evidence_manifest_toolkit.group_certificate.v1"
            ):
                raw = candidate
                inputs["schema_id"] = value["schema_id"]
                break
        else:
            raise AssertionError("The entire original control source must exist.")
        policy["required_claim_ids"] = []
    inputs["policy"] = policy
    inputs["content_json"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return inputs


def obligation_rule(condition: str, value: dict[str, object]) -> dict[str, object]:
    """Select full or deliberately incomplete unsigned scope without changing old cases.

    Parameters
    ----------
    condition : str
        Actual named unsigned scope control after CLI prefix removal.
    value : dict
        Whole rule including actual complete content and independently selected policy.

    Returns
    -------
    dict
        Entire original rule with only its explicit selected exception changed.
    """
    condition = condition.removeprefix("cli_")
    if not condition.startswith("obligation_") or condition == "obligation_missing_required_claim":
        return value
    exception = _object(value["unsigned_exception"])
    if condition == "obligation_partial_claims":
        exception["claim_ids"] = _array(exception["claim_ids"])[:1]
    if condition == "obligation_empty_claims":
        exception["claim_ids"] = []
    if condition == "obligation_empty_purposes":
        exception["purposes"] = []
    if condition == "obligation_missing_record":
        exception["validation_record_refs"] = []
    value["unsigned_exception"] = exception
    return value


def obligation_expected(
    condition: str, *, content: BlobRef, inputs: dict[str, object]
) -> tuple[str, dict[str, object]] | None:
    """Specify actual public missing-scope diagnostics without calling product helpers.

    Parameters
    ----------
    condition : str
        Actual complete scope input or previous source-consistent case.
    content : BlobRef
        Full actual canonical subject after selected input changes.
    inputs : dict
        Complete declared subject, preserving every field and record reference.

    Returns
    -------
    tuple or None
        Exact expected exception kind and all five independent reason fields, or None
        when an earlier existing source fault retains its unchanged original outcome.
    """
    condition = condition.removeprefix("cli_")
    old_missing = {
        "matching",
        "software",
        "software_historical",
        "sig_base_jcs",
        "sig_provenance_jcs",
        "sig_exception_empty",
        "cm_provenance_known",
    }
    if condition not in SIGNATURE_OBLIGATION_CASES and condition not in old_missing:
        return None
    if condition == "obligation_record_scope":
        document = _object(json.loads(_bytes(inputs["content_json"])))
        claim = _object(_array(document["claims"])[1])
        reference = _object(_object(claim["validation"])["record_ref"])
        return "refused", {
            "code": "invalid_schema",
            "subject_digest": reference["digest"],
            "claim_id": None,
            "pointer": "",
            "detail": "Input violates its selected schema.",
        }
    if condition == "protected_unprotected_scope":
        return "configuration", {
            "code": "configuration_error",
            "subject_digest": None,
            "claim_id": None,
            "pointer": "/trust",
            "detail": "Invalid local configuration.",
        }
    expected: dict[str, object] = {
        "code": "signature_required",
        "subject_digest": content.digest,
        "claim_id": None,
        "pointer": None,
        "detail": "The required evidence signature is unavailable.",
    }
    if condition in {
        "obligation_missing_required_claim",
        "software_receipt_obligation_unknown_required",
    }:
        expected.update(
            code="scope_missing",
            claim_id="deliberately-missing-required-claim",
            pointer="/claims",
            detail="Required claim scope does not resolve in the complete content.",
        )
    if condition.startswith("software_receipt_obligation_"):
        claims = [
            _object(item)
            for item in _array(_object(json.loads(_bytes(inputs["content_json"])))["claims"])
        ]
        if condition in {
            "software_receipt_obligation_partial",
            "software_receipt_obligation_purpose",
        }:
            expected.update(
                code="scope_missing",
                claim_id=claims[1 if condition.endswith("partial") else 0]["claim_id"],
                pointer="/claims",
                detail="Required signed claim and purpose scope is unavailable.",
            )
        if condition == "software_receipt_obligation_global_purpose":
            expected.update(code="scope_missing", detail="Required signed purpose is unavailable.")
        if condition == "software_receipt_obligation_intrinsic":
            expected.update(claim_id=claims[1]["claim_id"], pointer="/claims")
    if condition in {
        "obligation_missing_record",
        "obligation_record_no_evidence",
        "software_receipt_obligation_record",
    }:
        document = _object(json.loads(_bytes(inputs["content_json"])))
        claim = _object(_array(document["claims"])[1])
        record = _object(_object(claim["validation"])["record_ref"])
        expected.update(
            subject_digest=record["digest"],
            claim_id=claim["claim_id"],
            detail="The required validation record signature is unavailable.",
        )
    return "input", expected
