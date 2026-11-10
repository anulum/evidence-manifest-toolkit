# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole native validation adversarial public inputs

"""Change actual complete sources and signatures before real public verification."""

import base64
import json
from pathlib import Path

from Crypto.Signature import eddsa
from tests.domain.reproduction_receipt_source_faults import (
    RECEIPT_SOURCE_CASES,
    native_receipt_source_fault,
)
from tests.domain.reproduction_record_inputs import ReproductionOutcome
from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _array, _bytes, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, canonicalize_json

NATIVE_REPRODUCTION_CASES = tuple(
    "protected_reproduction_native_" + name
    for name in (
        "matching",
        "bad_signature",
        "wrong_message",
        "digest",
        "length",
        "unknown_claim",
        "partial_claim_scope",
        "missing_key",
        "short_key",
        "certificate_key",
        "certificate_id",
        "certificate_schema",
        "body_citation",
        "content_schema",
        "descendant_missing",
        "same_key_data",
        "second_receipt_bad",
        "multiple_receipts",
        *RECEIPT_SOURCE_CASES,
    )
) + (
    "cli_protected_reproduction_native_bad_signature",
    "cli_protected_reproduction_native_matching",
)


def native_reproduction_fault(
    condition: str, inputs: dict[str, object], directory: Path, *, limits: Limits
) -> tuple[dict[str, object], ReproductionOutcome]:
    """Retain all original parent fields and mutate one whole native validation source.

    Parameters
    ----------
    condition : str
        Actual named source/key/receipt contradiction or matching mathematical input.
    inputs : dict
        Entire earlier original fixture with its full unqualified reproduction package.
    directory : Path
        Actual complete owned source store before first S0, never a mocked resolver.
    limits : Limits
        Original full public invocation bounds.

    Returns
    -------
    tuple
        Entire final parent and independently specified original public diagnostic.
        Mathematical matching still reaches the remaining V2 guard, not run admission.
    """
    case = condition.removeprefix("cli_").removeprefix("protected_reproduction_native_")

    def read(reference: BlobRef) -> dict[str, object]:
        """Read the actual entire content-addressed source before a deliberate change."""
        return _object(json.loads((directory / reference.digest[7:]).read_bytes()))

    def child(value: dict[str, object], field: str) -> BlobRef:
        """Retain the complete explicitly selected reference argument."""
        return BlobRef.from_mapping(_object(value[field]))

    def native(value: dict[str, object], *, schema: bool = True) -> BlobRef:
        """Store one whole source with its original optional schema assertion."""
        return _stored(value, directory, schema_id=_text(value["schema_id"]) if schema else None)

    parent = _object(json.loads(_bytes(inputs["content_json"])))
    claims = [_object(item) for item in _array(parent["claims"])]
    selected = claims[1]
    validation = _object(selected["validation"])
    record = read(child(validation, "record_ref"))
    body_ref = child(record, "body_ref")
    body = read(body_ref)
    runner_ref = child(body, "runner_binding_ref")
    runner = read(runner_ref)
    producer = read(child(body, "producer_binding_ref"))
    content_ref = child(record, "validation_C0_statement_ref")
    content = read(content_ref)
    receipt_ref = BlobRef.from_mapping(_object(_array(record["ordered_native_receipt_refs"])[0]))
    receipt = read(receipt_ref)
    statement = _object(receipt["statement"])
    expected_source: BlobRef | None = None
    expected_pointer = ""
    expected_code = "invalid_claim"
    expected_claim: str | None = _text(body["claim_id"])
    detail = "Independent validation sources conflict."
    missing: BlobRef | None = None
    source_expected: dict[str, object] | None = None
    if case in {"missing_key", "short_key", "same_key_data"}:
        if case == "missing_key":
            body["runner_actual_key_ref"] = None
        else:
            key_ref = (
                _native_source(b"x" * 31, directory, "application/octet-stream")
                if case == "short_key"
                else BlobRef.from_mapping(
                    {**_object(producer["declared_public_key_ref"]), "media_type": "text/plain"}
                )
            )
            runner["declared_public_key_ref"] = dict(key_ref.to_mapping())
            runner_ref = native(runner)
            body["runner_binding_ref"] = dict(runner_ref.to_mapping())
            body["runner_actual_key_ref"] = dict(key_ref.to_mapping())
        body_ref = native(body)
        record["body_ref"] = dict(body_ref.to_mapping())
        content["source_ref"] = dict(body_ref.to_mapping())
        content_ref = native(content)
        record["validation_C0_statement_ref"] = dict(content_ref.to_mapping())
        statement.update(
            content_digest=content_ref.digest, content_byte_length=content_ref.byte_length
        )
        key = eddsa.import_private_key(
            bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        )
        signature = eddsa.new(key, "rfc8032").sign(
            b"GOTM-EMT-AUTHORITY-V2\x00"
            + canonicalize_json(json.dumps(statement).encode(), limits=limits)
        )
        receipt.update(
            statement=statement, signature=base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        )
        record["ordered_native_receipt_refs"] = [dict(_stored(receipt, directory).to_mapping())]
        expected_source = runner_ref if case == "same_key_data" else body_ref
        expected_pointer = (
            "/declared_public_key_ref" if case == "same_key_data" else "/runner_actual_key_ref"
        )
        if case == "same_key_data":
            expected_source = body_ref
            expected_pointer = "/runner_actual_key_ref"
            expected_code, expected_claim = "invalid_schema", None
            detail = "Reference metadata conflicts."
    elif case in {"body_citation", "content_schema", "descendant_missing"}:
        if case == "content_schema":
            content["unexpected"] = False
        else:
            source = read(child(body, "subject_ref"))
            content["source_ref"] = source["source_ref"]
            if case == "descendant_missing":
                missing = _native_source(
                    b"actually unavailable validation-only source", directory, "text/plain"
                )
                content["source_ref"] = dict(missing.to_mapping())
        content_ref = native(content, schema=False)
        record["validation_C0_statement_ref"] = dict(content_ref.to_mapping())
        expected_pointer = "/validation_C0_statement_ref"
        if case == "content_schema":
            expected_source = content_ref
            expected_pointer = ""
            expected_code, expected_claim = "invalid_schema", None
            detail = "Input violates its selected schema."
    else:
        if case in RECEIPT_SOURCE_CASES:
            statement, missing, source_expected = native_receipt_source_fault(
                case, statement, directory
            )
        if case == "multiple_receipts":
            statement["purpose"] = "human_review"
        if case in {"digest", "length"}:
            field = "content_digest" if case == "digest" else "content_byte_length"
            statement[field] = "sha256:" + "0" * 64 if case == "digest" else "1"
            expected_pointer = "/statement/" + field
            detail = "Validation receipt does not bind its whole validation manifest."
        if case in {"unknown_claim", "partial_claim_scope"}:
            statement["claim_ids"] = (
                sorted(
                    [*_array(statement["claim_ids"]), "unknown-validation-claim"],
                    key=lambda s: _text(s).encode("utf-16-be"),
                )
                if case == "unknown_claim"
                else [_object(_array(content["claims"])[0])["claim_id"]]
            )
            expected_pointer = "/statement/claim_ids"
            detail = "Validation receipt names an absent validation claim."
        if case in {"certificate_key", "certificate_id", "certificate_schema"}:
            certificate = read(child(statement, "authorization_ref"))
            if case == "certificate_key":
                certificate["subject_public_key_ref"] = producer["declared_public_key_ref"]
            elif case == "certificate_id":
                certificate["subject_key_id"] = "ed25519:" + "0" * 64
            else:
                certificate["unexpected"] = False
            certificate_ref = native(certificate, schema=case != "certificate_schema")
            statement["authorization_ref"] = dict(certificate_ref.to_mapping())
            expected_source, expected_pointer = body_ref, "/runner_actual_key_ref"
            if case == "certificate_schema":
                expected_source, expected_pointer = certificate_ref, ""
                expected_code, expected_claim = "invalid_schema", None
                detail = "Input violates its selected schema."
        key = eddsa.import_private_key(
            bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        )
        signed = b"GOTM-EMT-AUTHORITY-V2\x00" + canonicalize_json(
            json.dumps(statement).encode(), limits=limits
        )
        signature = eddsa.new(key, "rfc8032").sign(
            signed + (b"wrong message" if case == "wrong_message" else b"")
        )
        if case in {"bad_signature", "second_receipt_bad"}:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        receipt.update(
            statement=statement, signature=base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        )
        changed_ref = _stored(receipt, directory)
        record["ordered_native_receipt_refs"] = [dict(changed_ref.to_mapping())]
        if case == "second_receipt_bad":
            record["ordered_native_receipt_refs"] = [
                dict(receipt_ref.to_mapping()),
                dict(changed_ref.to_mapping()),
            ]
        if case == "multiple_receipts":
            record["ordered_native_receipt_refs"] = [
                dict(receipt_ref.to_mapping()),
                dict(changed_ref.to_mapping()),
            ]
        if case in {"bad_signature", "wrong_message", "second_receipt_bad"}:
            expected_source, expected_pointer = changed_ref, "/signature"
            expected_code, expected_claim = "invalid_signature", None
            detail = "The independent validation statement signature is invalid."
        elif case in {"digest", "length", "unknown_claim"}:
            expected_source, expected_code, expected_claim = changed_ref, "scope_missing", None
    record_ref = native(record)
    validation["record_ref"] = dict(record_ref.to_mapping())
    selected["validation"] = validation
    parent["claims"] = claims
    inputs["content_json"] = (
        base64.urlsafe_b64encode(json.dumps(parent).encode()).rstrip(b"=").decode()
    )
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
    if source_expected is not None:
        return inputs, ("refused", source_expected, None)
    if case in {"matching", "multiple_receipts", "partial_claim_scope"}:
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
    return inputs, (
        "refused",
        {
            "code": expected_code,
            "subject_digest": (expected_source or record_ref).digest,
            "claim_id": expected_claim,
            "pointer": expected_pointer,
            "detail": detail,
        },
        None,
    )
