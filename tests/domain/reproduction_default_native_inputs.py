# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete default-class validation native inputs

"""Keep default record construction and supplied software equations on real sources."""

import base64
import json
from pathlib import Path

from Crypto.Signature import eddsa
from tests.domain.clock_source_inputs import software_manifest_receipt
from tests.domain.native_run_inputs import rebind_native_run_runner
from tests.domain.reproduction_record_inputs import ReproductionOutcome
from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_software_sources import _software_table
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _array, _bytes, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, canonicalize_json, reference_bytes

DEFAULT_NATIVE_REPRODUCTION_CASES = (
    "reproduction_native_without_c0",
    "reproduction_native_c0_only",
    "reproduction_native_equal_key_data",
    "software_receipt_reproduction_native_matching",
    "reproduction_native_signed_unsigned",
)


def _equivalent_key_references(directory: Path, limits: Limits) -> tuple[BlobRef, BlobRef]:
    """Bind identical real point bytes under two admissible identity bases.

    Parameters
    ----------
    directory : Path
        Actual owned store for the one whole unchanged raw32 source.
    limits : Limits
        Original public operation bounds.

    Returns
    -------
    tuple of BlobRef
        Raw and JCS references to the same canonical32bytes. The raw compressed
        point happens to be JSON text; it is never decoded as a key wrapper. No
        private key, signature, possession or custody source is supplied.
    """
    raw = bytes.fromhex("226465636c617265642d7075626c69632d6b65792d3030303030303030303222")
    point = eddsa.import_public_key(raw).pointQ
    assert len(raw) == 32 and not (point * 8).is_point_at_infinity()
    assert canonicalize_json(raw, limits=limits) == raw
    first = reference_bytes(
        raw,
        media_type="application/octet-stream",
        digest_basis="raw_bytes",
        schema_id=None,
        limits=limits,
    )
    second = reference_bytes(
        raw,
        media_type="application/octet-stream",
        digest_basis="jcs_content",
        schema_id=None,
        limits=limits,
    )
    assert first != second and first.digest == second.digest
    (directory / first.digest[7:]).write_bytes(raw)
    return first, second


def default_native_reproduction_input(
    condition: str, inputs: dict[str, object], directory: Path, *, base: BlobRef, limits: Limits
) -> tuple[dict[str, object], ReproductionOutcome]:
    """Materialise whole actual default-class graphs and the supplied native equation.

    Parameters
    ----------
    condition : str
        One actual default package correspondence or software validation receipt.
    inputs : dict
        Whole original parent and unsigned/software reproduction package.
    directory : Path
        Actual owned complete source store before first S0.
    base : BlobRef
        Whole earlier ordinary policy, without replacing the record's earlier policy.
    limits : Limits
        Original unchanged public limits.

    Returns
    -------
    tuple
        Complete final parent and independently specified original diagnostic.
        Default construction remains root-free; all test keys remain unprotected. The
        software class retains its unresolved, unwaived record-signature obligation.
    """

    def read(reference: BlobRef) -> dict[str, object]:
        """Read an entire earlier stored source before deliberate changes."""
        return _object(json.loads((directory / reference.digest[7:]).read_bytes()))

    def child(value: dict[str, object], field: str) -> BlobRef:
        """Decode the complete actual source reference without rewriting metadata."""
        return BlobRef.from_mapping(_object(value[field]))

    def native(value: dict[str, object]) -> BlobRef:
        """Store the entire source under its actual native schema."""
        return _stored(value, directory, schema_id=_text(value["schema_id"]))

    parent = _object(json.loads(_bytes(inputs["content_json"])))
    claims = [_object(item) for item in _array(parent["claims"])]
    validation = _object(claims[1]["validation"])
    record = read(child(validation, "record_ref"))
    body = read(child(record, "body_ref"))
    body_ref = child(record, "body_ref")
    runner_ref = child(body, "runner_binding_ref")
    runner = read(runner_ref)
    producer = read(child(body, "producer_binding_ref"))
    if condition in {
        "reproduction_native_equal_key_data",
        "software_receipt_reproduction_native_matching",
        "reproduction_native_signed_unsigned",
    }:
        first = _native_source(
            bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            directory,
            "application/octet-stream",
        )
        second = _native_source(
            bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            directory,
            "application/octet-stream",
        )
        equal = condition == "reproduction_native_equal_key_data"
        producer["declared_public_key_ref"] = dict((first if equal else second).to_mapping())
        runner["declared_public_key_ref"] = (
            {**first.to_mapping(), "media_type": "text/plain"}
            if equal
            else dict(first.to_mapping())
        )
        if equal:
            raw_reference, canonical_reference = _equivalent_key_references(directory, limits)
            producer["declared_public_key_ref"] = dict(raw_reference.to_mapping())
            runner["declared_public_key_ref"] = dict(canonical_reference.to_mapping())
        runner_ref = native(runner)
        body.update(
            producer_binding_ref=dict(native(producer).to_mapping()),
            runner_binding_ref=dict(runner_ref.to_mapping()),
            runner_actual_key_ref=None if equal else dict(first.to_mapping()),
        )
        body = rebind_native_run_runner(body, runner=runner_ref, directory=directory)
        body_ref = native(body)
        record["body_ref"] = dict(body_ref.to_mapping())
    if condition == "reproduction_native_without_c0":
        receipt = _stored({"deliberately_unpaired_receipt": True}, directory)
        record["ordered_native_receipt_refs"] = [dict(receipt.to_mapping())]
    elif condition != "reproduction_native_equal_key_data":
        content = read(child(body, "subject_ref"))
        content.update(
            source_ref=dict(body_ref.to_mapping()),
            producer={**_object(content["producer"]), "principal": runner["principal_id"]},
        )
        raw = canonicalize_json(json.dumps(content).encode(), limits=limits)
        content_ref = reference_bytes(
            raw,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id="evidence_manifest_toolkit.manifest.v1",
            limits=limits,
        )
        (directory / content_ref.digest[7:]).write_bytes(raw)
        record["validation_C0_statement_ref"] = dict(content_ref.to_mapping())
        if condition in {
            "software_receipt_reproduction_native_matching",
            "reproduction_native_signed_unsigned",
        }:
            receipt, _ = software_manifest_receipt(
                raw,
                table=_software_table(base, directory, sequence="1"),
                scope=base,
                created_at=_text(content["created_at"]),
                directory=directory,
                limits=limits,
            )
            record["ordered_native_receipt_refs"] = [dict(receipt.to_mapping())]
    record_ref = native(record)
    validation["record_ref"] = dict(record_ref.to_mapping())
    claims[1]["validation"] = validation
    parent["claims"] = claims
    inputs["content_json"] = (
        base64.urlsafe_b64encode(json.dumps(parent).encode()).rstrip(b"=").decode()
    )
    if condition in {"reproduction_native_equal_key_data", "reproduction_native_without_c0"}:
        equal = condition == "reproduction_native_equal_key_data"
        return inputs, (
            "refused",
            {
                "code": "invalid_claim",
                "subject_digest": (runner_ref if equal else record_ref).digest,
                "claim_id": _text(body["claim_id"]),
                "pointer": "/declared_public_key_ref" if equal else "/validation_C0_statement_ref",
                "detail": "Independent validation sources conflict.",
            },
            None,
        )
    if condition == "software_receipt_reproduction_native_matching":
        return inputs, (
            "refused",
            {
                "code": "signature_required",
                "subject_digest": record_ref.digest,
                "claim_id": _text(body["claim_id"]),
                "pointer": None,
                "detail": "The required validation record signature is unavailable.",
            },
            None,
        )
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
