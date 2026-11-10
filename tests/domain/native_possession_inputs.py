# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — real own-key signature and complete declared protocol controls

"""Sign exact published-test-key messages without claiming qualified issuance or custody."""

import base64
import json
from pathlib import Path
from typing import Literal, cast

from Crypto.Signature import eddsa
from tests.domain.native_issuance_inputs import ISSUANCE_BASE, issuer_input
from tests.domain.native_possession_method_inputs import PAYLOAD_IDS, PossessionManifestWriter
from tests.domain.native_possession_receipt_inputs import possession_receipt_input
from tests.domain.native_possession_receiver_inputs import receiver_input
from tests.domain.native_possession_source_inputs import possession_source_input
from tests.domain.native_run_inputs import rebind_native_run_runner
from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef, Limits, canonicalize_json

POSSESSION_BASE = (
    "matching",
    "wrong_domain",
    "wrong_message",
    "signature_length",
    "nonce_alias",
    "request_other",
    "issuer_other",
    "receiver_replay",
    "receiver_fork",
    "receiver_sequence",
    "receiver_proof",
    "receiver_time",
    "receiver_head",
    "proof_missing",
    "result_extra",
    "process_scope",
    "receipt_matching",
    "receipt_target",
    "receipt_length",
    "receipt_claim",
    "receipt_alias_duplicate",
    "manifest_without_schema",
    "challenge_lifetime",
    "receiver_expiry",
    "receiver_head_unstable",
    "challenge_missing",
    "result_malformed",
    "challenge_principal",
    "request_kind",
    "challenge_time_invalid",
    "proof_without_key",
    "challenge_manifest_other",
    "limitations_missing",
    "limitations_schema",
    "issuance_missing",
    "challenge_manifest_invalid",
    "receiver_issued_missing",
    "receiver_head_mode",
    "receiver_head_size",
    "receiver_head_bound",
    "receiver_before_issue",
    "receiver_issue_boundary",
    "wrong_key",
    *ISSUANCE_BASE,
)
POSSESSION_CASES = tuple("reproduction_possession_" + value for value in POSSESSION_BASE) + (
    "cli_reproduction_possession_matching",
    "cli_reproduction_possession_wrong_domain",
    "cli_reproduction_possession_proof_missing",
    "protected_reproduction_possession_matching",
    "cli_reproduction_possession_receipt_target",
    "cli_reproduction_possession_issuer_challenge",
    "cli_reproduction_possession_issuer_journal_missing",
    "protected_reproduction_possession_issuer_matching",
)


def native_possession_input(
    body: dict[str, object],
    *,
    inputs: dict[str, object],
    rules: dict[str, object],
    conditions: BlobRef,
    directory: Path,
    condition: str,
) -> tuple[
    dict[str, object],
    tuple[Literal["configuration", "refused", "unavailable"], dict[str, object], BlobRef | None]
    | None,
]:
    """Create the actual raw own-key signature and every complete acyclic declared source.

    Parameters
    ----------
    body : dict
        Entire earlier validation body and full source-consistent run graph.
    inputs : dict
        Actual independently prepared public registry/limits/source configuration.
    rules : dict
        Whole selected original identity and method sources.
    conditions : BlobRef
        Existing explicit unqualified source limitations.
    directory : Path
        Actual owned flat raw source store before Clock/context freeze.
    condition : str
        Named real public API/CLI case or an unaffected original reproduction case.

    Returns
    -------
    tuple
        Entire updated body and an exact independent failure oracle, or None outside
        this surface. Real cryptographic bytes prove the equation only; no admitted
        object, clock/provider substitution or qualified receiver is fabricated.
    """
    if not condition.startswith("reproduction_possession_"):
        return body, None
    case = condition.removeprefix("reproduction_possession_")

    def read(reference: object) -> dict[str, object]:
        """Read one whole actual earlier source without rewriting its identity."""
        selected = BlobRef.from_mapping(_object(reference))
        return _object(json.loads((directory / selected.digest[7:]).read_bytes()))

    def ref(value: BlobRef) -> dict[str, str]:
        """Retain every original full reference assertion."""
        return dict(value.to_mapping())

    runner = read(body["runner_binding_ref"])
    identity_rule = read(rules["identity_rule_ref"])
    method_ref = BlobRef.from_mapping(_object(identity_rule["actual_key_possession_rule_ref"]))
    method = read(ref(method_ref))
    issuer = read(method["challenge_issuer_rule_ref"])
    execution = read(body["actual_run_provenance_ref"])
    request_ref = BlobRef.from_mapping(_object(execution["execution_request_ref"]))
    challenge_request = request_ref
    if case in {"request_other", "request_kind"}:
        alternative = read(ref(request_ref))
        if case == "request_other":
            alternative["resource_policy_ref"] = body["subject_ref"]
        else:
            alternative["request_kind"] = "producer_context"
        challenge_request = _stored(alternative, directory)
    disclosure = ref(conditions)
    challenge = {
        "semantic_law_ref": method["semantic_law_ref"],
        "identity_policy_ref": rules["identity_rule_ref"],
        "execution_request_ref": ref(challenge_request),
        "issuer_source_ref": body["subject_ref"]
        if case == "issuer_other"
        else issuer["issuer_identity_ref"],
        "principal_id": "another-principal"
        if case == "challenge_principal"
        else runner["principal_id"],
        "vendor_id": runner["vendor_id"],
        "public_key_ref": runner["declared_public_key_ref"],
        "launch_record_ref": runner["actual_launch_or_declared_source_ref"],
        "process_identity_ref": runner["process_identity_ref"],
        "nonce_base64url": "A" * 42 + "B"
        if case == "nonce_alias"
        else base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode(),
        "issued_at": "invalid-time" if case == "challenge_time_invalid" else "2024-01-01T00:00:00Z",
        "expires_at": "2024-01-01T00:00:00Z"
        if case == "challenge_lifetime"
        else "2030-01-01T00:00:00Z",
        "issuance_time_sources_ref": disclosure,
    }
    challenge_ref = _stored(challenge, directory, schema_id=PAYLOAD_IDS["challenge"])
    writer = PossessionManifestWriter(inputs, directory, conditions)
    issuance_ref, issuance_conflict, issuer_journal = issuer_input(
        challenge_ref,
        issuer=issuer,
        receiver_method=method["receiver_method_ref"],
        conditions=conditions,
        directory=directory,
        case=case,
    )
    challenge_manifest = writer.manifest("challenge", challenge, issuance_ref)
    message = {
        "possession_method_ref": ref(method_ref),
        "identity_policy_ref": rules["identity_rule_ref"],
        "challenge_ref": ref(challenge_ref),
        **{
            field: challenge[field]
            for field in (
                "principal_id",
                "vendor_id",
                "public_key_ref",
                "launch_record_ref",
                "process_identity_ref",
            )
        },
    }
    if case == "wrong_message":
        message["vendor_id"] = "different-signed-vendor"
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    raw = canonicalize_json(json.dumps(message).encode(), limits=limits)
    domain = (
        b"GOTM-EMT-AUTHORITY-V2\x00"
        if case == "wrong_domain"
        else b"GOTM-NATIVE-KEY-POSSESSION\x00\x01"
    )
    key = eddsa.import_private_key(
        bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
            if case == "wrong_key"
            else "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
    )
    public_ref = BlobRef.from_mapping(_object(runner["declared_public_key_ref"]))
    selected_public = (directory / public_ref.digest[7:]).read_bytes()
    if case == "wrong_key":
        assert key.public_key().export_key(format="raw") != selected_public
    else:
        assert key.public_key().export_key(format="raw") == selected_public
    signature = eddsa.new(key, "rfc8032").sign(domain + raw)
    eddsa.new(key.public_key(), "rfc8032").verify(domain + raw, signature)
    if case == "signature_length":
        signature = signature[:-1]
    proof = _native_source(signature, directory, "application/octet-stream")
    completion, receiver_conflict = receiver_input(
        challenge_ref, proof, challenge_request, runner, method, conditions, directory, writer, case
    )
    challenge_receipts, receiver_receipts, receipt_conflict = possession_receipt_input(
        case,
        challenge=challenge_manifest,
        completion=completion,
        conditions=conditions,
        directory=directory,
        limits=limits,
    )
    result = {
        "possession_method_ref": ref(method_ref),
        "identity_policy_ref": rules["identity_rule_ref"],
        "challenge_ref": ref(challenge_ref),
        "challenge_manifest_ref": ref(challenge_manifest),
        "ordered_challenge_receipt_refs": challenge_receipts,
        "proof_bytes_ref": ref(proof),
        "receiver_completion_manifest_ref": ref(completion),
        "ordered_receiver_receipt_refs": receiver_receipts,
        "limitations_ref": disclosure,
    }
    if case == "result_extra":
        result["unexpected"] = False
    result, source_conflict, missing_source = possession_source_input(
        case, result, issuance=issuance_ref, directory=directory, limits=limits
    )
    if case == "issuer_journal_missing":
        missing_source = issuer_journal
        (directory / issuer_journal.digest[7:]).unlink()
    elif case == "issuer_journal_bytes":
        journal_path = directory / issuer_journal.digest[7:]
        original = journal_path.read_bytes()
        journal_path.write_bytes(b"[" + original[1:])
    if case == "manifest_without_schema":
        for field in ("challenge_manifest_ref", "receiver_completion_manifest_ref"):
            result[field] = {
                name: value for name, value in _object(result[field]).items() if name != "schema_id"
            }
    result_ref = (
        _native_source(b"{", directory, "application/json")
        if case == "result_malformed"
        else _stored(result, directory)
    )
    runner["key_possession_ref"] = ref(result_ref)
    runner_ref = _stored(
        runner, directory, schema_id="evidence_manifest_toolkit.identity_binding.v2"
    )
    updated = rebind_native_run_runner(
        {**body, "runner_binding_ref": ref(runner_ref)}, runner=runner_ref, directory=directory
    )
    producer_ref = None
    if case == "proof_without_key":
        producer = read(updated["producer_binding_ref"])
        producer.update(declared_public_key_ref=None, key_possession_ref=ref(result_ref))
        producer_ref = _stored(
            producer, directory, schema_id="evidence_manifest_toolkit.identity_binding.v2"
        )
        updated["producer_binding_ref"] = ref(producer_ref)
    code, source, field, detail = (
        "invalid_claim",
        challenge_ref,
        "",
        "Native key-possession sources conflict.",
    )
    if case in {"wrong_domain", "wrong_message", "signature_length", "wrong_key"}:
        code, source, field, detail = (
            "invalid_signature",
            result_ref,
            "proof_bytes_ref",
            "The native key-possession signature is invalid.",
        )
    elif case == "nonce_alias":
        field = "nonce_base64url"
    elif case == "request_other":
        field = "execution_request_ref"
    elif case == "request_kind":
        source, field = challenge_request, "request_kind"
    elif case == "issuer_other":
        field = "issuer_source_ref"
    elif case == "process_scope":
        field = "process_identity_ref"
    elif case == "challenge_principal":
        field = "principal_id"
    elif case == "challenge_time_invalid":
        code, field, detail = "invalid_schema", "issued_at", "Invalid UTC timestamp."
    elif case == "proof_without_key":
        assert producer_ref is not None
        source, field = producer_ref, "declared_public_key_ref"
    elif case == "challenge_lifetime":
        field = "expires_at"
    elif case == "issuer_receiver_rule":
        source = BlobRef.from_mapping(_object(method["challenge_issuer_rule_ref"]))
        field = "challenge_completion_method_ref"
    elif issuance_conflict is not None:
        source, field = issuance_conflict
        code, detail = (
            ("reference_mismatch", "Reference byte identity does not match.")
            if case == "issuer_journal_bytes"
            else ("invalid_claim", "Native challenge issuance sources conflict.")
        )
    elif receipt_conflict is not None:
        code, source, field, detail = (
            "scope_missing",
            result_ref,
            receipt_conflict,
            "Native possession receipt target conflicts.",
        )
    elif source_conflict is not None:
        code, supplied_source, field, detail = source_conflict
        source = result_ref if supplied_source is None else supplied_source
    elif receiver_conflict is not None:
        source, field = receiver_conflict
        detail = "Native challenge receiver sources conflict."
    elif case == "result_extra":
        code, source, detail = "invalid_schema", result_ref, "Input violates its selected schema."
    elif case == "result_malformed":
        code, source, detail = "invalid_json", result_ref, "Input is not valid strict JSON."
    elif case in {"proof_missing", "challenge_missing"} or missing_source is not None:
        missing = missing_source
        if missing is None:
            missing = proof if case == "proof_missing" else challenge_ref
            (directory / missing.digest[7:]).unlink()
        return updated, (
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
    else:
        return updated, (
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
    return updated, (
        "refused",
        {
            "code": code,
            "subject_digest": source.digest,
            "claim_id": None,
            "pointer": "/" + field if field else "",
            "detail": detail,
        },
        None,
    )
