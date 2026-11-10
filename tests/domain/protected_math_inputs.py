# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual native receipt and primitive-source controls

"""Retain full real input graphs and published-key math without native authority claims."""

import base64
import hashlib
import json
from pathlib import Path

from Crypto.Signature import eddsa
from tests.domain.protected_ordinary_inputs import (
    ordinary_certificate_state,
    protected_manifest_receipt,
)
from tests.domain.test_software_sources import _stored_source
from tests.domain.test_verification_report_sources import _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, canonicalize_json, reference_bytes

PROTECTED_MATH_CASES = (
    "protected_math_matching",
    "protected_math_mixed_order_valid",
    "protected_math_cofactor_only",
    "protected_math_wrong_message",
    "protected_math_legacy_domain",
    "protected_math_bad_signature",
    "protected_math_scalar_order",
    "protected_math_small_order_r",
    "protected_math_noncanonical_r",
    "protected_math_wrong_key_source",
    "protected_math_short_key_source",
    "protected_math_small_order_key",
    "cli_protected_math_bad_signature",
    "cli_protected_math_matching",
)


def protected_math_state(
    case: str, *, base: BlobRef, grant: BlobRef, snapshot: BlobRef, directory: Path, limits: Limits
) -> tuple[BlobRef, BlobRef, BlobRef]:
    """Retain whole ordinary sources with one actual chosen key-material contradiction.

    Parameters
    ----------
    case : str
        Actual complete matching input or selected raw key/identity/point contradiction.
    base, grant, snapshot : BlobRef
        Entire original source selections, without native authority or custody acceptance.
    directory : Path
        Owned complete flat source store.
    limits : Limits
        Original operation bounds for actual raw data identity.

    Returns
    -------
    tuple of BlobRef
        Complete grant, snapshot and leaf. All test key sources are unprotected/unenrolled.
    """
    grant, snapshot, certificate = ordinary_certificate_state(base, grant, snapshot, directory)
    case = case.removeprefix("cli_")
    material = (
        mixed_order_public_key()
        if case in {"protected_math_mixed_order_valid", "protected_math_cofactor_only"}
        else bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        if case == "protected_math_wrong_key_source"
        else b"\x01" + b"\x00" * 31
        if case == "protected_math_small_order_key"
        else b"a" * 31
        if case == "protected_math_short_key_source"
        else None
    )
    if material is not None:
        public = reference_bytes(
            material,
            media_type="application/octet-stream",
            digest_basis="raw_bytes",
            schema_id=None,
            limits=limits,
        )
        (directory / public.digest[7:]).write_bytes(material)
        leaf = _object(json.loads((directory / certificate.digest[7:]).read_bytes()))
        leaf["subject_public_key_ref"] = dict(public.to_mapping())
        if case in {
            "protected_math_small_order_key",
            "protected_math_mixed_order_valid",
            "protected_math_cofactor_only",
        }:
            leaf["subject_key_id"] = "ed25519:" + hashlib.sha256(material).hexdigest()
        certificate = _stored_source(leaf, directory, schema_id=_text(leaf["schema_id"]))
        selected = _object(json.loads((directory / snapshot.digest[7:]).read_bytes()))
        selected["certificate_refs"] = [dict(certificate.to_mapping())]
        snapshot = _stored_source(selected, directory, schema_id=_text(selected["schema_id"]))
    return grant, snapshot, certificate


def protected_math_receipt(
    case: str,
    content: bytes,
    *,
    snapshot: BlobRef,
    certificate: BlobRef,
    scope: BlobRef,
    created_at: str,
    directory: Path,
    limits: Limits,
) -> tuple[BlobRef, bytes]:
    """Freeze the complete actual message/signature and any explicit mathematical fault.

    Parameters
    ----------
    case : str
        Matching native signature or actual full-message/domain/point/scalar corruption.
    content : bytes
        Entire actual C0, never an easier projected target.
    snapshot, certificate, scope : BlobRef
        Entire original declared selected sources, without authority admission.
    created_at : str
        Actual supplied UTC token, without qualified Clock substitution.
    directory : Path
        Owned whole input source store.
    limits : Limits
        Original canonical/input bounds.

    Returns
    -------
    tuple
        Entire canonical original receipt identity/bytes. Genuine signatures use only
        the published unprotected RFC8032 vector, never an operational protected key.
    """
    leaf = _object(json.loads((directory / certificate.digest[7:]).read_bytes()))
    _, raw = protected_manifest_receipt(
        content,
        snapshot=snapshot,
        certificate=certificate,
        scope=scope,
        created_at=created_at,
        directory=directory,
        limits=limits,
        statement_changes={"signer_key_id": leaf["subject_key_id"]},
    )
    envelope = _object(json.loads(raw))
    statement = canonicalize_json(json.dumps(envelope["statement"]).encode(), limits=limits)
    encoded = _text(envelope["signature"])
    signature = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    case = case.removeprefix("cli_")
    if case in {"protected_math_wrong_message", "protected_math_legacy_domain"}:
        # Published RFC8032 section7.1 vector, not an operational or protected secret.
        key = eddsa.import_private_key(
            bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        )
        message = (
            b"GOTM-EMT-SIGNED-STATEMENT-V1\n" + statement
            if case == "protected_math_legacy_domain"
            else b"GOTM-EMT-AUTHORITY-V2\0" + statement + b"wrong-whole-message"
        )
        signature = eddsa.new(key, "rfc8032").sign(message)
        eddsa.new(key.public_key(), "rfc8032").verify(message, signature)
    if case in {"protected_math_mixed_order_valid", "protected_math_cofactor_only"}:
        signature = mixed_order_signature(
            b"GOTM-EMT-AUTHORITY-V2\0" + statement,
            cofactor_only=case == "protected_math_cofactor_only",
        )
    if case == "protected_math_bad_signature":
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
    if case == "protected_math_scalar_order":
        signature = signature[:32] + (2**252 + 27742317777372353535851937790883648493).to_bytes(
            32, "little"
        )
    if case == "protected_math_small_order_r":
        signature = b"\x01" + b"\x00" * 31 + signature[32:]
    if case == "protected_math_noncanonical_r":
        signature = (2**255 - 19).to_bytes(32, "little") + signature[32:]
    envelope["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    raw = canonicalize_json(json.dumps(envelope).encode(), limits=limits)
    reference = reference_bytes(
        raw,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=None,
        limits=limits,
    )
    (directory / reference.digest[7:]).write_bytes(raw)
    return reference, raw


def protected_math_expected(
    case: str, *, receipt: BlobRef, certificate: BlobRef
) -> dict[str, object]:
    """State all five actual public error fields independently from runtime math.

    Parameters
    ----------
    case : str
        Full actual mathematical/source control.
    receipt, certificate : BlobRef
        Entire actual independently prepared targets, without signature/class admission.

    Returns
    -------
    dict
        Fixed full signature/source failure or the remaining real V2 state boundary.
    """
    case = case.removeprefix("cli_")
    if case in {"protected_math_matching", "protected_math_mixed_order_valid"}:
        return {
            "code": "configuration_error",
            "subject_digest": None,
            "claim_id": None,
            "pointer": "/trust",
            "detail": "Invalid local configuration.",
        }
    if case in {"protected_math_wrong_key_source", "protected_math_short_key_source"}:
        return {
            "code": "invalid_delegation",
            "subject_digest": certificate.digest,
            "claim_id": None,
            "pointer": "/subject_public_key_ref",
            "detail": "Selected native key data does not match the certificate subject.",
        }
    return {
        "code": "invalid_signature",
        "subject_digest": receipt.digest,
        "claim_id": None,
        "pointer": "/signature",
        "detail": "The protected statement signature is invalid.",
    }


def mixed_order_public_key() -> bytes:
    """Return an actual mixed-order raw point using maintained public coordinates.

    Returns
    -------
    bytes
        Canonical raw32 B+(0,-1)=(-Bx,-By). This mathematical input has known
        scalar1 and a torsion component; it is not an eligible operational key.
    """
    base = eddsa.import_public_key(b"\x58" + b"\x66" * 31).pointQ
    modulus = 2**255 - 19
    encoded = ((modulus - int(base.y)) | (((modulus - int(base.x)) & 1) << 255)).to_bytes(
        32, "little"
    )
    point = eddsa.import_public_key(encoded).pointQ
    assert point * 2 == base * 2 and not (point * 8).is_point_at_infinity()
    return encoded


def mixed_order_signature(message: bytes, *, cofactor_only: bool) -> bytes:
    """Construct real full-message vectors that distinguish the exact native equation.

    Parameters
    ----------
    message : bytes
        Entire actual native V2 target, including its exact domain and zero separator.
    cofactor_only : bool
        Select a deliberately false exact equation whose cofactored equation holds,
        or a genuine exact-equation signature. Neither input claims key eligibility.

    Returns
    -------
    bytes
        Actual canonical raw64 signature with S<L, produced using maintained points
        and the original reduced challenge. Exact and cofactored relations are checked
        independently through public point operations, never a product private helper.

    Raises
    ------
    AssertionError
        No selected challenge parity occurs within the finite owned vector search.
    """
    public = mixed_order_public_key()
    point = eddsa.import_public_key(public).pointQ
    base = eddsa.import_public_key(b"\x58" + b"\x66" * 31).pointQ
    order = 2**252 + 27742317777372353535851937790883648493
    for nonce in range(1, 1025):
        r_point = base * nonce
        r_bytes = (int(r_point.y) | ((int(r_point.x) & 1) << 255)).to_bytes(32, "little")
        challenge = (
            int.from_bytes(hashlib.sha512(r_bytes + public + message).digest(), "little") % order
        )
        if bool(challenge & 1) != cofactor_only:
            continue
        scalar = (nonce + challenge) % order
        left, right = base * scalar, r_point + point * challenge
        assert left * 8 == right * 8
        assert (left == right) is not cofactor_only
        return r_bytes + scalar.to_bytes(32, "little")
    raise AssertionError("Native mixed-order vector search exhausted.")
