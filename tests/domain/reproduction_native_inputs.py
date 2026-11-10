# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete distinct published-key validation sources

"""Build genuine unprotected test-key validation receipts without authority admission."""

import base64
import hashlib
import json
from pathlib import Path

from Crypto.Signature import eddsa
from tests.domain.protected_ordinary_inputs import protected_manifest_receipt
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _array, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, canonicalize_json, reference_bytes


def native_validation_bundle(
    document: dict[str, object],
    body: BlobRef,
    *,
    snapshot: BlobRef,
    certificate: BlobRef,
    scope: BlobRef,
    directory: Path,
    limits: Limits,
) -> tuple[BlobRef, list[BlobRef]]:
    """Sign the whole body-citing validation C0 with the actual runner's published key.

    Parameters
    ----------
    document : dict
        Whole earlier original subject, retaining every original claim and limitation.
    body : BlobRef
        Entire earlier body with actual runner source, explicitly unqualified execution.
    snapshot, certificate, scope : BlobRef
        Whole unqualified native sources. A separate runner leaf is included in a whole
        declared snapshot; no issuer/control signature or custody proof is invented.
    directory : Path
        Actual owned immutable full source store before the Clock first sample.
    limits : Limits
        Original unchanged full operation bounds.

    Returns
    -------
    tuple
        Whole validation C0 and ordered actual native receipt references. Both keys are
        published RFC8032 vectors, unprotected and unenrolled, never eligible seat keys.
    """

    def read(reference: BlobRef) -> dict[str, object]:
        """Read one whole earlier source from the actual owned store."""
        return _object(json.loads((directory / reference.digest[7:]).read_bytes()))

    body_value = read(body)
    runner_ref = BlobRef.from_mapping(_object(body_value["runner_binding_ref"]))
    runner = read(runner_ref)
    key_reference = BlobRef.from_mapping(_object(body_value["runner_actual_key_ref"]))
    public = (directory / key_reference.digest[7:]).read_bytes()
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        if public.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        else "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    key = eddsa.import_private_key(seed)
    assert key.public_key().export_key(format="raw") == public
    leaf = read(certificate)
    leaf.update(
        subject_key_id="ed25519:" + hashlib.sha256(public).hexdigest(),
        subject_public_key_ref=dict(key_reference.to_mapping()),
        identity_custody_source_ref=dict(runner_ref.to_mapping()),
        scope={**_object(leaf["scope"]), "principal_ids": [runner["principal_id"]]},
        serial="3",
    )
    leaf_ref = _stored(leaf, directory, schema_id=_text(leaf["schema_id"]))
    state = read(snapshot)
    state["certificate_refs"] = [*_array(state["certificate_refs"]), dict(leaf_ref.to_mapping())]
    state_ref = _stored(state, directory, schema_id=_text(state["schema_id"]))
    validation = {
        **document,
        "source_ref": dict(body.to_mapping()),
        "producer": {**_object(document["producer"]), "principal": runner["principal_id"]},
    }
    raw = canonicalize_json(json.dumps(validation).encode(), limits=limits)
    reference = reference_bytes(
        raw,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id="evidence_manifest_toolkit.manifest.v1",
        limits=limits,
    )
    (directory / reference.digest[7:]).write_bytes(raw)
    _, template = protected_manifest_receipt(
        raw,
        snapshot=state_ref,
        certificate=leaf_ref,
        scope=scope,
        created_at=_text(document["created_at"]),
        directory=directory,
        limits=limits,
    )
    envelope = _object(json.loads(template))
    statement = _object(envelope["statement"])
    statement["signer_key_id"] = leaf["subject_key_id"]
    canonical = canonicalize_json(json.dumps(statement).encode(), limits=limits)
    signature = eddsa.new(key, "rfc8032").sign(b"GOTM-EMT-AUTHORITY-V2\x00" + canonical)
    eddsa.new(key.public_key(), "rfc8032").verify(
        b"GOTM-EMT-AUTHORITY-V2\x00" + canonical, signature
    )
    envelope.update(
        statement=statement,
        signature=base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    )
    receipt = _stored(envelope, directory)
    return reference, [receipt]
