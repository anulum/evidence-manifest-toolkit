# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete native validation descendant source faults

"""Retain whole receipt/certificate source faults for real API and CLI traversal."""

import json
from pathlib import Path

from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _object, _text

from evidence_manifest_toolkit import BlobRef

RECEIPT_SOURCE_CASES = (
    "certificate_missing",
    "certificate_key_missing",
    "certificate_key_identity",
    "receipt_scope_missing",
    "receipt_authorizing_missing",
)


def native_receipt_source_fault(
    case: str, statement: dict[str, object], directory: Path
) -> tuple[dict[str, object], BlobRef | None, dict[str, object] | None]:
    """Change one actual selected descendant without mutating any shared source.

    Parameters
    ----------
    case : str
        Named whole native certificate/key/scope/authorizing-source contradiction.
    statement : dict
        Entire actual validation statement, re-signed by the caller after mutation.
    directory : Path
        Actual owned full source store frozen before public Clock sampling.

    Returns
    -------
    tuple
        Whole updated statement, exact source to remove after materialisation, and an
        independently specified byte-identity reason where the source remains present.
    """
    missing: BlobRef | None = None
    reason: dict[str, object] | None = None
    if case.startswith("receipt_"):
        field = "scope_ref" if case == "receipt_scope_missing" else "authorizing_state_ref"
        missing = _stored({"unavailable_validation_receipt_source": field}, directory)
        statement[field] = dict(missing.to_mapping())
        return statement, missing, None
    original = BlobRef.from_mapping(_object(statement["authorization_ref"]))
    certificate = _object(json.loads((directory / original.digest[7:]).read_bytes()))
    if case != "certificate_missing":
        public = _native_source(b"p" * 32, directory, "application/octet-stream")
        certificate["subject_public_key_ref"] = dict(public.to_mapping())
    certificate["serial"] = "4"
    reference = _stored(certificate, directory, schema_id=_text(certificate["schema_id"]))
    if case == "certificate_missing":
        missing = reference
    elif case == "certificate_key_missing":
        missing = public
    else:
        (directory / public.digest[7:]).write_bytes(b"q" * 32)
        reason = {
            "code": "reference_mismatch",
            "subject_digest": reference.digest,
            "claim_id": None,
            "pointer": "/subject_public_key_ref",
            "detail": "Reference byte identity does not match.",
        }
    statement["authorization_ref"] = dict(reference.to_mapping())
    return statement, missing, reason
