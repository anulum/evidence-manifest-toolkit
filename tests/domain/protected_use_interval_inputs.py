# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — protected whole-use public source cases

"""Construct immutable selected windows before genuine invocation capture and entry."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tests.domain.test_software_sources import _stored_source
from tests.domain.test_verification_report_sources import _object, _text

from evidence_manifest_toolkit import BlobRef

PROTECTED_USE_INTERVAL_CASES = (
    "protected_use_grant_lower",
    "protected_use_grant_upper",
    "protected_use_withdrawal_lower",
    "protected_use_until_withdrawal",
    "protected_use_grant_year_zero",
    "protected_use_snapshot_lower",
    "protected_use_snapshot_upper",
    "protected_use_certificate_lower",
    "protected_use_certificate_upper",
    "protected_use_parent",
    "protected_use_matching",
    "protected_use_snapshot_after_signature",
    "cli_protected_use_snapshot_upper",
    "cli_protected_use_certificate_lower",
)
PROTECTED_USE_RECEIPT_CASES = frozenset(
    {
        "protected_use_certificate_lower",
        "protected_use_certificate_upper",
        "protected_use_parent",
        "protected_use_matching",
        "protected_use_snapshot_after_signature",
    }
)
PROTECTED_USE_MATCHING_CASES = frozenset(
    {
        "protected_use_until_withdrawal",
        "protected_use_grant_year_zero",
        "protected_use_parent",
        "protected_use_matching",
    }
)


def protected_use_interval_sources(
    condition: str,
    *,
    grant: BlobRef,
    snapshot: BlobRef,
    certificate: BlobRef | None,
    original_sample_utc: str,
    directory: Path,
) -> tuple[BlobRef, BlobRef, BlobRef | None, dict[str, object] | None]:
    """Keep whole prior source windows while the later actual context is still unfrozen.

    Parameters
    ----------
    condition : str
        Named full grant, snapshot, certificate or parent-chain source scenario.
    grant, snapshot : BlobRef
        Entire independently selected earlier declarations, without root enrolment.
    certificate : BlobRef or None
        Actual published-test-key ordinary leaf when that scenario requires a receipt.
    original_sample_utc : str
        Genuine earlier annual raw sample, used only to declare a three-second source
        boundary. Current invocation captures and native entry are never substituted.
    directory : Path
        Owned immutable store preserving every original body when creating a successor.

    Returns
    -------
    tuple
        Whole actual grant/snapshot/leaf and exact authored refusal, or None for unchanged
        or numerically matching sources. No source becomes accepted protected authority.
    """
    case = condition.removeprefix("cli_")
    if case not in PROTECTED_USE_INTERVAL_CASES:
        return grant, snapshot, certificate, None

    def body(reference: BlobRef) -> dict[str, object]:
        """Read the complete original native declaration without a projected replacement."""
        return _object(json.loads((directory / reference.digest[7:]).read_bytes()))

    def store(value: dict[str, object]) -> BlobRef:
        """Retain the full canonical body and its actual original native schema metadata."""
        return _stored_source(value, directory, schema_id=_text(value["schema_id"]))

    observed = datetime.fromisoformat(original_sample_utc.removesuffix("Z") + "+00:00")
    lower = (observed - timedelta(seconds=3)).astimezone(UTC).isoformat().replace("+00:00", "Z")
    upper = (observed + timedelta(seconds=3)).astimezone(UTC).isoformat().replace("+00:00", "Z")
    grant_value, snapshot_value = body(grant), body(snapshot)
    subject: BlobRef | None = None
    pointer = ""
    if (
        case.startswith(("protected_use_grant_", "protected_use_withdrawal_"))
        or case == "protected_use_until_withdrawal"
    ):
        lifetime = _object(grant_value["lifetime"])
        if case in {"protected_use_withdrawal_lower", "protected_use_until_withdrawal"}:
            lifetime.update(kind="until_withdrawal", not_after=None)
        if case.endswith("_lower"):
            lifetime["not_before"] = lower
            pointer = "/lifetime/not_before"
        if case.endswith("_upper"):
            lifetime["not_after"] = upper
            pointer = "/lifetime/not_after"
        if case == "protected_use_grant_year_zero":
            lifetime["not_before"] = "0000-01-01T00:00:00.0000000000000000001Z"
        grant_value["lifetime"] = lifetime
        grant = store(grant_value)
        subject = grant
        snapshot_value["root_grant_ref"] = dict(grant.to_mapping())
    if case.startswith("protected_use_snapshot_") and case.endswith(("_lower", "_upper")):
        field = "issued_at" if case.endswith("_lower") else "expires_at"
        snapshot_value[field] = lower if case.endswith("_lower") else upper
        pointer = "/" + field
    if case.startswith("protected_use_certificate_"):
        assert certificate is not None
        value = body(certificate)
        field = "not_before" if case.endswith("_lower") else "not_after"
        value[field] = lower if case.endswith("_lower") else upper
        certificate = store(value)
        subject, pointer = certificate, "/" + field
        snapshot_value["certificate_refs"] = [dict(certificate.to_mapping())]
    if case == "protected_use_snapshot_after_signature":
        snapshot_value["issued_at"] = (
            (observed - timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
        )
        pointer = "/issued_at"
    snapshot = store(snapshot_value)
    if case.startswith("protected_use_snapshot_"):
        subject = snapshot
    if case in PROTECTED_USE_MATCHING_CASES:
        return grant, snapshot, certificate, None
    assert subject is not None
    return (
        grant,
        snapshot,
        certificate,
        {
            "code": "invalid_delegation",
            "subject_digest": subject.digest,
            "claim_id": None,
            "pointer": pointer,
            "detail": "Protected authorisation does not precede its ordinary statement."
            if case == "protected_use_snapshot_after_signature"
            else "Protected authorisation does not cover the complete verification interval.",
        },
    )
