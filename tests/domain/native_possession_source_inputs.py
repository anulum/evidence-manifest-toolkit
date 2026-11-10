# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole possession source and manifest contradiction inputs

"""Retain complete original C0 inputs while changing one independently named source condition."""

import json
from pathlib import Path

from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef, Limits, canonicalize_json, reference_bytes


def possession_source_input(
    case: str,
    result: dict[str, object],
    *,
    issuance: BlobRef,
    directory: Path,
    limits: Limits,
) -> tuple[dict[str, object], tuple[str, BlobRef | None, str, str] | None, BlobRef | None]:
    """Alter a whole selected source without substituting a verifier or accepted result.

    Parameters
    ----------
    case : str
        Explicit public missing, unknown-schema or complete-C0 contradiction.
    result : dict
        Whole earlier possession result before its immutable identity is materialised.
    issuance : BlobRef
        Actual original challenge issuance source already used by public seal.
    directory : Path
        Owned whole byte store.
    limits : Limits
        Entire independently selected public operation bounds.

    Returns
    -------
    tuple
        Whole result and an independent code/source/field/detail oracle, or the
        exact missing reference. A None oracle source means the later whole result
        identity. This is expected failure data, never a production admitted value.
    """
    result = dict(result)
    oracle: tuple[str, BlobRef | None, str, str] | None = None
    missing: BlobRef | None = None
    if case == "challenge_manifest_other":
        result["challenge_manifest_ref"] = result["receiver_completion_manifest_ref"]
        oracle = (
            "invalid_claim",
            None,
            "challenge_manifest_ref",
            "Native key-possession sources conflict.",
        )
    elif case == "limitations_schema":
        unknown = _stored(
            {"native_possession_limitations": "Unqualified source control."},
            directory,
            schema_id="uninstalled.native_possession_limitations.v1",
        )
        result["limitations_ref"] = dict(unknown.to_mapping())
        oracle = ("unknown_schema", None, "limitations_ref", "Selected schema is not known.")
    elif case == "limitations_missing":
        missing = _native_source(
            b"Missing native possession limitations source.", directory, "text/plain"
        )
        result["limitations_ref"] = dict(missing.to_mapping())
    elif case == "issuance_missing":
        missing = issuance
    elif case == "challenge_manifest_invalid":
        original = BlobRef.from_mapping(_object(result["challenge_manifest_ref"]))
        whole = _object(json.loads((directory / original.digest[7:]).read_bytes()))
        whole["unexpected"] = False
        raw = canonicalize_json(json.dumps(whole).encode(), limits=limits)
        invalid = reference_bytes(
            raw,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id="evidence_manifest_toolkit.manifest.v1",
            limits=limits,
        )
        (directory / invalid.digest[7:]).write_bytes(raw)
        result["challenge_manifest_ref"] = dict(invalid.to_mapping())
        oracle = ("invalid_schema", invalid, "", "Input violates its selected schema.")
    if missing is not None:
        (directory / missing.digest[7:]).unlink()
    return result, oracle, missing
