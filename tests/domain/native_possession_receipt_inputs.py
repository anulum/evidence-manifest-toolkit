# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual signed native possession receipt target controls

"""Construct real complete C0 receipts without qualifying their controller or custody."""

from pathlib import Path

from tests.domain.clock_source_inputs import software_manifest_receipt
from tests.domain.test_software_sources import _software_table

from evidence_manifest_toolkit import BlobRef, Limits, reference_bytes


def possession_receipt_input(
    case: str,
    *,
    challenge: BlobRef,
    completion: BlobRef,
    conditions: BlobRef,
    directory: Path,
    limits: Limits,
) -> tuple[list[dict[str, str]], list[dict[str, str]], str | None]:
    """Retain actual receipt order, exact targets and raw/JCS duplicate identities.

    Parameters
    ----------
    case : str
        Named whole public receipt target control, or another possession case.
    challenge, completion : BlobRef
        Entire actual public-seal challenge and final receiver C0.
    conditions : BlobRef
        Explicit original unqualified-source disclosure and static scope.
    directory : Path
        Owned actual byte store, never a substituted production resolver.
    limits : Limits
        Original complete caller allowance.

    Returns
    -------
    tuple
        Whole ordered challenge and receiver receipt references, plus the
        independently expected conflicting challenge-array position when present.
        Actual published-key signatures supply no issuer or receiver admission.
    """
    if not case.startswith("receipt_"):
        return [], [], None
    table = _software_table(conditions, directory, sequence="1")
    changes: dict[str, object] | None = None
    if case == "receipt_target":
        changes = {"content_digest": completion.digest}
    elif case == "receipt_length":
        changes = {"content_byte_length": "1"}
    elif case == "receipt_claim":
        changes = {"claim_ids": ["unclaimed-native-source"]}
    refs = []
    for target, altered in ((challenge, changes), (completion, None)):
        selected, _ = software_manifest_receipt(
            (directory / target.digest[7:]).read_bytes(),
            table=table,
            scope=conditions,
            created_at="2026-06-01T00:00:00Z",
            directory=directory,
            limits=limits,
            statement_changes=altered,
        )
        refs.append(selected)
    ordered = [dict(refs[0].to_mapping())]
    conflict = "ordered_challenge_receipt_refs/0" if changes is not None else None
    if case == "receipt_alias_duplicate":
        raw = (directory / refs[0].digest[7:]).read_bytes()
        alias = reference_bytes(
            raw,
            media_type="application/json",
            digest_basis="raw_bytes",
            schema_id=None,
            limits=limits,
        )
        assert alias != refs[0] and alias.digest == refs[0].digest
        ordered.append(dict(alias.to_mapping()))
        conflict = "ordered_challenge_receipt_refs/1"
    return ordered, [dict(refs[1].to_mapping())], conflict
