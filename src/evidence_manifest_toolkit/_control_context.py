# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — independently known native control reference positions

"""Keep fixed native control expectations separate from optional received schema assertions."""

from ._values import BlobRef


def control_target_schema(parent_schema: str, pointer: str) -> str | None:
    """Select only the original native snapshot's independently known control fields.

    Parameters
    ----------
    parent_schema : str
        Already independently selected and validated containing native schema.
    pointer : str
        Actual concrete selected reference position, never an arbitrary artifact label.

    Returns
    -------
    str or None
        Original native target schema at known control positions, otherwise no expectation.
    """
    if parent_schema != "evidence_manifest_toolkit.trust_snapshot.v1":
        return None
    if pointer == "/registry_ref":
        return "evidence_manifest_toolkit.registry_snapshot.v1"
    if pointer == "/previous_snapshot_ref":
        return "evidence_manifest_toolkit.trust_snapshot.v1"
    prefix = "/group_certificate_refs/"
    index = pointer.removeprefix(prefix)
    if pointer.startswith(prefix) and index and index.isascii() and index.isdecimal():
        return "evidence_manifest_toolkit.group_certificate.v1"
    return None


def references_agree(left: BlobRef, right: BlobRef, *, expected_schema: str) -> bool:
    """Compare full native declarations without converting an omitted schema into a field.

    Parameters
    ----------
    left, right : BlobRef
        Actual original declarations; digest, basis, length and media must match exactly.
    expected_schema : str
        Independently known native type; any nonnull received assertion must match it.

    Returns
    -------
    bool
        Exact identity/media agreement and compatible native assertions. No input is rewritten.
    """
    return (
        (left.digest, left.digest_basis, left.byte_length, left.media_type)
        == (right.digest, right.digest_basis, right.byte_length, right.media_type)
        and left.schema_id in (None, expected_schema)
        and right.schema_id in (None, expected_schema)
    )
