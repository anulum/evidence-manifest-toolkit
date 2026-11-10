# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — declared fields without acceptance

"""Display only the fixed recognised declarations of complete strict JSON."""

from collections.abc import Mapping
from typing import cast

from ._codecs import decode_reference
from ._declarations import DECLARED_PATHS
from ._difference import pointer_member, utf16_key
from ._errors import InputRefused
from ._immutable import FrozenJson, freeze_json
from ._json import JsonValue, parse_document
from ._references import reference_bytes
from ._results import Inspection
from ._values import BlobRef, Limits, Reason


def _declared_reference(value: JsonValue) -> BlobRef | None:
    """Recognize only complete reference declarations for diagnostic display.

    Parameters
    ----------
    value : object
        Entire declared value at a known position.

    Returns
    -------
    BlobRef or None
        Whole valid declaration, or no recognized reference; no metadata is invented.
    """
    try:
        return decode_reference(value, subject=None, pointer="")
    except InputRefused:
        return None


def _positions(document: JsonValue, steps: tuple[str | None, ...]) -> list[tuple[str, JsonValue]]:
    """Visit fixed common declaration paths in original instance order.

    Parameters
    ----------
    document : object
        Entire strict document.
    steps : tuple
        Literal member names and explicit array-each positions.

    Returns
    -------
    list of tuple
        Actual concrete pointers and complete corresponding values.
    """
    positions: list[tuple[str, JsonValue]] = [("", document)]
    for step in steps:
        next_positions: list[tuple[str, JsonValue]] = []
        for pointer, value in positions:
            if step is None and isinstance(value, list):
                next_positions.extend(
                    (pointer + "/" + str(i), child) for i, child in enumerate(value)
                )
            elif step is not None and isinstance(value, dict) and step in value:
                next_positions.append((pointer + "/" + pointer_member(step), value[step]))
        positions = next_positions
    return positions


def inspect(content_json: bytes, *, limits: Limits) -> Inspection:
    """Extract recognised declarations without resolving or accepting evidence.

    Parameters
    ----------
    content_json : bytes
        Entire original strict JSON, with no registry or implicit trust input.
    limits : Limits
        Explicit operation bounds for parsing and prospective byte identity.

    Returns
    -------
    Inspection
        Exactly six original fields; acceptance is always not_evaluated.

    Raises
    ------
    ConfigurationError
        Invalid operation limits.
    InputRefused
        Strict source parsing or canonical byte identity cannot be completed.
    """
    document = parse_document(content_json, limits=limits)
    label = document.get("schema_id") if isinstance(document, dict) else None
    schema_id = label if isinstance(label, str) else None
    content_ref = reference_bytes(
        content_json,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=schema_id,
        limits=limits,
    )
    if schema_id is not None and schema_id not in DECLARED_PATHS:
        return Inspection(
            schema_id,
            content_ref,
            (),
            (),
            "not_evaluated",
            (
                Reason(
                    "unknown_schema",
                    content_ref.digest,
                    None,
                    "/schema_id",
                    "Declared schema is not interpreted by this inspection profile.",
                ),
            ),
        )
    claims: tuple[Mapping[str, FrozenJson], ...] = ()
    references: list[tuple[str, BlobRef]] = []
    if schema_id in DECLARED_PATHS and isinstance(document, dict):
        if schema_id == "evidence_manifest_toolkit.manifest.v1":
            declared = document.get("claims")
            if isinstance(declared, list):
                claims = tuple(
                    cast(Mapping[str, FrozenJson], freeze_json(claim))
                    for claim in declared
                    if isinstance(claim, dict)
                )
        for steps in DECLARED_PATHS[cast(str, schema_id)]:
            for pointer, value in _positions(document, steps):
                reference = _declared_reference(value)
                if reference is not None:
                    references.append((pointer, reference))
    return Inspection(
        schema_id,
        content_ref,
        claims,
        tuple(
            reference for _, reference in sorted(references, key=lambda item: utf16_key(item[0]))
        ),
        "not_evaluated",
        (),
    )
