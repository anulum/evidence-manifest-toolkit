# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact diagnostic JSON differences

"""Compare JSON kinds, ordered arrays and envelopes without an acceptance oracle."""

from ._json import JsonValue, parse_document
from ._references import reference_bytes
from ._results import Difference
from ._values import BlobRef, Limits


def pointer_member(name: str) -> str:
    """Escape one literal object member for its concrete RFC6901 pointer.

    Parameters
    ----------
    name : str
        Exact decoded member name.

    Returns
    -------
    str
        Inverse tilde/slash escaping without normalization.
    """
    return name.replace("~", "~0").replace("/", "~1")


def utf16_key(value: str) -> bytes:
    """Order decoded strings by exact UTF16 code units.

    Parameters
    ----------
    value : str
        Original strict Unicode string.

    Returns
    -------
    bytes
        Big-endian UTF16 ordering key with no Unicode normalization.
    """
    return value.encode("utf-16-be")


def _content_reference(data: bytes, limits: Limits) -> BlobRef:
    """Identify whole canonical comparison content without selecting an evidence schema.

    Parameters
    ----------
    data : bytes
        Entire original comparison input, acquired under the strict common profile.
    limits : Limits
        Entire operation bounds.

    Returns
    -------
    BlobRef
        Exact canonical diagnostic identity with no selected evidence schema.
    """
    return reference_bytes(
        data,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=None,
        limits=limits,
    )


def _changes(left: JsonValue, right: JsonValue) -> tuple[str, ...]:
    """Collect structural value differences with JSON-kind and array-order fidelity.

    Parameters
    ----------
    left, right : object
        Entire admitted common JSON values.

    Returns
    -------
    tuple of str
        Distinct changed pointers in UTF16 order; length/type changes retain their parent.
    """
    changed: set[str] = set()
    pending: list[tuple[str, JsonValue, JsonValue]] = [("", left, right)]
    while pending:
        pointer, a, b = pending.pop()
        if type(a) is not type(b):
            changed.add(pointer)
        elif isinstance(a, dict) and isinstance(b, dict):
            for key in a.keys() | b.keys():
                child_pointer = pointer + "/" + pointer_member(key)
                if key not in a or key not in b:
                    changed.add(child_pointer)
                else:
                    pending.append((child_pointer, a[key], b[key]))
        elif isinstance(a, list) and isinstance(b, list):
            if len(a) != len(b):
                changed.add(pointer)
            for index, (x, y) in enumerate(zip(a, b, strict=False)):
                pending.append((pointer + "/" + str(index), x, y))
        elif a != b:
            changed.add(pointer)
    return tuple(sorted(changed, key=utf16_key))


def diff(
    left_json: bytes,
    right_json: bytes,
    *,
    limits: Limits,
    left_envelopes: tuple[bytes, ...] = (),
    right_envelopes: tuple[bytes, ...] = (),
) -> Difference:
    """Compare complete strict canonical content and ordered receipt identities.

    Parameters
    ----------
    left_json, right_json : bytes
        Entire original JSON documents; retrieval whitespace is not identity.
    limits : Limits
        Explicit operation bounds used for every supplied document.
    left_envelopes, right_envelopes : tuple of bytes
        Explicit detached JSON envelope inputs in their original order.

    Returns
    -------
    Difference
        All eight original diagnostic fields, with acceptance not_evaluated.

    Raises
    ------
    ConfigurationError
        Invalid operation limits.
    InputRefused
        Any supplied content or envelope violates the strict JSON byte profile.
    """
    left = parse_document(left_json, limits=limits)
    right = parse_document(right_json, limits=limits)
    left_ref = _content_reference(left_json, limits)
    right_ref = _content_reference(right_json, limits)
    left_receipts = tuple(_content_reference(envelope, limits) for envelope in left_envelopes)
    right_receipts = tuple(_content_reference(envelope, limits) for envelope in right_envelopes)
    return Difference(
        left_ref,
        right_ref,
        left_ref == right_ref,
        _changes(left, right),
        left_receipts,
        right_receipts,
        left_receipts == right_receipts,
        "not_evaluated",
    )
