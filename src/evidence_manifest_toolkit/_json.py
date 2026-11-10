# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — strict original JSON and canonical bytes

"""Acquire strict JSON before canonicalizing its admitted binary64 values."""

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

import rfc8785

from ._errors import ConfigurationError, InputRefused
from ._values import Limits, Reason

type JsonValue = None | bool | float | str | list[JsonValue] | dict[str, JsonValue]


class _NumberToken(str):
    """Keep a decoded numeric lexeme distinct from an actual JSON string."""


@dataclass(frozen=True, slots=True)
class AcquiredDocument:
    """Retain original source tokens beside the common binary64 interpretation.

    Attributes
    ----------
    raw_bytes : bytes
        Unchanged whole document, including numeric and string spellings.
    value : object
        Complete admitted JSON value for common canonicalization/schema checks.
    number_tokens : Mapping
        Exact numeric lexemes at literal concrete JSON Pointers, captured before conversion.
    """

    raw_bytes: bytes
    value: JsonValue
    number_tokens: Mapping[str, str]


_LIMIT_FIELDS = (
    "max_json_bytes",
    "max_blob_bytes",
    "max_total_reference_bytes",
    "max_reference_count",
    "max_graph_depth",
    "max_json_depth",
)


def validate_limits(limits: Limits) -> None:
    """Require every explicit positive operation bound without boolean coercion.

    Parameters
    ----------
    limits : Limits
        All six caller-supplied acquisition/traversal bounds.

    Raises
    ------
    ConfigurationError
        A bound is not an actual positive integer.
    """
    if not isinstance(limits, Limits):
        raise ConfigurationError(
            Reason(
                "configuration_error", None, None, "/limits", "Limits require positive integers."
            )
        )
    for name in _LIMIT_FIELDS:
        value: object = getattr(limits, name)
        if type(value) is not int or value <= 0:
            raise ConfigurationError(
                Reason(
                    "configuration_error",
                    None,
                    None,
                    "/limits/" + name,
                    "Limits require positive integers.",
                )
            )


def _refuse(code: str) -> InputRefused:
    """Construct the fixed strict acquisition refusal.

    Parameters
    ----------
    code : str
        Actual strict source failure code.

    Returns
    -------
    InputRefused
        Caller-safe reason with no guessed source identity.
    """
    detail = "Input is not valid strict JSON." if code == "invalid_json" else "JSON input refused."
    return InputRefused(Reason(code, None, None, None, detail))


def _number(token: str) -> float:
    """Interpret an original numeric token under the finite binary64 common profile.

    Parameters
    ----------
    token : str
        Exact retained JSON number spelling.

    Returns
    -------
    float
        Finite common interpretation; exact quantity consumers use retained tokens.

    Raises
    ------
    InputRefused
        The token does not admit a finite common number.
    """
    value = float(token)
    if not math.isfinite(value):
        raise _refuse("unsupported_canonical_number")
    return value


def _constant(token: str) -> None:
    """Refuse nonstandard nonfinite JSON constants.

    Parameters
    ----------
    token : str
        Actual parser constant token.

    Raises
    ------
    InputRefused
        Nonfinite constants are never admitted.
    """
    raise _refuse("unsupported_canonical_number")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Acquire whole object pairs while refusing decoded duplicate names.

    Parameters
    ----------
    pairs : list of tuple
        All decoded object names and unchanged parser values.

    Returns
    -------
    dict
        Whole original object population.

    Raises
    ------
    InputRefused
        A decoded object member name repeats.
    """
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _refuse("invalid_json")
        result[key] = value
    return result


def _check_depth(text: str, maximum: int) -> None:
    """Bound source container depth before recursive JSON acquisition.

    Parameters
    ----------
    text : str
        Entire original decoded UTF-8 document.
    maximum : int
        Explicit positive operation depth bound.

    Raises
    ------
    InputRefused
        Source depth or closing-container balance is invalid.
    """
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > maximum:
                raise _refuse("limit_exceeded")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise _refuse("invalid_json")


def _validate_decoded(value: object, pointer: str, number_tokens: dict[str, str]) -> JsonValue:
    """Retain exact numeric tokens while acquiring strict complete common values.

    Parameters
    ----------
    value : object
        Entire original parser value tree.
    pointer : str
        Concrete escaped location of this value.
    number_tokens : dict
        Receives original numeric spellings before binary64 conversion.

    Returns
    -------
    object
        Strict complete JSON value with unchanged array/string order.

    Raises
    ------
    InputRefused
        A value or numeric token violates strict acquisition.
    UnicodeError
        A string/name does not admit strict UTF-8.
    """
    if isinstance(value, _NumberToken):
        number_tokens[pointer] = str(value)
        return _number(value)
    if value is None or isinstance(value, (bool, float)):
        return value
    if isinstance(value, str):
        value.encode("utf-8")
        return value
    if isinstance(value, list):
        return [
            _validate_decoded(child, pointer + "/" + str(index), number_tokens)
            for index, child in enumerate(value)
        ]
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise _refuse("invalid_json")
            key.encode("utf-8")
            escaped = key.replace("~", "~0").replace("/", "~1")
            result[key] = _validate_decoded(child, pointer + "/" + escaped, number_tokens)
        return result
    raise _refuse("invalid_json")


def acquire_document(data: bytes, *, limits: Limits) -> AcquiredDocument:
    """Acquire a bounded strict document while preserving pre-conversion numbers.

    Parameters
    ----------
    data : bytes
        Original bytes; no BOM, duplicate keys or nonfinite extension is accepted.
    limits : Limits
        All six explicit operation bounds, checked before document acquisition.

    Returns
    -------
    AcquiredDocument
        Original bytes, exact numeric tokens and the common binary64 interpretation.
        Source-specific quantity/order guards consume the original tokens, not rounded values.

    Raises
    ------
    ConfigurationError
        A required limit is not a positive integer.
    InputRefused
        Invalid bytes, strings, numbers or exhausted document/depth bounds.
    """
    validate_limits(limits)
    if len(data) > limits.max_json_bytes:
        raise _refuse("limit_exceeded")
    try:
        text = data.decode("utf-8")
        _check_depth(text, limits.max_json_depth)
        decoded: object = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_NumberToken,
            parse_float=_NumberToken,
            parse_constant=_constant,
        )
        number_tokens: dict[str, str] = {}
        value = _validate_decoded(decoded, "", number_tokens)
        return AcquiredDocument(data, value, MappingProxyType(number_tokens))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise _refuse("invalid_json") from error
    except RecursionError as error:
        raise _refuse("limit_exceeded") from error


def parse_document(data: bytes, *, limits: Limits) -> JsonValue:
    """Return common JSON values without treating them as exact source quantities.

    Parameters
    ----------
    data : bytes
        Whole original JSON document, never rewritten.
    limits : Limits
        All explicit positive operation bounds.

    Returns
    -------
    object
        Common finite binary64 JSON interpretation. Quantity/ordering consumers use
        acquire_document's retained raw tokens instead of inferring a source numeric mode.

    Raises
    ------
    ConfigurationError
        Invalid operation limits.
    InputRefused
        Strict JSON parsing or source acquisition fails.
    """
    return acquire_document(data, limits=limits).value


def canonicalize_json(data: bytes, *, limits: Limits) -> bytes:
    """Return RFC8785 canonical bytes of a complete admitted JSON document.

    Parameters
    ----------
    data : bytes
        Complete source JSON, retained unchanged by this operation.
    limits : Limits
        Explicit positive bounds; no hidden document default is selected.

    Returns
    -------
    bytes
        Canonical UTF-8 without BOM or trailing newline.

    Raises
    ------
    ConfigurationError
        Invalid operation limits.
    InputRefused
        Strict parsing or canonical representation refuses the source, including
        exhaustion of the native parser or canonical writer's recursion capacity.
    """
    value = parse_document(data, limits=limits)
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as error:
        raise _refuse("unsupported_canonical_number") from error
    except RecursionError as error:
        raise _refuse("limit_exceeded") from error
