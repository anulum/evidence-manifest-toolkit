# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — literal typed reference selection

"""Expand reviewed selectors after complete schema validation, retaining every edge."""

import re
from dataclasses import dataclass

from ._difference import pointer_member
from ._errors import ConfigurationError, InputRefused
from ._json import JsonValue
from ._registry_types import ReferencePath, ReferenceRequirement
from ._values import Digest, Reason

_INDEX = re.compile(r"0|[1-9][0-9]*")


def configuration_refusal(pointer: str) -> ConfigurationError:
    """Locate invalid caller configuration without artifact or backend diagnostics.

    Parameters
    ----------
    pointer : str
        Actual local configuration field.

    Returns
    -------
    ConfigurationError
        Fixed safe reason with null artifact identity.
    """
    return ConfigurationError(
        Reason("configuration_error", None, None, pointer, "Invalid local configuration.")
    )


def validate_path(path: ReferencePath, *, pointer: str) -> None:
    """Check the closed selector grammar independently of received evidence.

    Parameters
    ----------
    path : ReferencePath
        Caller-selected immutable selector with literal members and array steps.
    pointer : str
        Actual position of this selector in the caller configuration.

    Raises
    ------
    ConfigurationError
        An unknown step, malformed index, reserved identifier or allowance is supplied.
    """
    if (
        not isinstance(path.path_id, str)
        or not path.path_id
        or path.path_id.startswith("typed-control:")
    ):
        raise configuration_refusal(pointer + "/path_id")
    if path.absent not in ("schema_optional", "refuse"):
        raise configuration_refusal(pointer + "/absent")
    if path.null not in ("schema_optional", "refuse"):
        raise configuration_refusal(pointer + "/null")
    if path.requirement not in ("when_present", "policy_optional"):
        raise configuration_refusal(pointer + "/requirement")
    for index, step in enumerate(path.steps):
        location = pointer + "/steps/" + str(index)
        kind = step.get("kind")
        if kind == "member":
            if set(step) != {"kind", "name"} or not isinstance(step["name"], str):
                raise configuration_refusal(location)
            try:
                step["name"].encode("utf-8")
            except UnicodeError as error:
                raise configuration_refusal(location + "/name") from error
        elif kind == "index":
            token = step.get("index")
            if (
                set(step) != {"kind", "index"}
                or not isinstance(token, str)
                or len(token) > 256
                or _INDEX.fullmatch(token) is None
            ):
                raise configuration_refusal(location)
        elif kind != "each" or set(step) != {"kind"}:
            raise configuration_refusal(location)


def pointer_tokens(pointer: str) -> tuple[str, ...]:
    """Decode literal RFC6901 tokens without URI decoding or Unicode normalization.

    Parameters
    ----------
    pointer : str
        JSON string pointer, with empty string selecting the root.

    Returns
    -------
    tuple of str
        Exact decoded member or index tokens.

    Raises
    ------
    ValueError
        Pointer syntax or a tilde escape is outside the selected profile.
    """
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
        raise ValueError("Invalid JSON Pointer.")
    pointer.encode("utf-8")
    if not pointer:
        return ()
    tokens = pointer[1:].split("/")
    if any(re.search(r"~(?:[^01]|$)", token) for token in tokens):
        raise ValueError("Invalid JSON Pointer escape.")
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in tokens)


def selector_contains(path: ReferencePath, pointer: str) -> bool:
    """Check membership of a literal concrete pointer in the exact selected path.

    Parameters
    ----------
    path : ReferencePath
        Whole independently known typed selector.
    pointer : str
        Literal complete RFC6901 instance, with no wildcard interpretation.

    Returns
    -------
    bool
        Whether every actual token matches the selected member/index/each steps.
    """
    try:
        tokens = pointer_tokens(pointer)
    except (ValueError, UnicodeError):
        return False
    if len(tokens) != len(path.steps):
        return False
    for token, step in zip(tokens, path.steps, strict=True):
        if step["kind"] == "member" and token != step["name"]:
            return False
        if step["kind"] == "index" and token != step["index"]:
            return False
        if step["kind"] == "each" and _INDEX.fullmatch(token) is None:
            return False
    return True


@dataclass(frozen=True, slots=True)
class SelectedPosition:
    """Preserve a concrete selected position, including explicit absence and null.

    Attributes
    ----------
    path_id, pointer : str
        Reviewed selector identity and actual literal location in the subject.
    value : object
        Actual JSON value, or None for a position that was absent.
    present : bool
        Distinguish an absent position from a supplied JSON null.
    required : bool
        Present declared closure or a selected policy override needs this position.
    """

    path_id: str
    pointer: str
    value: JsonValue
    present: bool
    required: bool


def select_positions(
    document: JsonValue,
    path: ReferencePath,
    *,
    subject_digest: Digest,
    requirements: tuple[ReferenceRequirement, ...],
) -> tuple[SelectedPosition, ...]:
    """Walk one reviewed path in a complete, previously schema-validated subject.

    Parameters
    ----------
    document : object
        Entire parsed subject; schema and selector compatibility are checked first.
    path : ReferencePath
        Independently selected path with literal member, fixed index and array-each steps.
    subject_digest : str
        Actual containing subject for located structural and required-scope refusals.
    requirements : tuple of ReferenceRequirement
        Already validated overrides for this exact subject, schema and path.

    Returns
    -------
    tuple of SelectedPosition
        Every observed instance in source order, retaining optional absence/null.

    Raises
    ------
    InputRefused
        A wrong parent type, disallowed absence/null or required no-match occurs.
    """
    requested: set[str] = set()
    require_all = False
    for requirement in requirements:
        if requirement.subject_digest == subject_digest and requirement.path_id == path.path_id:
            if requirement.instances is None:
                require_all = True
            else:
                requested.update(requirement.instances)

    def refuse(pointer: str, code: str = "scope_missing") -> InputRefused:
        """Locate an actual selected-path failure on its containing subject.

        Parameters
        ----------
        pointer : str
            Concrete invalid or absent instance position.
        code : str
            Actual selector failure code.

        Returns
        -------
        InputRefused
            Located required-position refusal without inferred reference metadata.
        """
        return InputRefused(
            Reason(
                code,
                subject_digest,
                None,
                pointer,
                "Required reference position is invalid or absent.",
            )
        )

    pending: list[tuple[str, JsonValue, int, bool]] = [("", document, 0, True)]
    selected: list[SelectedPosition] = []
    found: set[str] = set()
    while pending:
        pointer, value, offset, present = pending.pop()
        overridden = require_all or any(
            instance == pointer or instance.startswith(pointer + "/") for instance in requested
        )
        if not present:
            if path.absent == "refuse" or overridden:
                raise refuse(pointer)
            selected.append(SelectedPosition(path.path_id, pointer, None, False, False))
            continue
        if value is None:
            if path.null == "refuse" or overridden:
                raise refuse(pointer)
            selected.append(SelectedPosition(path.path_id, pointer, None, True, False))
            if offset == len(path.steps):
                found.add(pointer)
            continue
        if offset == len(path.steps):
            required = overridden or path.requirement == "when_present"
            selected.append(SelectedPosition(path.path_id, pointer, value, True, required))
            found.add(pointer)
            continue
        step = path.steps[offset]
        kind = step["kind"]
        if kind == "member":
            if not isinstance(value, dict):
                raise refuse(pointer, "invalid_schema")
            name = step["name"]
            pending.append(
                (pointer + "/" + pointer_member(name), value.get(name), offset + 1, name in value)
            )
        elif kind == "index":
            if not isinstance(value, list):
                raise refuse(pointer, "invalid_schema")
            index = int(step["index"])
            exists = index < len(value)
            pending.append(
                (
                    pointer + "/" + step["index"],
                    value[index] if exists else None,
                    offset + 1,
                    exists,
                )
            )
        else:
            if not isinstance(value, list):
                raise refuse(pointer, "invalid_schema")
            if not value and require_all:
                raise refuse(pointer)
            pending.extend(
                (pointer + "/" + str(index), value[index], offset + 1, True)
                for index in range(len(value) - 1, -1, -1)
            )
    if require_all and not found:
        raise refuse("")
    if requested - found:
        raise refuse(sorted(requested - found)[0])
    return tuple(selected)
