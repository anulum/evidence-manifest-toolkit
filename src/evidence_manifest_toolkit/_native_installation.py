# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole native implementation descriptor and installed source bodies

"""Compare every actual installed source body without executing or opening received filenames."""

import hashlib
from dataclasses import dataclass
from importlib.resources import files
from typing import cast

from referencing.jsonschema import Schema

from ._budget import ReferenceBudget
from ._context_sources import ContextSource
from ._errors import InputRefused
from ._format_sources import FixedSource
from ._json import JsonValue, acquire_document
from ._reference_paths import configuration_refusal
from ._successor_formats import FixedFormat
from ._values import BlobRef, Digest, Reason

_RESOURCE = "_native_launch_implementation.json"
_METHOD = "whole_native_launch_source_interpretation"


@dataclass(frozen=True, slots=True)
class InstalledSourceFile:
    """Retain a whole known installation body and its actual native pin.

    Attributes
    ----------
    filename : str
        Installation-derived relative name, never a received path or executable selector.
    reference : BlobRef
        Internal actual byte identity for the shared quota; native descriptor rows are
        filename/length/hash data, not invented Common Ref edges.
    raw_bytes : bytes
        Entire unchanged installed body after its exact native pin comparison.
    """

    filename: str
    reference: BlobRef
    raw_bytes: bytes


@dataclass(frozen=True, slots=True)
class NativeInstallation:
    """Keep the complete source descriptor and every actual matched installation body.

    Attributes
    ----------
    descriptor : FixedSource
        Entire exact independently selected raw descriptor and known private data format.
    source_files : tuple of InstalledSourceFile
        All actual maintained package Python/JSON bodies, read in whole under one budget.
        Correspondence supplies no independent installation or native method qualification.
    """

    descriptor: FixedSource
    source_files: tuple[InstalledSourceFile, ...]


def _format() -> FixedFormat:
    """Return the complete fixed native descriptor grammar without a public schema ID.

    Returns
    -------
    FixedFormat
        Known literal descriptor fields and native file pins, with no Ref selector.
    """
    schema: Schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "method_id": {"const": _METHOD},
            "method_version": {"const": "1"},
            "implementation_files": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "filename": {"type": "string", "minLength": 1, "maxLength": 512},
                        "byte_length": {
                            "type": "string",
                            "maxLength": 256,
                            "pattern": "^(0|[1-9][0-9]*)$",
                        },
                        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    },
                    "required": ["filename", "byte_length", "sha256"],
                },
            },
        },
        "required": ["method_id", "method_version", "implementation_files"],
    }
    return FixedFormat(schema, schema, (), None, "native-launch-implementation-source")


def _refuse(subject: Digest) -> InputRefused:
    """Locate an actually unknown whole selected implementation without a weaker retry.

    Parameters
    ----------
    subject : str
        Actual containing independently selected method declaration identity.

    Returns
    -------
    InputRefused
        Fixed whole-source diagnostic at its original implementation field.
    """
    return InputRefused(
        Reason(
            "policy_unavailable",
            subject,
            None,
            "/implementation_ref",
            "Native method implementation sources conflict.",
        )
    )


def _limit(subject: Digest, pointer: str) -> InputRefused:
    """Keep a real installed-resource acquisition bound separate from source eligibility.

    Parameters
    ----------
    subject : str
        Actual containing descriptor identity.
    pointer : str
        Literal original complete native file row.

    Returns
    -------
    InputRefused
        Actual source quota failure without a fabricated method acceptance result.
    """
    return InputRefused(
        Reason(
            "limit_exceeded", subject, None, pointer, "Native installation source bound exceeded."
        )
    )


def _read(name: str, maximum: int) -> bytes:
    """Read only an installation-derived resource with a bounded chunked overread.

    Parameters
    ----------
    name : str
        Literal descriptor or independently enumerated installed resource, not input data.
    maximum : int
        Original finite byte allowance. Chunking also supports arbitrary positive caller bounds.

    Returns
    -------
    bytes
        At most maximum plus one bytes; the owning caller distinguishes mismatch and quota.

    Raises
    ------
    ConfigurationError
        The fixed installed resource cannot be read.
    """
    parts: list[bytes] = []
    remaining = maximum + 1
    try:
        resource = files("evidence_manifest_toolkit").joinpath(*name.split("/"))
        if not resource.is_file():
            raise configuration_refusal("/implementation_ref")
        with resource.open("rb") as handle:
            while remaining:
                chunk = handle.read(min(remaining, 65536))
                if not chunk:
                    break
                parts.append(chunk)
                remaining -= len(chunk)
    except OSError as error:
        raise configuration_refusal("/implementation_ref") from error
    return b"".join(parts)


def _inventory() -> tuple[str, ...]:
    """Enumerate only the two independently installed code/resource namespaces.

    Returns
    -------
    tuple of str
        Entire sorted Python and JSON population, excluding its descriptor's own bytes.
        Other executable layouts refuse rather than silently omitting source bodies.

    Raises
    ------
    ConfigurationError
        Installation discovery fails or contains an unsupported code layout.
    """
    root = files("evidence_manifest_toolkit")
    names: list[str] = []
    try:
        for prefix in ("", "_schemas/"):
            for item in root.joinpath(prefix.rstrip("/")).iterdir():
                if item.is_dir():
                    if item.name not in (
                        {"_schemas", "__pycache__"} if not prefix else {"__pycache__"}
                    ):
                        raise configuration_refusal("/implementation_ref")
                    continue
                name = prefix + item.name
                if name == _RESOURCE:
                    continue
                if item.name.endswith((".so", ".pyd", ".dll", ".dylib", ".pyc")) or (
                    prefix and item.name.endswith(".py")
                ):
                    raise configuration_refusal("/implementation_ref")
                if item.name.endswith((".py", ".json")):
                    names.append(name)
    except OSError as error:
        raise configuration_refusal("/implementation_ref") from error
    return tuple(sorted(names))


def match_native_installation(
    reference: BlobRef, supplied: bytes, *, subject: Digest, budget: ReferenceBudget
) -> NativeInstallation:
    """Match the whole selected descriptor and every entire installed implementing body.

    Parameters
    ----------
    reference : BlobRef
        Original whole independent implementation argument, without code/path dispatch.
    supplied : bytes
        Entire identity-matching original resolver output, retained by NativeMethodInputs.
        The caller closes the complete original source graph before this physical read.
    subject : str
        Containing method declaration identity for precise original source diagnostics.
    budget : ReferenceBudget
        SAME cumulative byte/count allowance, including prior schemas and all native data.

    Returns
    -------
    NativeInstallation
        Whole descriptor and actual known bodies; not source approval or native admission.

    Raises
    ------
    InputRefused
        Its identity/metadata, unknown method or actual original source quota fails.
    ConfigurationError
        Fixed installed data/code is missing, malformed or contradicts its entire population.
    """
    if (
        reference.digest_basis != "raw_bytes"
        or reference.media_type != "application/json"
        or reference.schema_id is not None
    ):
        raise _refuse(subject)
    raw = _read(_RESOURCE, min(int(reference.byte_length), budget.limits.max_blob_bytes))
    if (
        len(raw) != int(reference.byte_length)
        or "sha256:" + hashlib.sha256(raw).hexdigest() != reference.digest
    ):
        raise _refuse(subject)
    budget.charge(reference, raw, subject=subject, pointer="/implementation_ref")
    try:
        document = acquire_document(raw, limits=budget.limits)
    except InputRefused as error:
        if error.reason.code == "limit_exceeded":
            raise
        raise configuration_refusal("/implementation_ref") from error
    selected = _format()
    selected.validate_configuration(document.value, pointer="/implementation_ref")
    value = cast(dict[str, JsonValue], document.value)
    population = cast(list[dict[str, str]], value["implementation_files"])
    names = _inventory()
    if tuple(row["filename"] for row in population) != names:
        raise configuration_refusal("/implementation_ref")
    observed: list[InstalledSourceFile] = []
    for index, (name, row) in enumerate(zip(names, population, strict=True)):
        pointer = "/implementation_files/" + str(index)
        length = int(row["byte_length"])
        source_ref = BlobRef(
            "sha256:" + row["sha256"],
            row["byte_length"],
            "application/schema+json"
            if name.startswith("_schemas/")
            else "text/x-python"
            if name.endswith(".py")
            else "application/json",
            "raw_bytes",
        )
        if length > budget.limits.max_blob_bytes:
            raise _limit(reference.digest, pointer)
        cached = budget.cached(source_ref, subject=reference.digest, pointer=pointer)
        if cached is None and length > budget.limits.max_total_reference_bytes - budget.total_bytes:
            raise _limit(reference.digest, pointer)
        source = _read(name, length)
        if len(source) != length or hashlib.sha256(source).hexdigest() != row["sha256"]:
            raise configuration_refusal("/implementation_ref")
        budget.charge(source_ref, source, subject=reference.digest, pointer=pointer)
        observed.append(InstalledSourceFile(name, source_ref, source))
    context = ContextSource(reference, supplied, document, None, ())
    return NativeInstallation(FixedSource(context, selected), tuple(observed))
