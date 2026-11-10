# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual native entry and independently selected source binding

"""Bind the installed fixed entry method and whole host sources without accepting a Clock."""

import hashlib
import re
from dataclasses import asdict, dataclass
from importlib.resources import files

import rfc8785

from ._acquisition import acquire_reference, identity_reason
from ._budget import ReferenceBudget
from ._clock_values import clock_unavailable
from ._codecs import DECIMAL_PATTERN, decode_reference, encode_bytes
from ._entry_observation import (
    ENVIRONMENT_FIELDS,
    NativeEntryCapture,
    NativeEntryObservation,
    process_start_identity,
)
from ._errors import InputRefused
from ._immutable import thaw_json
from ._interfaces import Resolver
from ._invocation_wire import SuccessorTrust
from ._json import JsonValue, acquire_document
from ._reference_paths import configuration_refusal
from ._references import reference_bytes
from ._values import BlobRef, Digest, Reason

_RESOURCE = "_native_entry_method.json"
_METHOD_FILES = (
    "_entry_observation.py",
    "_entry_binding.py",
    "_verification.py",
    "_verification_inputs.py",
    "_clock_subject.py",
)
_METHOD = "linux_glibc_x86_64_monotonic_raw_timex_v1"
_ORIGIN = "1970-01-01T00:00:00Z"
_CLOCK_POINTER = "/required_evaluation_time_qualification/clock_qualification_ref"
_METHOD_POINTER = "/trust/clock_entry_binding/entry_observation_method_ref"
_ABI = {"long_bits": "64", "pointer_bits": "64", "byte_order": "little", "timex_size": "208"}


@dataclass(frozen=True, slots=True)
class BoundNativeEntry:
    """Keep actual E and the complete source matches separate from Clock admission.

    Attributes
    ----------
    observation : NativeEntryObservation
        Whole actual immutable E/native data; neither kernel status nor tolerance is a verdict.
    method_reference, boot_reference, process_reference, environment_reference : BlobRef
        Entire original independently selected references after actual source/code matching.
    observation_json, observation_reference : bytes, BlobRef
        Whole later native observation with all fields retained and exact integer strings.
        It is not inserted backward into an earlier caller, subject, witness or policy.
    origin : str
        Explicit fixed native-method coordinate choice, not an inferred global wire epoch.
    """

    observation: NativeEntryObservation
    method_reference: BlobRef
    boot_reference: BlobRef
    process_reference: BlobRef
    environment_reference: BlobRef
    observation_json: bytes
    observation_reference: BlobRef
    origin: str


def _installed_bytes(name: str, *, budget: ReferenceBudget, subject: Digest) -> bytes:
    """Read one fixed installed implementation resource within the same operation bounds.

    Parameters
    ----------
    name : str
        Literal known resource name; received filenames never choose a source or executable.
    budget : ReferenceBudget
        Original operation quota, without a separate native-source allowance.
    subject : str
        Whole independently selected enclosing policy.

    Returns
    -------
    bytes
        Entire actual installed file, unchanged.

    Raises
    ------
    ConfigurationError
        A required fixed implementation resource is absent or unreadable.
    InputRefused
        The whole resource exceeds the original blob bound.
    """
    try:
        with files("evidence_manifest_toolkit").joinpath(name).open("rb") as handle:
            raw = handle.read(budget.limits.max_blob_bytes + 1)
    except OSError as error:
        raise configuration_refusal(_METHOD_POINTER) from error
    if len(raw) > budget.limits.max_blob_bytes:
        raise InputRefused(
            Reason(
                "limit_exceeded", subject, None, _METHOD_POINTER, "Native source bound exceeded."
            )
        )
    return raw


def _installed_method(reference: BlobRef, *, budget: ReferenceBudget, subject: Digest) -> None:
    """Match the entire fixed descriptor and every complete implementing source file.

    Parameters
    ----------
    reference : BlobRef
        Whole independently selected method descriptor; it loads no received code.
    budget : ReferenceBudget
        SAME budget for the descriptor and all fixed implementing source resources.
    subject : str
        Whole independently selected enclosing policy for the original Clock refusal.

    Raises
    ------
    ConfigurationError
        The installed descriptor or pinned implementation resource is malformed or changed.
    InputRefused
        The method is unknown, or an actual original quota is exceeded.
    """
    raw = _installed_bytes(_RESOURCE, budget=budget, subject=subject)
    actual = reference_bytes(
        raw,
        media_type="application/json",
        digest_basis="raw_bytes",
        schema_id=None,
        limits=budget.limits,
    )
    if reference != actual:
        raise clock_unavailable(subject, _CLOCK_POINTER)
    budget.charge(reference, raw, subject=subject, pointer=_METHOD_POINTER)
    try:
        value = acquire_document(raw, limits=budget.limits).value
    except InputRefused as error:
        if error.reason.code == "limit_exceeded":
            raise
        raise configuration_refusal(_METHOD_POINTER) from error
    expected = {
        "method_id": _METHOD,
        "coordinate_origin": _ORIGIN,
        "clock_name": "CLOCK_MONOTONIC_RAW",
        "ticks_per_second": {"numerator": "1000000000", "denominator": "1"},
        "abi": _ABI,
        "environment_fields": list(ENVIRONMENT_FIELDS),
    }
    if not isinstance(value, dict) or set(value) != {*expected, "implementation_files"}:
        raise configuration_refusal(_METHOD_POINTER)
    if any(value[name] != item for name, item in expected.items()):
        raise configuration_refusal(_METHOD_POINTER)
    population = value["implementation_files"]
    if not isinstance(population, list) or len(population) != len(_METHOD_FILES):
        raise configuration_refusal(_METHOD_POINTER)
    for index, (name, row) in enumerate(zip(_METHOD_FILES, population, strict=True)):
        if (
            not isinstance(row, dict)
            or set(row) != {"filename", "byte_length", "sha256"}
            or row["filename"] != name
            or not isinstance(row["byte_length"], str)
            or len(row["byte_length"]) > 256
            or DECIMAL_PATTERN.fullmatch(row["byte_length"]) is None
            or not isinstance(row["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
        ):
            raise configuration_refusal(_METHOD_POINTER)
        source = _installed_bytes(name, budget=budget, subject=subject)
        if (
            str(len(source)) != row["byte_length"]
            or hashlib.sha256(source).hexdigest() != row["sha256"]
        ):
            raise configuration_refusal(_METHOD_POINTER)
        source_ref = BlobRef(
            "sha256:" + row["sha256"], row["byte_length"], "text/x-python", "raw_bytes"
        )
        budget.charge(
            source_ref,
            source,
            subject=reference.digest,
            pointer="/implementation_files/" + str(index),
        )


def _selected_bytes(
    reference: BlobRef,
    *,
    media_type: str,
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> bytes:
    """Acquire the whole original raw native binding source and preserve typed failures.

    Parameters
    ----------
    reference : BlobRef
        Original full boot, process or environment source, without invented schema metadata.
    media_type : str
        Exact raw format selected by this fixed native method.
    resolver : Resolver
        Original bounded caller source, with no source/path discovery.
    budget : ReferenceBudget
        SAME already charged schema/policy/native budget.
    subject : str
        Whole independently selected policy.
    pointer : str
        Exact caller binding field.

    Returns
    -------
    bytes
        Whole identity-matching raw source.

    Raises
    ------
    ReferenceUnavailable
        The actual original argument is unavailable.
    InputRefused
        Metadata/identity/quota fails, or this fixed raw source mapping is unsupported.
    """
    if (
        reference.digest_basis != "raw_bytes"
        or reference.schema_id is not None
        or reference.media_type != media_type
    ):
        raise clock_unavailable(subject, _CLOCK_POINTER)
    raw = acquire_reference(
        reference, resolver=resolver, budget=budget, subject=subject, pointer=pointer
    )
    failure = identity_reason(reference, raw, budget=budget, subject=subject, pointer=pointer)
    if failure is not None:
        raise InputRefused(failure)
    return raw


def bind_native_entry(
    entry: NativeEntryCapture | None,
    *,
    trust: SuccessorTrust,
    policy_reference: BlobRef,
    resolver: Resolver,
    budget: ReferenceBudget,
) -> BoundNativeEntry:
    """Match actual entry/boot/process/environment to the whole independent caller selection.

    Parameters
    ----------
    entry : native capture or None
        Actual E captured at the public verifier entry before any source traversal.
    trust : successor context
        Complete independently selected frozen caller and all original binding fields.
    policy_reference : BlobRef
        Whole enclosing policy for the original evaluation-time diagnostic.
    resolver : Resolver
        Caller-owned bounded source for the original whole binding records.
    budget : ReferenceBudget
        SAME operation budget for all implementation/binding/fresh observation bytes.

    Returns
    -------
    BoundNativeEntry
        Whole actual observation, source matches and explicit origin. Full physical
        uncertainty, witness/handoff/window, class and authority predicates remain required.

    Raises
    ------
    InputRefused
        E/domain/source binding is unavailable or conflicts, or a shared bound fails.
    ConfigurationError
        An installed fixed method resource is missing or changed.
    ReferenceUnavailable
        A whole originally selected boot/process/environment source is absent.
    """
    subject = policy_reference.digest
    if not isinstance(entry, NativeEntryObservation) or not (
        0 <= entry.entry_ticks <= entry.acquired_through_ticks and entry.resolution_ns > 0
    ):
        raise clock_unavailable(subject, _CLOCK_POINTER)
    binding = trust.clock_entry_binding
    selected = {
        name: decode_reference(
            thaw_json(binding[name]), subject=subject, pointer="/trust/clock_entry_binding/" + name
        )
        for name in (
            "entry_observation_method_ref",
            "boot_domain_ref",
            "process_start_identity_ref",
            "implementation_environment_ref",
        )
    }
    _installed_method(selected["entry_observation_method_ref"], budget=budget, subject=subject)
    sources = {
        name: _selected_bytes(
            ref,
            media_type="application/json"
            if name == "implementation_environment_ref"
            else "text/plain",
            resolver=resolver,
            budget=budget,
            subject=subject,
            pointer="/trust/clock_entry_binding/" + name,
        )
        for name, ref in selected.items()
        if name != "entry_observation_method_ref"
    }
    if sources["boot_domain_ref"] != entry.boot_bytes:
        raise clock_unavailable(subject, _CLOCK_POINTER)
    try:
        process = process_start_identity(sources["process_start_identity_ref"])
    except ValueError as error:
        raise clock_unavailable(subject, _CLOCK_POINTER) from error
    if process != (entry.process_id, entry.process_start_ticks):
        raise clock_unavailable(subject, _CLOCK_POINTER)
    environment_ref = selected["implementation_environment_ref"]
    try:
        environment = acquire_document(
            sources["implementation_environment_ref"], limits=budget.limits
        )
    except InputRefused as error:
        reason = error.reason
        raise InputRefused(
            Reason(reason.code, environment_ref.digest, None, "", reason.detail)
        ) from error
    if environment.value != acquire_document(entry.environment_json, limits=budget.limits).value:
        raise clock_unavailable(subject, _CLOCK_POINTER)
    values: dict[str, JsonValue] = {
        name: encode_bytes(value)
        if isinstance(value, bytes)
        else str(value)
        if type(value) is int
        else value
        for name, value in asdict(entry).items()
    }
    raw = rfc8785.dumps(values)
    observed_ref = reference_bytes(
        raw,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=None,
        limits=budget.limits,
    )
    budget.charge(observed_ref, raw, subject=subject, pointer=_CLOCK_POINTER)
    return BoundNativeEntry(
        entry,
        selected["entry_observation_method_ref"],
        selected["boot_domain_ref"],
        selected["process_start_identity_ref"],
        environment_ref,
        raw,
        observed_ref,
        _ORIGIN,
    )
