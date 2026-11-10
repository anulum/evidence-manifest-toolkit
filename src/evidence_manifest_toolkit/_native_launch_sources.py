# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete native launch source and declared identity joins

"""Interpret whole captured launcher data without reopening historical paths or admitting identity."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._acquisition import acquire_reference
from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._errors import InputRefused
from ._format_sources import FixedSource
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue, acquire_document
from ._native_launch_format import native_launch_format
from ._reference_paths import configuration_refusal
from ._subject_formats import SubjectFormat, subject_format_reasons
from ._values import BlobRef, Reason, Utc

_POSITIVE = re.compile(r"[1-9][0-9]*")
_FILE_SIZE = re.compile(r"-1|0|[1-9][0-9]*")


@dataclass(frozen=True, slots=True)
class NativeLaunchSource:
    """Retain the entire actual launcher source and exact parsed civil time.

    Attributes
    ----------
    reference : BlobRef
        Original whole raw-byte argument, retaining every actual metadata assertion.
    document : AcquiredDocument
        Complete strict source, unchanged raw bytes and all original number tokens.
        Empty vendor/key and unavailable file/process facts remain exactly recorded.
        Neither source shape nor a consistent declaration authenticates a process,
        vendor, key, custody, controller, run, historical event or identity class.
    recorded_at : Utc
        Original Common-valid timestamp; this value supplies no Clock qualification.
    """

    reference: BlobRef
    document: AcquiredDocument
    recorded_at: Utc


def acquire_native_launch_source(
    binding: FixedSource,
    *,
    method: FixedSource,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> NativeLaunchSource:
    """Read all native launch fields and check exact declared principal/vendor correspondence.

    Parameters
    ----------
    binding : FixedSource
        Complete producer or runner identity after original source closure and whole
        policy/custody/class relations. No test-created accepted value is consumed.
    method : FixedSource
        Whole independently selected launcher declaration; received bindings choose
        no code, external process, observer, catalogue or provider.
    formats : Mapping
        Original validated structural lookup for any actual Ref schema assertion.
    resolver : Resolver
        Sole bounded original-byte source. Historical filenames/PIDs stay data.
    budget : ReferenceBudget
        SAME original invocation quota, including the complete rule/Clock/record graphs.

    Returns
    -------
    NativeLaunchSource
        Entire known raw source and actual declaration correspondence. Required source,
        implementation/environment/qualification, possession, observation, custody,
        time and class admission remain separate original method obligations.

    Raises
    ------
    ConfigurationError
        The selected identity or procedure requires an unimplemented observer method.
    InputRefused
        Whole source/schema/numeric lexeme/Common UTC or exact declared identity
        correspondence fails, preserving the actual containing source and field.
    ReferenceUnavailable
        The complete original selected source is genuinely unavailable.
    """
    subject = binding.source.reference.digest
    identity = cast(dict[str, JsonValue], cast(AcquiredDocument, binding.source.document).value)
    if identity["identity_class"] != "declared_by_launcher_under_the_seat_account":
        raise configuration_refusal("/identity_class")
    launcher = decode_reference(
        identity["observer_or_launcher_ref"], subject=subject, pointer="/observer_or_launcher_ref"
    )
    if launcher != method.source.reference:
        raise InputRefused(
            Reason(
                "invalid_claim",
                subject,
                None,
                "/observer_or_launcher_ref",
                "Native launch source conflicts with its declared identity.",
            )
        )
    selected = native_launch_format(method, resolver=resolver, budget=budget)
    reference = decode_reference(
        identity["actual_launch_or_declared_source_ref"],
        subject=subject,
        pointer="/actual_launch_or_declared_source_ref",
    )
    if reference.digest_basis != "raw_bytes":
        raise InputRefused(
            Reason(
                "invalid_schema",
                subject,
                None,
                "/actual_launch_or_declared_source_ref",
                "Native launch source requires original raw bytes.",
            )
        )
    raw = acquire_reference(
        reference,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer="/actual_launch_or_declared_source_ref",
    )
    try:
        document = acquire_document(raw, limits=budget.limits)
    except InputRefused as error:
        reason = error.reason
        raise InputRefused(
            Reason(reason.code, reference.digest, None, "", reason.detail)
        ) from error
    failures = subject_format_reasons(
        selected,
        document,
        reference,
        formats=formats,
        subject=subject,
        pointer="/actual_launch_or_declared_source_ref",
    )
    if failures:
        raise InputRefused(failures[0])
    value = cast(dict[str, JsonValue], document.value)
    process = cast(dict[str, JsonValue], value["process"])
    number_paths = (
        ("/command_words", _POSITIVE),
        ("/launcher_pid", _POSITIVE),
        ("/process/pid", _POSITIVE),
        ("/executable/size", _FILE_SIZE),
    ) + (() if process["image"] is None else (("/process/image/size", _FILE_SIZE),))
    for pointer, pattern in number_paths:
        if pattern.fullmatch(document.number_tokens.get(pointer, "")) is None:
            raise InputRefused(
                Reason(
                    "invalid_schema",
                    reference.digest,
                    None,
                    pointer,
                    "Native launch integer token is invalid.",
                )
            )
    try:
        recorded_at = Utc(value["recorded_at"])
    except InputRefused as error:
        reason = error.reason
        raise InputRefused(
            Reason(reason.code, reference.digest, None, "/recorded_at", reason.detail)
        ) from error
    for native_field, identity_field in (
        ("seat", "principal_id"),
        ("declared_vendor", "vendor_id"),
    ):
        if (native_field == "seat" or value[native_field] != "") and (
            value[native_field] != identity[identity_field]
        ):
            raise InputRefused(
                Reason(
                    "invalid_claim",
                    subject,
                    None,
                    "/" + identity_field,
                    "Native launch source conflicts with its declared identity.",
                )
            )
    return NativeLaunchSource(reference, document, recorded_at)
