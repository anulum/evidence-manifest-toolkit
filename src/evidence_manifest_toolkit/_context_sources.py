# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete explicit caller-context source acquisition

"""Acquire selected policy and native control bytes without inferring owner approval."""

from dataclasses import dataclass
from typing import Literal

from jsonschema import Draft202012Validator

from ._acquisition import acquire_reference, identity_reason
from ._budget import ReferenceBudget
from ._errors import InputRefused, ReferenceUnavailable
from ._interfaces import Resolver
from ._json import AcquiredDocument, acquire_document
from ._registry import common_schema
from ._temporal_semantics import temporal_reasons
from ._values import BlobRef, Digest, Reason

type NativeControl = Literal["group_certificate", "trust_snapshot", "registry_snapshot"]


@dataclass(frozen=True, slots=True)
class ContextSource:
    """Preserve an entire original caller-selected declaration and acquired source.

    Attributes
    ----------
    reference : BlobRef
        Whole original argument, retaining basis and optional schema metadata unchanged.
    raw_bytes : bytes or None
        Actual bounded bytes; None means the original lookup was genuinely unavailable.
    document : AcquiredDocument or None
        Entire identity-matching object with its original number tokens. For known controls,
        the fixed native schema and local temporal invariants also passed.
    expected_schema_id : str or None
        Independently selected native context, distinct from optional received metadata.
        Local policy configuration is unregistered and has no inferred evidence schema.
    reasons : tuple of Reason
        Actual acquisition/identity/native-shape failures. Empty means neither owner approval
        nor authenticated delegation, reviewed policy, clock or current eligibility.
    """

    reference: BlobRef
    raw_bytes: bytes | None
    document: AcquiredDocument | None
    expected_schema_id: str | None
    reasons: tuple[Reason, ...]


def acquire_context_source(
    reference: BlobRef,
    *,
    expected_control: NativeControl | None,
    resolver: Resolver,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> ContextSource:
    """Read one whole explicitly selected source under the operation's shared bounds.

    Parameters
    ----------
    reference : BlobRef
        Exact caller argument, never completed from an unavailable lookup.
    expected_control : {"group_certificate", "trust_snapshot", "registry_snapshot"} or None
        Fixed native context held by the owning operation. None selects whole local policy
        JSON without assigning a registered evidence type or choosing its policy grammar.
    resolver : Resolver
        Explicit bounded offline source; no hidden envelope discovery or fallback.
    budget : ReferenceBudget
        Sole shared byte/count budget, including static schemas and other selected roots.
    subject : str
        Actual containing subject for this selected lookup's located refusal.
    pointer : str
        Actual original containing field position.

    Returns
    -------
    ContextSource
        Original declaration, actual presence, complete valid object and precise refusals.
        Matching bytes and schemas alone never authenticate owner-pinned root policy.

    Raises
    ------
    ConfigurationError
        The explicit resolver returns a value other than bytes or a fixed native source fails.
    InputRefused
        Metadata agreement or a shared read/count bound is violated.
    """
    expected_schema_id = (
        None
        if expected_control is None
        else "evidence_manifest_toolkit." + expected_control + ".v1"
    )
    try:
        data = acquire_reference(
            reference, resolver=resolver, budget=budget, subject=subject, pointer=pointer
        )
    except ReferenceUnavailable:
        return ContextSource(
            reference,
            None,
            None,
            expected_schema_id,
            (
                Reason(
                    "reference_unavailable",
                    subject,
                    None,
                    pointer,
                    "Required reference unavailable.",
                ),
            ),
        )
    failure = identity_reason(reference, data, budget=budget, subject=subject, pointer=pointer)
    if failure is not None:
        return ContextSource(reference, data, None, expected_schema_id, (failure,))
    try:
        document = acquire_document(data, limits=budget.limits)
    except InputRefused as error:
        reason = error.reason
        return ContextSource(
            reference,
            data,
            None,
            expected_schema_id,
            (Reason(reason.code, reference.digest, None, "", reason.detail),),
        )
    if not isinstance(document.value, dict):
        return ContextSource(
            reference,
            data,
            None,
            expected_schema_id,
            (
                Reason(
                    "invalid_schema",
                    reference.digest,
                    None,
                    "",
                    "Complete context object is required.",
                ),
            ),
        )
    if expected_control is not None:
        if reference.schema_id is not None and reference.schema_id != expected_schema_id:
            return ContextSource(
                reference,
                data,
                None,
                expected_schema_id,
                (
                    Reason(
                        "invalid_schema",
                        subject,
                        None,
                        pointer,
                        "Declared context schema conflicts with its independently selected native type.",
                    ),
                ),
            )
        validator = Draft202012Validator(common_schema(expected_control, limits=budget.limits))
        if not validator.is_valid(document.value):
            return ContextSource(
                reference,
                data,
                None,
                expected_schema_id,
                (
                    Reason(
                        "invalid_schema",
                        reference.digest,
                        None,
                        "",
                        "Native control shape is invalid.",
                    ),
                ),
            )
        reasons = temporal_reasons(
            document.value, schema_id=expected_schema_id or "", subject=reference.digest
        )
        if reasons:
            return ContextSource(reference, data, None, expected_schema_id, reasons)
    return ContextSource(reference, data, document, expected_schema_id, ())
