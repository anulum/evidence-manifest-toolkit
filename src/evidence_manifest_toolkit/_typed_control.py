# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact digest-only typed control acquisitions

"""Resolve only admitted native statement control links without fabricating missing metadata."""

from dataclasses import dataclass
from typing import Literal

from jsonschema import Draft202012Validator

from ._budget import ReferenceBudget
from ._codecs import DIGEST_PATTERN
from ._errors import InputRefused, ReferenceUnavailable
from ._interfaces import Resolver
from ._json import AcquiredDocument, acquire_document
from ._reference_paths import configuration_refusal
from ._references import reference_bytes
from ._registry import common_schema
from ._results import ReferenceObservation
from ._temporal_semantics import temporal_reasons
from ._values import BlobRef, Digest, Reason


@dataclass(frozen=True, slots=True)
class ControlLink:
    """Retain an actual native lookup's observation and original matching subject.

    Attributes
    ----------
    observation : ReferenceObservation
        Exact containing statement/path/pointer, with no complete reference for missing bytes.
    reference : BlobRef or None
        Actual bounded acquired identity; absent when no bytes were available.
    document : AcquiredDocument or None
        Entire actual source and token custody only for matching native schema-valid bytes.
    missing_digest : str or None
        Exact original digest-only unavailable lookup argument, never a synthetic BlobRef.
    """

    observation: ReferenceObservation
    reference: BlobRef | None
    document: AcquiredDocument | None
    missing_digest: Digest | None


def acquire_control_link(
    digest: Digest,
    *,
    field: Literal["group_certificate_digest", "trust_snapshot_digest"],
    statement_digest: Digest,
    resolver: Resolver,
    budget: ReferenceBudget,
) -> ControlLink:
    """Acquire one fixed native control subject through its exact original digest argument.

    Parameters
    ----------
    digest : str
        Entire valid original declaration; no unavailable length/schema is invented.
    field : {"group_certificate_digest", "trust_snapshot_digest"}
        Only the two admitted typed-control labels on actual supplied group statements.
    statement_digest : str
        Identity of the entire actual containing statement, distinct from its content subject.
    resolver : Resolver
        Explicit caller source; no URL, hidden envelope discovery or alternative basis.
    budget : ReferenceBudget
        Sole cumulative schema/context/content/reference acquisition budget.

    Returns
    -------
    ControlLink
        Whole observation and actual known-schema subject, or exact missing digest identity.
        Structure, bytes and time intervals supply no root/signature/delegation authority.

    Raises
    ------
    ConfigurationError
        The admitted field, digest, resolver return type or fixed packaged schema is invalid.
    InputRefused
        Acquiring the entire native subject exceeds explicit operation bounds.
    """
    if (
        field not in ("group_certificate_digest", "trust_snapshot_digest")
        or DIGEST_PATTERN.fullmatch(digest) is None
    ):
        raise configuration_refusal("/trust/control_envelopes")
    pointer = "/" + field
    path_id = "typed-control:" + field
    cached = budget.digest_bytes(digest)
    maximum = min(
        budget.limits.max_blob_bytes,
        budget.limits.max_json_bytes,
        budget.limits.max_total_reference_bytes - budget.total_bytes
        if cached is None
        else budget.limits.max_blob_bytes,
    )
    if maximum <= 0:
        raise InputRefused(
            Reason(
                "limit_exceeded",
                statement_digest,
                None,
                pointer,
                "Reference acquisition bound exceeded.",
            )
        )
    try:
        data = cached if cached is not None else resolver.resolve_digest(digest, max_bytes=maximum)
    except ReferenceUnavailable as error:
        if error.reference != digest:
            raise ReferenceUnavailable(digest) from error
        failure = Reason(
            "reference_unavailable",
            statement_digest,
            None,
            pointer,
            "Required reference unavailable.",
        )
        return ControlLink(
            ReferenceObservation(
                statement_digest, path_id, pointer, True, None, "unavailable", (failure,)
            ),
            None,
            None,
            digest,
        )
    if not isinstance(data, bytes):
        raise configuration_refusal("/resolver")
    if len(data) > maximum:
        raise InputRefused(
            Reason(
                "limit_exceeded",
                statement_digest,
                None,
                pointer,
                "Reference acquisition bound exceeded.",
            )
        )
    name = "group_certificate" if field == "group_certificate_digest" else "trust_snapshot"
    schema_id = "evidence_manifest_toolkit." + name + ".v1"
    reference = reference_bytes(
        data,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=schema_id,
        limits=budget.limits,
    )
    budget.charge(reference, data, subject=statement_digest, pointer=pointer)
    reasons: list[Reason] = []
    document: AcquiredDocument | None = None
    if reference.digest != digest:
        reasons.append(
            Reason(
                "reference_mismatch",
                statement_digest,
                None,
                pointer,
                "Reference bytes do not match their declared identity.",
            )
        )
    else:
        acquired = acquire_document(data, limits=budget.limits)
        validator = Draft202012Validator(common_schema(name, limits=budget.limits))
        if not isinstance(acquired.value, dict) or not validator.is_valid(acquired.value):
            reasons.append(
                Reason(
                    "invalid_schema", reference.digest, None, "", "Native control shape is invalid."
                )
            )
        else:
            reasons.extend(
                temporal_reasons(acquired.value, schema_id=schema_id, subject=reference.digest)
            )
            if not reasons:
                document = acquired
    return ControlLink(
        ReferenceObservation(
            statement_digest,
            path_id,
            pointer,
            True,
            reference,
            "matched" if not reasons else "mismatched",
            tuple(reasons),
        ),
        reference,
        document,
        None,
    )
