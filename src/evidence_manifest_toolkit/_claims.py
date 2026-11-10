# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole native claim inventory and declared obligations

"""Check native claim relations without manufacturing independence or physical evidence."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

import rfc8785
from jsonschema import Draft202012Validator
from referencing.jsonschema import Schema

from ._codecs import decode_reference
from ._json import JsonValue
from ._reference_paths import configuration_refusal
from ._registry import common_schema
from ._values import BlobRef, Digest, Limits, Reason


@dataclass(frozen=True, slots=True)
class ClaimObligation:
    """Retain per-claim authority obligations rather than accepting their declarations.

    Attributes
    ----------
    claim_id : str
        Unique native claim identity, in the original inventory order.
    subject_digest : str
        Exact declared tested subject, distinct from the containing content identity.
    origin, validation_status : str
        Separate original modalities, never combined into an execution ladder.
    signature_required : bool
        Measured or independently reproduced claims require scoped signatures.
    validation_record : BlobRef or None
        Actual complete declared record; its presence alone does not qualify reproduction.
    validation_record_signature_required : bool
        Independent reproduction also requires the actual record's applicable signature.
    measurement_references : tuple of BlobRef
        Actual target/instrument/acceptance/uncertainty references, without inferred values.
    """

    claim_id: str
    subject_digest: Digest
    origin: str
    validation_status: str
    signature_required: bool
    validation_record: BlobRef | None
    validation_record_signature_required: bool
    measurement_references: tuple[BlobRef, ...]


def claim_inventory(
    document: JsonValue, *, subject: Digest, limits: Limits
) -> tuple[tuple[dict[str, JsonValue], ...], tuple[Reason, ...]]:
    """Validate every native claim against the fixed complete common claim schema.

    Parameters
    ----------
    document : object
        Complete known manifest or protected native claim-inventory payload.
    subject : str
        Actual containing identity for every located claim-shape refusal.
    limits : Limits
        Complete operation bounds used for the independently fixed schema source.

    Returns
    -------
    tuple
        Whole ordered claim mappings and all shape/duplicate-ID reasons. Invalid
        inventories have no accepted projection; the original document stays unchanged.
    """
    if not isinstance(document, dict) or not isinstance(document.get("claims"), list):
        return (), (
            Reason("invalid_claim", subject, None, "/claims", "Native claim inventory is missing."),
        )
    root = common_schema("manifest", limits=limits)
    if isinstance(root, bool):
        raise configuration_refusal("/registry/entries")
    schema = cast(Schema, root["properties"]["claims"])
    validator = Draft202012Validator(root).evolve(schema=schema)
    values = cast(list[JsonValue], document["claims"])
    reasons: list[Reason] = []
    for failure in validator.iter_errors(values):
        pointer = "/claims" + "".join(
            "/" + str(token).replace("~", "~0").replace("/", "~1")
            for token in failure.absolute_path
        )
        claim_id: str | None = None
        if failure.absolute_path and isinstance(failure.absolute_path[0], int):
            index = failure.absolute_path[0]
            candidate = values[index]
            if isinstance(candidate, dict) and isinstance(candidate.get("claim_id"), str):
                claim_id = cast(str, candidate["claim_id"])
        reasons.append(
            Reason(
                "invalid_claim",
                subject,
                claim_id,
                pointer,
                "Native claim violates the common profile.",
            )
        )
    if reasons:
        return (), tuple(reasons)
    claims = tuple(cast(dict[str, JsonValue], value) for value in values)
    identifiers: set[str] = set()
    for index, claim in enumerate(claims):
        identifier = cast(str, claim["claim_id"])
        if identifier in identifiers:
            reasons.append(
                Reason(
                    "invalid_claim",
                    subject,
                    identifier,
                    "/claims/" + str(index) + "/claim_id",
                    "Native claim identifiers are not unique.",
                )
            )
        identifiers.add(identifier)
    return claims, tuple(reasons)


def claim_obligations(
    claims: tuple[dict[str, JsonValue], ...], *, subject: Digest
) -> tuple[ClaimObligation, ...]:
    """Extract the obligations of a completely validated native inventory.

    Parameters
    ----------
    claims : tuple of dict
        Entire schema-valid unique claim population, retaining source order.
    subject : str
        Actual containing identity for reference-declaration diagnostics.

    Returns
    -------
    tuple of ClaimObligation
        Required signature/record/measurement bindings. No field asserts that a
        runner is independent, a target is qualified or an uncertainty model is valid.

    Raises
    ------
    InputRefused
        A supplied record reference fails the unchanged complete BlobRef shape.
    """
    result: list[ClaimObligation] = []
    for index, claim in enumerate(claims):
        pointer = "/claims/" + str(index)
        origin = cast(str, claim["origin"])
        validation = cast(dict[str, JsonValue], claim["validation"])
        status = cast(str, validation["status"])
        scope = cast(dict[str, JsonValue], claim["scope"])
        record = (
            decode_reference(
                validation["record_ref"],
                subject=subject,
                pointer=pointer + "/validation/record_ref",
            )
            if "record_ref" in validation
            else None
        )
        measurement: tuple[BlobRef, ...] = ()
        if origin == "measured":
            fields = cast(dict[str, JsonValue], claim["measurement"])
            measurement = tuple(
                decode_reference(
                    fields[name], subject=subject, pointer=pointer + "/measurement/" + name
                )
                for name in (
                    "target_ref",
                    "instrument_ref",
                    "acceptance_record_ref",
                    "uncertainty_record_ref",
                )
            )
        result.append(
            ClaimObligation(
                cast(str, claim["claim_id"]),
                cast(str, scope["subject_digest"]),
                origin,
                status,
                origin == "measured" or status == "independently_reproduced",
                record,
                status == "independently_reproduced",
                measurement,
            )
        )
    return tuple(result)


def inventory_echo_reason(
    manifest: Mapping[str, JsonValue], payload: Mapping[str, JsonValue], *, subject: Digest
) -> Reason | None:
    """Compare whole ordered inventories through JCS, retaining all native fields.

    Parameters
    ----------
    manifest : Mapping
        Entire validated enclosing native manifest.
    payload : Mapping
        Entire validated payload selected under protected claim_inventory_common.
    subject : str
        Actual manifest identity for its payload binding diagnostic.

    Returns
    -------
    Reason or None
        Exact whole-inventory mismatch, or None for complete ordered canonical equality.
        Foreign claim_boundary records never enter this native echo comparison.
    """
    if "claims" not in manifest or "claims" not in payload:
        return Reason(
            "invalid_claim",
            subject,
            None,
            "/payload_ref",
            "Native payload claim inventory is missing.",
        )
    if rfc8785.dumps(manifest["claims"]) != rfc8785.dumps(payload["claims"]):
        return Reason(
            "invalid_claim",
            subject,
            None,
            "/payload_ref",
            "Whole ordered payload claim inventory differs.",
        )
    return None


def reproduction_identity_reasons(
    claims: tuple[dict[str, JsonValue], ...], *, subject: Digest, producer_principal: str
) -> tuple[Reason, ...]:
    """Refuse declared self-reproduction without promoting an independent label.

    Parameters
    ----------
    claims : tuple of dict
        Complete native schema-valid inventory.
    subject : str
        Actual containing identity.
    producer_principal : str
        Actual containing producer declaration; authenticated record identity is checked later.

    Returns
    -------
    tuple of Reason
        Located contradictions in declared identities. Absence of a contradiction
        does not establish independence or qualify the actual reproduction record.
    """
    reasons: list[Reason] = []
    for index, claim in enumerate(claims):
        validation = cast(dict[str, JsonValue], claim["validation"])
        if (
            validation["status"] == "independently_reproduced"
            and validation["runner_id"] == producer_principal
        ):
            reasons.append(
                Reason(
                    "invalid_claim",
                    subject,
                    cast(str, claim["claim_id"]),
                    "/claims/" + str(index) + "/validation/runner_id",
                    "Producer cannot independently reproduce its own claim.",
                )
            )
    return tuple(reasons)
