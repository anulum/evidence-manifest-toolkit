# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — finite common semantic composition

"""Apply selected common invariants to whole schema-valid subjects and their bound payloads."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._budget import ByteIdentity
from ._claims import (
    ClaimObligation,
    claim_inventory,
    claim_obligations,
    inventory_echo_reason,
    reproduction_identity_reasons,
)
from ._codecs import decode_bytes, decode_reference
from ._json import AcquiredDocument
from ._schema_resources import StaticSchema
from ._statements import key_id, statement_reasons
from ._temporal_semantics import temporal_reasons
from ._values import Digest, Limits, Reason


@dataclass(frozen=True, slots=True)
class SubjectSemantics:
    """Keep located common refusals and explicit per-claim authority obligations.

    Attributes
    ----------
    reasons : tuple of Reason
        Actual declared common-profile contradictions, without scientific evaluation.
    claim_obligations : tuple of ClaimObligation
        Entire native inventory's signature/record/measurement requirements.
    """

    reasons: tuple[Reason, ...]
    claim_obligations: tuple[ClaimObligation, ...]


def subject_semantics(
    static: StaticSchema,
    document: AcquiredDocument,
    *,
    subject: Digest,
    documents: Mapping[ByteIdentity, AcquiredDocument],
    schemas: Mapping[str, StaticSchema],
    limits: Limits,
) -> SubjectSemantics:
    """Compose common rules using only the independent selected schema/profile.

    Parameters
    ----------
    static : StaticSchema
        Independently selected validated entry, including its finite common profile.
    document : AcquiredDocument
        Entire already schema-valid actual subject with original bytes/token custody.
    subject : str
        Actual containing identity for located refusals.
    documents : Mapping
        Complete matching schema-valid required closure subjects, indexed by byte identity.
    schemas : Mapping
        Complete independently selected static registry; artifact labels select no code.
    limits : Limits
        Entire operation bounds for the fixed native claim schema.

    Returns
    -------
    SubjectSemantics
        Native contradictions and outstanding authority obligations. An empty reason
        population supplies no trusted signature, independent run or domain verdict.

    Raises
    ------
    InputRefused
        An original native field/reference/UTC token fails its explicit source law.
    """
    value = document.value
    entry = static.entry
    if not isinstance(value, dict):
        if entry.common_semantics_id == "evidence_manifest_toolkit.common_json.v1":
            return SubjectSemantics((), ())
        return SubjectSemantics(
            (Reason("invalid_schema", subject, None, "", "Common profile requires an object."),),
            (),
        )
    reasons = list(temporal_reasons(value, schema_id=entry.schema_id, subject=subject))
    obligations: tuple[ClaimObligation, ...] = ()
    if entry.common_semantics_id in (
        "evidence_manifest_toolkit.manifest_common.v1",
        "evidence_manifest_toolkit.claim_inventory_common.v1",
    ):
        claims, failures = claim_inventory(value, subject=subject, limits=limits)
        reasons.extend(failures)
        if not failures:
            obligations = claim_obligations(claims, subject=subject)
            producer = value.get("producer")
            if isinstance(producer, dict) and isinstance(producer.get("principal"), str):
                reasons.extend(
                    reproduction_identity_reasons(
                        claims, subject=subject, producer_principal=cast(str, producer["principal"])
                    )
                )
        if entry.common_semantics_id == "evidence_manifest_toolkit.manifest_common.v1":
            reference = decode_reference(
                value["payload_ref"], subject=subject, pointer="/payload_ref"
            )
            identity = reference.digest, reference.digest_basis, reference.byte_length
            payload = documents.get(identity)
            selected = schemas.get(reference.schema_id or "")
            if (
                payload is not None
                and isinstance(payload.value, dict)
                and selected is not None
                and selected.entry.common_semantics_id
                == "evidence_manifest_toolkit.claim_inventory_common.v1"
            ):
                mismatch = inventory_echo_reason(value, payload.value, subject=subject)
                if mismatch is not None:
                    reasons.append(mismatch)
    elif entry.common_semantics_id == "evidence_manifest_toolkit.signed_statement_common.v1":
        reasons.extend(statement_reasons(value, subject=subject))
    elif entry.common_semantics_id == "evidence_manifest_toolkit.group_certificate_common.v1":
        try:
            public = decode_bytes(cast(str, value["public_key_base64url"]))
        except ValueError:
            reasons.append(
                Reason(
                    "invalid_delegation",
                    subject,
                    None,
                    "/public_key_base64url",
                    "Certificate public key encoding is invalid.",
                )
            )
        else:
            if len(public) != 32:
                reasons.append(
                    Reason(
                        "invalid_delegation",
                        subject,
                        None,
                        "/public_key_base64url",
                        "Certificate public key length is invalid.",
                    )
                )
            elif value["subject_key_id"] != key_id(public):
                reasons.append(
                    Reason(
                        "invalid_delegation",
                        subject,
                        None,
                        "/subject_key_id",
                        "Certificate key identity does not match its public bytes.",
                    )
                )
    return SubjectSemantics(tuple(reasons), obligations)
