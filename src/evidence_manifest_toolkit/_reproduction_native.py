# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole independent validation native evidence

"""Check full validation targets and runner equations without admitting reproduction."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._acquisition import acquire_reference
from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._content import CompleteContent, prepare_content
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._reproduction_receipt_sources import (
    ValidationReceiptSources,
    acquire_validation_receipt_sources,
)
from ._schema_resources import StaticSchema
from ._signature_provider import initialize_verifier
from ._statements import key_id
from ._subject_formats import SubjectFormat
from ._successor_envelopes import parse_successor_envelope
from ._values import BlobRef, Reason


@dataclass(frozen=True, slots=True)
class ReproductionNativeEvidence:
    """Retain whole validation content and actual mathematical evidence.

    Attributes
    ----------
    content : CompleteContent or None
        Entire explicitly selected validation C0 with its common semantics and graph.
    runner_key_reference, runner_key : BlobRef or None, bytes or None
        Whole actual runner source and unchanged data, without enrolled key custody.
    receipts : tuple of ValidationReceiptSources
        Ordered whole native statements, certificates, graphs and parsed receipts. A returned
        result has checked every equation;
        it supplies no certificate, history, identity, run, Clock or class acceptance.
    """

    content: CompleteContent | None
    runner_key_reference: BlobRef | None
    runner_key: bytes | None
    receipts: tuple[ValidationReceiptSources, ...]


def check_reproduction_native(
    record: FixedSource,
    body: FixedSource,
    producer: FixedSource,
    runner: FixedSource,
    *,
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> ReproductionNativeEvidence:
    """Bind ordered receipts to the entire validation C0 and actual distinct runner key.

    Parameters
    ----------
    record, body, producer, runner : FixedSource
        Entire schema-valid earlier sources after their complete reference closure and
        declared relation checks. No supplied class label establishes an actual run.
    formats : Mapping
        Already selected native and original static schemas, without registry mutation.
    resolver : Resolver
        Sole bounded original source; cached exact references retain their byte identity.
    budget : ReferenceBudget
        SAME invocation allowance, including every original and earlier source graph.

    Returns
    -------
    ReproductionNativeEvidence
        Full sources and mathematical evidence only. Earlier certificate authority,
        temporal reconstruction and all independent execution predicates remain required.

    Raises
    ------
    InputRefused
        Actual source, full target, claim/body citation, key or native equation conflicts.
    ReferenceUnavailable
        An original selected required source or descendant is genuinely unavailable.
    ConfigurationError
        An actual required equation lacks the conforming maintained verifier.
    """

    def value(source: FixedSource) -> dict[str, JsonValue]:
        """Read the complete validated source without discarding any received field."""
        return cast(dict[str, JsonValue], cast(AcquiredDocument, source.source.document).value)

    def refuse(source: FixedSource, field: str) -> None:
        """Locate a necessary independent-source contradiction without echoing input."""
        raise InputRefused(
            Reason(
                "invalid_claim",
                source.source.reference.digest,
                cast(str, value(body)["claim_id"]),
                "/" + field,
                "Independent validation sources conflict.",
            )
        )

    def key(source: FixedSource, field: str) -> tuple[BlobRef | None, bytes | None]:
        """Read only an explicit complete key source through the original shared budget."""
        declared = value(source)[field]
        if declared is None:
            return None, None
        reference = decode_reference(
            declared, subject=source.source.reference.digest, pointer="/" + field
        )
        return reference, acquire_reference(
            reference,
            resolver=resolver,
            budget=budget,
            subject=source.source.reference.digest,
            pointer="/" + field,
        )

    _, producer_key = key(producer, "declared_public_key_ref")
    _, declared_runner_key = key(runner, "declared_public_key_ref")
    runner_reference, runner_key = key(body, "runner_actual_key_ref")
    if (
        producer_key is not None
        and declared_runner_key is not None
        and producer_key == declared_runner_key
    ):
        refuse(runner, "declared_public_key_ref")
    record_value = value(record)
    receipt_references = cast(list[JsonValue], record_value["ordered_native_receipt_refs"])
    declaration = record_value["validation_C0_statement_ref"]
    if declaration is None:
        if receipt_references:
            refuse(record, "validation_C0_statement_ref")
        return ReproductionNativeEvidence(None, runner_reference, runner_key, ())
    reference = decode_reference(
        declaration,
        subject=record.source.reference.digest,
        pointer="/validation_C0_statement_ref",
    )
    raw = acquire_reference(
        reference,
        resolver=resolver,
        budget=budget,
        subject=record.source.reference.digest,
        pointer="/validation_C0_statement_ref",
    )
    content = prepare_content(
        raw,
        schema_id="evidence_manifest_toolkit.manifest.v1",
        schemas={
            name: schema for name, schema in formats.items() if isinstance(schema, StaticSchema)
        },
        formats=formats,
        requirements=(),
        resolver=resolver,
        budget=budget,
    )
    if content.closure.missing_references:
        raise ReferenceUnavailable(content.closure.missing_references[0])
    if content.reasons:
        raise InputRefused(content.reasons[0])
    body_reference = body.source.reference
    if not any(
        observed.reference is not None
        and observed.reference.digest == body_reference.digest
        and observed.reference.digest_basis == body_reference.digest_basis
        and observed.reference.byte_length == body_reference.byte_length
        and observed.outcome == "matched"
        for observed in content.closure.observations
    ):
        refuse(record, "validation_C0_statement_ref")
    if receipt_references and (runner_key is None or len(runner_key) != 32):
        refuse(body, "runner_actual_key_ref")
    receipts: list[ValidationReceiptSources] = []
    for index, item in enumerate(receipt_references):
        receipt_reference = decode_reference(
            item,
            subject=record.source.reference.digest,
            pointer="/ordered_native_receipt_refs/" + str(index),
        )
        receipt_raw = acquire_reference(
            receipt_reference,
            resolver=resolver,
            budget=budget,
            subject=record.source.reference.digest,
            pointer="/ordered_native_receipt_refs/" + str(index),
        )
        envelope = parse_successor_envelope(
            receipt_raw, context="ordinary_statement", budget=budget
        )
        statement = envelope.statement.value
        for field, expected in (
            ("content_digest", content.content_ref.digest),
            ("content_byte_length", content.content_ref.byte_length),
            ("content_schema_id", content.content_ref.schema_id),
        ):
            if statement[field] != expected:
                raise InputRefused(
                    Reason(
                        "scope_missing",
                        envelope.reference.digest,
                        None,
                        "/statement/" + field,
                        "Validation receipt does not bind its whole validation manifest.",
                    )
                )
        claims = {claim.claim_id for claim in content.content_claim_obligations}
        included = cast(tuple[str, ...], statement["claim_ids"])
        if not set(included) <= claims:
            raise InputRefused(
                Reason(
                    "scope_missing",
                    envelope.reference.digest,
                    None,
                    "/statement/claim_ids",
                    "Validation receipt names an absent validation claim.",
                )
            )
        sources = acquire_validation_receipt_sources(
            envelope,
            protected=record_value["evidence_class"] == "protected_native_seat_reproduction",
            formats=formats,
            resolver=resolver,
            budget=budget,
        )
        certificate = sources.certificate
        if certificate is not None:
            _, certificate_key = key(certificate, "subject_public_key_ref")
            if certificate_key != runner_key or value(certificate)["subject_key_id"] != key_id(
                cast(bytes, runner_key)
            ):
                refuse(body, "runner_actual_key_ref")
        verifier = initialize_verifier()
        from ._successor_signatures import verify_successor_signature

        if not verify_successor_signature(
            envelope, public_key=cast(bytes, runner_key), verifier=verifier
        ):
            raise InputRefused(
                Reason(
                    "invalid_signature",
                    envelope.reference.digest,
                    None,
                    "/signature",
                    "The independent validation statement signature is invalid.",
                )
            )
        receipts.append(sources)
    return ReproductionNativeEvidence(content, runner_reference, runner_key, tuple(receipts))
