# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete ordinary signature scope obligations

"""Apply the selected exact unsigned scope without granting native or domain admission."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._claims import ClaimObligation
from ._codecs import decode_reference
from ._content import CompleteContent
from ._immutable import FrozenJson
from ._signature_rule_source import SignatureRuleSource
from ._software_receipts import SoftwareReceiptCheck
from ._trust_types import VerificationPolicy
from ._values import BlobRef, Reason


@dataclass(frozen=True, slots=True)
class SignatureObligationCheck:
    """Retain actual content coverage and every separate validation-record obligation.

    Attributes
    ----------
    rule : SignatureRuleSource
        Entire independently selected rule and its full earlier source population.
    receipts : tuple of SoftwareReceiptCheck
        Whole actual source-matched mathematical candidates. These are not authenticated
        native authority, custody, identity, time or independently accepted state.
    unsigned_claim_ids, unsigned_purposes : tuple of str
        Exact ordinary unsigned exception populations, without inferred extra scope.
    unsigned_validation_records : tuple of BlobRef
        Whole record exceptions; records outside this scope retain their obligations.
    unwaived_record_obligations : tuple of ClaimObligation
        Entire original claims needing independent record signature validation. A C0
        receipt cannot supply it; the owning record/class method still must check it.
    ordinary_reasons : tuple of Reason
        Actual missing ordinary content claim/purpose coverage. Pending record
        requirements remain separate so their own complete sources can be checked.
    """

    rule: SignatureRuleSource
    receipts: tuple[SoftwareReceiptCheck, ...]
    unsigned_claim_ids: tuple[str, ...]
    unsigned_purposes: tuple[str, ...]
    unsigned_validation_records: tuple[BlobRef, ...]
    unwaived_record_obligations: tuple[ClaimObligation, ...]
    ordinary_reasons: tuple[Reason, ...]

    @property
    def reasons(self) -> tuple[Reason, ...]:
        """Retain all ordinary failures and every unresolved unwaived record requirement.

        Returns
        -------
        tuple of Reason
            Original ordered ordinary and pending-record failures. Source acquisition,
            structural correspondence or signature math clears no record requirement.
        """
        return self.ordinary_reasons + tuple(
            Reason(
                "signature_required",
                cast(BlobRef, claim.validation_record).digest,
                claim.claim_id,
                None,
                "The required validation record signature is unavailable.",
            )
            for claim in self.unwaived_record_obligations
        )


def check_signature_obligations(
    content: CompleteContent,
    *,
    policy: VerificationPolicy,
    rule: SignatureRuleSource,
    receipts: tuple[SoftwareReceiptCheck, ...],
) -> SignatureObligationCheck:
    """Check full ordinary content scope and retain every unwaived record requirement.

    Parameters
    ----------
    content : CompleteContent
        Entire actual native subject and complete original ordered claim obligations.
    policy : VerificationPolicy
        Independently selected whole required claim/purpose/reference population.
    rule : SignatureRuleSource
        Complete already matched class/content/base/scope/window source. This method
        applies no exception to a control target or a different source/class.
    receipts : tuple of SoftwareReceiptCheck
        Actual complete target/key equation outcomes after the owning receipt method
        has refused any failure. Native class authority remains independently required.

    Returns
    -------
    SignatureObligationCheck
        Exact selected exception, all actual ordinary coverage reasons and unwaived
        whole record obligations. It supplies no final waiver or eligibility verdict
        before the complete selected class, Clock and record methods are admitted.
    """
    claims = content.content_claim_obligations
    identifiers: tuple[str, ...] = ()
    purposes: tuple[str, ...] = ()
    records: tuple[BlobRef, ...] = ()
    exception = rule.declaration["unsigned_exception"]
    if (
        exception is not None
        and rule.declaration["profile_class"] == "unsigned_declared"
        and content.content_ref.schema_id == "evidence_manifest_toolkit.manifest.v1"
    ):
        scoped = cast(Mapping[str, FrozenJson], exception)
        identifiers = cast(tuple[str, ...], scoped["claim_ids"])
        purposes = cast(tuple[str, ...], scoped["purposes"])
        records = tuple(
            decode_reference(
                item,
                subject=rule.source.reference.digest,
                pointer="/unsigned_exception/validation_record_refs/" + str(index),
            )
            for index, item in enumerate(
                cast(tuple[FrozenJson, ...], scoped["validation_record_refs"])
            )
        )
    available = {claim.claim_id for claim in claims}
    reasons = [
        Reason(
            "scope_missing",
            content.content_ref.digest,
            identifier,
            "/claims",
            "Required claim scope does not resolve in the complete content.",
        )
        for identifier in policy.required_claim_ids
        if identifier not in available
    ]
    exception_active = bool(identifiers and purposes)
    all_claims_covered = all(
        identifier in identifiers for identifier in policy.required_claim_ids
    ) and all(claim.claim_id in identifiers for claim in claims if claim.signature_required)
    all_purposes_covered = all(purpose in purposes for purpose in policy.required_purposes)
    if not receipts and not (exception_active and all_claims_covered and all_purposes_covered):
        reasons.append(
            Reason(
                "signature_required",
                content.content_ref.digest,
                None,
                None,
                "The required evidence signature is unavailable.",
            )
        )
    for identifier in policy.required_claim_ids:
        for purpose in policy.required_purposes:
            if (
                receipts
                and not (exception_active and identifier in identifiers and purpose in purposes)
                and not any(
                    item.envelope.statement.value["purpose"] == purpose
                    and identifier
                    in cast(tuple[str, ...], item.envelope.statement.value["claim_ids"])
                    for item in receipts
                )
            ):
                reasons.append(
                    Reason(
                        "scope_missing",
                        content.content_ref.digest,
                        identifier,
                        "/claims",
                        "Required signed claim and purpose scope is unavailable.",
                    )
                )
    for purpose in policy.required_purposes:
        if (
            receipts
            and not (exception_active and purpose in purposes and all_claims_covered)
            and not any(item.envelope.statement.value["purpose"] == purpose for item in receipts)
        ):
            reasons.append(
                Reason(
                    "scope_missing",
                    content.content_ref.digest,
                    None,
                    None,
                    "Required signed purpose is unavailable.",
                )
            )
    for claim in claims:
        if (
            claim.signature_required
            and receipts
            and not (exception_active and claim.claim_id in identifiers)
            and not any(
                claim.claim_id in cast(tuple[str, ...], item.envelope.statement.value["claim_ids"])
                for item in receipts
            )
        ):
            reasons.append(
                Reason(
                    "signature_required",
                    content.content_ref.digest,
                    claim.claim_id,
                    "/claims",
                    "The required evidence signature is unavailable.",
                )
            )
    pending_records = tuple(
        claim
        for claim in claims
        if claim.validation_record_signature_required
        and not (
            exception_active
            and "evidence" in purposes
            and claim.claim_id in identifiers
            and claim.validation_record in records
        )
    )
    return SignatureObligationCheck(
        rule, receipts, identifiers, purposes, records, pending_records, tuple(reasons)
    )
