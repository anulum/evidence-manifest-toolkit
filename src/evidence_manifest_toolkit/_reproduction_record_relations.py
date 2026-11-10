# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole independent record and declared identity relations

"""Check entire reproduction source relations without admitting a run or identity proof."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ._claims import ClaimObligation
from ._closure import ClosureResult
from ._content import CompleteContent
from ._context_sources import ContextSource
from ._format_sources import FixedSource
from ._immutable import FrozenJson
from ._json import AcquiredDocument, JsonValue
from ._method_rule_sources import MethodRuleSources
from ._native_launch_sources import NativeLaunchSource
from ._native_possession_equation import NativePossessionEquation
from ._reproduction_native import ReproductionNativeEvidence
from ._reproduction_run_sources import ReproductionRunSources
from ._values import Reason


@dataclass(frozen=True, slots=True)
class ReproductionRecordSources:
    """Retain the full selected package, earlier evidence and actual relation failures.

    Attributes
    ----------
    claim : ClaimObligation
        Entire original native claim obligation, without an inferred reproduction verdict.
    record, body, producer, runner : FixedSource
        Complete actual record package, earlier body and both full identity bindings.
    subject, policy : ContextSource
        Entire earlier subject and paired policy; neither is replaced by the later
        verifier invocation or a projection of the final parent manifest.
    foreign : FixedSource or None
        Whole actually selected foreign identity source. Presence authenticates nothing.
    closure : ClosureResult
        All selected required source edges under the original shared invocation budget.
    reasons : tuple of Reason
        Located whole-source or declared-identity contradictions. Absence does not prove
        a committed run, key possession, time, non-use, comparison, class or eligibility.
    native_launch_sources : tuple of NativeLaunchSource or None
        Both whole actual producer/runner launch records after original source relations,
        or None when earlier failures prevented interpretation. No identity is admitted.
    native_evidence : ReproductionNativeEvidence or None
        Entire actual validation C0, runner key and ordered native equations. None means
        earlier relation failures prevented this method; mathematics admits no authority.
    run_sources : ReproductionRunSources or None
        Entire execution/release/comparison/access graph and separate comparator
        identity after earlier checks. Shape and joins admit no independent run.
    possession_equations : tuple of NativePossessionEquation or None
        Both supplied producer/runner own-key equations and complete receiver sources,
        or None for an absent optional proof. No freshness/custody class is admitted.
    """

    claim: ClaimObligation
    record: FixedSource
    body: FixedSource
    producer: FixedSource
    runner: FixedSource
    subject: ContextSource
    policy: ContextSource
    foreign: FixedSource | None
    closure: ClosureResult
    reasons: tuple[Reason, ...] = ()
    native_evidence: ReproductionNativeEvidence | None = None
    native_launch_sources: tuple[NativeLaunchSource, NativeLaunchSource] | None = None
    run_sources: ReproductionRunSources | None = None
    possession_equations: tuple[NativePossessionEquation | None, ...] = ()


def reproduction_relation_reasons(
    sources: ReproductionRecordSources,
    *,
    content: CompleteContent,
    policy: Mapping[str, FrozenJson],
    rules: MethodRuleSources,
) -> tuple[Reason, ...]:
    """Evaluate complete record/body/class and independently selected method-policy relations.

    Parameters
    ----------
    sources : ReproductionRecordSources
        Entire schema-valid package/body/identity population and complete original graph.
    content : CompleteContent
        Actual ordinary C0 with its whole validated native claim inventory.
    policy : Mapping
        Entire independently selected successor policy, not the earlier record policy.
    rules : MethodRuleSources
        Whole selected identity/validation/foreign and actual comparison/execution declarations.

    Returns
    -------
    tuple of Reason
        Every located necessary relation failure. Equal declared vendors, principals or
        whole key references refuse independence; differing references prove no key or
        authenticated vendor distinction. The full comparison Ref and execution non-use
        permission must match; neither supplies actual run/non-use/native admission.
    """
    record = cast(
        dict[str, JsonValue], cast(AcquiredDocument, sources.record.source.document).value
    )
    body = cast(dict[str, JsonValue], cast(AcquiredDocument, sources.body.source.document).value)
    producer = cast(
        dict[str, JsonValue], cast(AcquiredDocument, sources.producer.source.document).value
    )
    runner = cast(
        dict[str, JsonValue], cast(AcquiredDocument, sources.runner.source.document).value
    )
    identity = cast(
        dict[str, JsonValue], cast(AcquiredDocument, rules.identity.source.document).value
    )
    validation = cast(
        dict[str, JsonValue], cast(AcquiredDocument, rules.validation.source.document).value
    )
    execution = cast(
        dict[str, JsonValue],
        cast(AcquiredDocument, rules.native_bindings.execution.source.document).value,
    )
    reference = content.content_ref
    root = cast(
        dict[str, JsonValue],
        content.closure.documents[
            reference.digest, reference.digest_basis, reference.byte_length
        ].value,
    )
    claim = next(
        cast(dict[str, JsonValue], item)
        for item in cast(list[JsonValue], root["claims"])
        if cast(dict[str, JsonValue], item)["claim_id"] == sources.claim.claim_id
    )
    reasons: list[Reason] = []

    def refuse(source: FixedSource, field: str) -> None:
        """Locate a concrete relation contradiction without echoing received source text."""
        reasons.append(
            Reason(
                "invalid_claim",
                source.source.reference.digest,
                sources.claim.claim_id,
                "/" + field,
                "Independent validation sources conflict.",
            )
        )

    for field, actual, expected in (
        ("subject_ref", record["subject_ref"], body["subject_ref"]),
        ("claim_id", record["claim_id"], sources.claim.claim_id),
        ("whole_policy_ref", record["whole_policy_ref"], body["whole_policy_ref"]),
        (
            "whole_conditions_and_limitations_ref",
            record["whole_conditions_and_limitations_ref"],
            policy["whole_conditions_and_limitations_ref"],
        ),
    ):
        if actual != expected:
            refuse(sources.record, field)
    for field, actual, expected in (
        ("claim_id", body["claim_id"], sources.claim.claim_id),
        ("custody_class", body["custody_class"], policy["profile_class"]),
        ("outcome", body["outcome"], claim["verdict"]),
        (
            "comparison_rule_ref",
            body["comparison_rule_ref"],
            dict(rules.native_bindings.comparison.source.reference.to_mapping()),
        ),
    ):
        if actual != expected:
            refuse(sources.body, field)
    evidence_class = record["evidence_class"]
    if evidence_class not in cast(list[str], validation["permitted_record_classes"]):
        refuse(sources.record, "evidence_class")
    native_class = {
        "unsigned_declared_reproduction": "unsigned_declared",
        "software_local_reproduction": "software_local_unprotected",
        "protected_native_seat_reproduction": "protected_delegated",
    }.get(cast(str, evidence_class))
    if native_class is not None and native_class != body["custody_class"]:
        refuse(sources.record, "evidence_class")
    if evidence_class == "github_hosted_verified_run_identity" and rules.foreign is None:
        refuse(sources.record, "foreign_run_identity_ref")
    nonuse = body["nonuse_class"]
    if (
        nonuse not in cast(tuple[str, ...], policy["allowed_nonuse_classes"])
        or nonuse not in cast(list[str], validation["required_nonuse_classes"])
        or nonuse not in cast(list[str], execution["permitted_nonuse_classes"])
    ):
        refuse(sources.body, "nonuse_class")
    for source, value in ((sources.producer, producer), (sources.runner, runner)):
        if value["identity_class"] not in cast(list[str], identity["permitted_identity_classes"]):
            refuse(source, "identity_class")
        if value["custody_class"] != identity["custody_class"]:
            refuse(source, "custody_class")
        if value["whole_policy_ref"] != dict(rules.identity.source.reference.to_mapping()):
            refuse(source, "whole_policy_ref")
    if producer["principal_id"] != cast(dict[str, JsonValue], root["producer"])["principal"]:
        refuse(sources.producer, "principal_id")
    if runner["principal_id"] != cast(dict[str, JsonValue], claim["validation"])["runner_id"]:
        refuse(sources.runner, "principal_id")
    for field in ("vendor_id", "principal_id"):
        if producer[field] == runner[field]:
            refuse(sources.runner, field)
    if (
        producer["declared_public_key_ref"] is not None
        and producer["declared_public_key_ref"] == runner["declared_public_key_ref"]
    ):
        refuse(sources.runner, "declared_public_key_ref")
    if (
        body["runner_actual_key_ref"] is not None
        and body["runner_actual_key_ref"] != runner["declared_public_key_ref"]
    ):
        refuse(sources.body, "runner_actual_key_ref")
    return tuple(reasons)
