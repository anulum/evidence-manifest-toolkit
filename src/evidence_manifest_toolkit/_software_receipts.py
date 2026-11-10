# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual software receipt targets and native equations

"""Check whole software receipt correspondence without manufacturing native authority."""

from dataclasses import dataclass
from typing import cast

from ._codecs import reference_value
from ._immutable import FrozenJson
from ._json import AcquiredDocument, JsonValue
from ._policy_source import PolicyDeclaration
from ._signature_provider import initialize_verifier
from ._software_sources import SoftwareKeySource, SoftwareSources
from ._successor_envelopes import SuccessorEnvelope
from ._values import BlobRef, Reason, Utc


@dataclass(frozen=True, slots=True)
class SoftwareReceiptCheck:
    """Retain the entire receipt and source-scoped mathematical result.

    Attributes
    ----------
    envelope : SuccessorEnvelope
        Whole original statement, exact disjoint message and raw64 signature.
    matching_keys : tuple of SoftwareKeySource
        Entire selected rows matching the literal signer, declared purpose and original
        policy principal/role/segment. Rows are not combined to invent a broader scope.
    signature_valid : bool
        Actual maintained-provider verification of the complete original message.
        This is not custody, identity, source qualification or native authorization.
    reasons : tuple of Reason
        Actual target/source/scope/declared-window/revocation or mathematical failures.
        Even an empty tuple does not accept Clock, the whole scope rule or authority.
    verified_keys : tuple of SoftwareKeySource
        Whole matching rows whose declared signing/evaluation windows and actual
        full-message equation passed. Their windows remain separate; no union
        supplies authorization through the complete actual entry interval.
    """

    envelope: SuccessorEnvelope
    matching_keys: tuple[SoftwareKeySource, ...]
    signature_valid: bool
    reasons: tuple[Reason, ...]
    verified_keys: tuple[SoftwareKeySource, ...] = ()


def check_software_receipt(
    envelope: SuccessorEnvelope,
    *,
    sources: SoftwareSources,
    content_reference: BlobRef,
    actual_claim_ids: tuple[str, ...],
    policy: PolicyDeclaration,
    evaluation_time: Utc,
) -> SoftwareReceiptCheck:
    """Check the real whole software target and selected source before native admission.

    Parameters
    ----------
    envelope : SuccessorEnvelope
        Independently parsed complete ordinary V2 receipt.
    sources : SoftwareSources
        Full actual current and selected histories, not artifact-selected authority.
    content_reference : BlobRef
        Actual complete canonical native manifest identity and schema.
    actual_claim_ids : tuple of str
        Entire actual manifest claim population, without narrowing to required claims.
    policy : PolicyDeclaration
        Whole earlier ordinary policy, retaining its exact principal/role/segment scope.
    evaluation_time : Utc
        Original fixed caller token; comparison alone does not qualify its Clock.

    Returns
    -------
    SoftwareReceiptCheck
        Whole original receipt, matching full rows and actual mathematical outcome.
        Complete rule, identity/possession/custody, current source authentication, accepted
        Clock and propagated authorization windows remain independent native predicates.

    Raises
    ------
    ConfigurationError
        A required actual signature has no conforming maintained local provider.
        No provider is initialized for an incompatible target or unavailable key.

    Notes
    -----
    Claimed signing time and caller time must both be in one complete selected row's
    half-open window. This necessary declaration check is not proof of actual signing
    time or of the complete Clock interval through entry E. Each whole verified
    row is retained separately for that subsequent interval check.
    """
    statement = envelope.statement.value
    reasons: list[Reason] = []

    def refuse(name: str, code: str = "invalid_delegation") -> None:
        """Retain an actual complete statement-field failure without source text.

        Parameters
        ----------
        name : str
            Original statement field or concrete array member position.
        code : str
            Existing native reason category, never a new admission or warning code.
        """
        reasons.append(
            Reason(
                code,
                envelope.reference.digest,
                None,
                "/statement/" + name,
                "Software statement does not match its independently selected source or target.",
            )
        )

    selected = sources.selected
    table_ref = reference_value(selected.fixed.source.reference)
    for name, expected in (
        ("content_digest", content_reference.digest),
        ("content_byte_length", content_reference.byte_length),
        ("content_schema_id", content_reference.schema_id),
        ("authorizing_state_ref", table_ref),
        ("authorization_ref", table_ref),
        ("snapshot_ref", table_ref),
        ("scope_ref", reference_value(selected.scope_reference)),
    ):
        if statement[name] != expected:
            refuse(name, "scope_missing")
    for index, identifier in enumerate(cast(tuple[str, ...], statement["claim_ids"])):
        if identifier not in actual_claim_ids:
            refuse("claim_ids/" + str(index), "scope_missing")
    if reasons:
        return SoftwareReceiptCheck(envelope, (), False, tuple(reasons))

    matching = tuple(
        key
        for key in selected.keys
        if key.value["key_id"] == statement["signer_key_id"]
        and statement["purpose"] in cast(tuple[FrozenJson, ...], key.value["purposes"])
        and key.value["principal"] == policy.required_principal
        and key.value["role"] == policy.required_role
        and key.value["segment"] == policy.required_segment
    )
    if not matching:
        refuse("signer_key_id")
        return SoftwareReceiptCheck(envelope, (), False, tuple(reasons))
    signed_at = Utc(statement["claimed_signed_at"])
    windowed = tuple(
        key
        for key in matching
        if key.valid_from.compare(signed_at) <= 0
        and signed_at.compare(key.valid_until) < 0
        and key.valid_from.compare(evaluation_time) <= 0
        and evaluation_time.compare(key.valid_until) < 0
    )
    if not windowed:
        refuse("claimed_signed_at")
    for table in (*sources.history, *sources.selected_history):
        value = cast(AcquiredDocument, table.fixed.source.document)
        revocations = cast(
            list[dict[str, JsonValue]], cast(dict[str, JsonValue], value.value)["revocations"]
        )
        if any(item["key_id"] == statement["signer_key_id"] for item in revocations):
            refuse("signer_key_id", "key_revoked")
            break
    if reasons:
        return SoftwareReceiptCheck(envelope, matching, False, tuple(reasons))

    # Import only for an actual compatible signed route; unsigned/source-only routes
    # never import the native provider or manufacture an unused verifier.
    verifier = initialize_verifier()
    from ._successor_signatures import verify_successor_signature

    public_keys = dict.fromkeys(key.public_key for key in windowed)
    verified = {
        public_key: verify_successor_signature(envelope, public_key=public_key, verifier=verifier)
        for public_key in public_keys
    }
    verified_keys = tuple(key for key in windowed if verified[key.public_key])
    valid = bool(verified_keys)
    if not valid:
        reasons.append(
            Reason(
                "invalid_signature",
                envelope.reference.digest,
                None,
                "/signature",
                "The software statement signature is invalid.",
            )
        )
    return SoftwareReceiptCheck(envelope, matching, valid, tuple(reasons), verified_keys)
