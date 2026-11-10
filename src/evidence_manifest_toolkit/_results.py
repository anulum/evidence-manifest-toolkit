# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — closed operation result types

"""Keep construction, declarations and separated verification gates distinct."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from ._immutable import FrozenJson
from ._values import BlobRef, Digest, Reason, Utc


@dataclass(frozen=True, slots=True)
class SealResult:
    """Return immutable construction bytes without an evidence acceptance flag.

    Attributes
    ----------
    canonical_content : bytes
        Complete canonical content, excluding all detached signatures.
    content_ref : BlobRef
        Canonical content identity and length of those same bytes.
    envelope_json : bytes or None
        Canonical detached envelope, absent for unsigned construction.
    """

    canonical_content: bytes
    content_ref: BlobRef
    envelope_json: bytes | None


@dataclass(frozen=True, slots=True)
class Inspection:
    """Display declarations without authenticating or accepting them.

    Attributes
    ----------
    schema_id : str or None
        Declared schema label, if present as a string.
    content_ref : BlobRef or None
        Prospective strict canonical identity, if parsing succeeded.
    declared_claims : tuple
        Complete immutable recognised claim mappings in source order.
    declared_references : tuple of BlobRef
        Recognised reference declarations in concrete pointer order, including repeats.
    acceptance : {"not_evaluated"}
        Inspection never evaluates evidence acceptance.
    reasons : tuple of Reason
        Actual declaration interpretation diagnostics.
    """

    schema_id: str | None
    content_ref: BlobRef | None
    declared_claims: tuple[Mapping[str, FrozenJson], ...]
    declared_references: tuple[BlobRef, ...]
    acceptance: Literal["not_evaluated"]
    reasons: tuple[Reason, ...]


@dataclass(frozen=True, slots=True)
class Difference:
    """Compare canonical content and ordered receipt identities without acceptance.

    Attributes
    ----------
    left_ref, right_ref : BlobRef
        Strict canonical content identities of the complete supplied documents.
    content_equal : bool
        Whether the admitted canonical content bytes are identical.
    changed_paths : tuple of str
        Exact changed JSON Pointers sorted by UTF16 code units.
    left_envelope_refs, right_envelope_refs : tuple of BlobRef
        Canonical detached envelope identities in supplied order.
    receipts_equal : bool
        Equality of those ordered identities, without signature authentication.
    acceptance : {"not_evaluated"}
        Identity comparison never states evidence acceptance.
    """

    left_ref: BlobRef
    right_ref: BlobRef
    content_equal: bool
    changed_paths: tuple[str, ...]
    left_envelope_refs: tuple[BlobRef, ...]
    right_envelope_refs: tuple[BlobRef, ...]
    receipts_equal: bool
    acceptance: Literal["not_evaluated"]


@dataclass(frozen=True, slots=True)
class ReferenceObservation:
    """Record each selected edge independently of deduplicated byte reads.

    Attributes
    ----------
    subject_digest : str
        Actual containing subject identity.
    path_id : str
        Independently selected typed path or admitted control diagnostic label.
    pointer : str
        Actual concrete JSON Pointer of the observed edge.
    required : bool
        Whether this edge belongs to required closure.
    reference : BlobRef or None
        Whole available declaration; digest-only missing metadata is not fabricated.
    outcome : str
        Matched, unavailable, mismatched, absent or not_required.
    reasons : tuple of Reason
        Exact reasons associated with this edge.
    """

    subject_digest: Digest
    path_id: str
    pointer: str
    required: bool
    reference: BlobRef | None
    outcome: Literal["matched", "unavailable", "mismatched", "absent", "not_required"]
    reasons: tuple[Reason, ...]


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Return all fifteen common report fields without a scientific verdict.

    Attributes
    ----------
    content_ref, policy_ref, registry_ref : BlobRef
        Exact content and independently selected policy/registry identities.
    evaluation_mode : {"current", "historical"}
        Explicit caller-selected mode; archive success never becomes current acceptance.
    evaluation_time : str
        Original parsed-valid caller UTC token, retained without rounding.
    evaluated_claim_ids : tuple of str
        Actually evaluated complete claim scope.
    structure, integrity, authenticity, availability : str
        Independent structural, byte, signature and required-availability results.
    common_eligibility : {"eligible", "refused"}
        Conjunction of the applicable common gates.
    domain_verdict : {"not_evaluated"}
        Domain evaluation belongs to the separately owned consumer.
    current_eligibility : {"eligible", "refused"}
        Current common acceptance, retaining historical and domain composition boundaries.
    reference_observations : tuple of ReferenceObservation
        Every observed edge, with all duplicate metadata agreements preserved.
    reasons : tuple of Reason
        All actual gate failures with their applicable subjects and locations.
    """

    content_ref: BlobRef
    policy_ref: BlobRef
    registry_ref: BlobRef
    evaluation_mode: Literal["current", "historical"]
    evaluation_time: Utc
    evaluated_claim_ids: tuple[str, ...]
    structure: Literal["valid", "invalid", "unsupported"]
    integrity: Literal["matched", "mismatched", "unavailable"]
    authenticity: Literal["trusted", "untrusted", "unsigned", "unavailable"]
    availability: Literal["complete", "partial", "unavailable"]
    common_eligibility: Literal["eligible", "refused"]
    domain_verdict: Literal["not_evaluated"]
    current_eligibility: Literal["eligible", "refused"]
    reference_observations: tuple[ReferenceObservation, ...]
    reasons: tuple[Reason, ...]
