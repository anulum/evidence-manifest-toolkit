# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit signer and caller trust inputs

"""Represent caller authority without issuing keys or installing received state."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from ._immutable import FrozenJson, copy_frozen
from ._registry_types import ReferenceRequirement
from ._values import BlobRef, Utc

type Purpose = Literal[
    "evidence",
    "deployment",
    "human_review",
    "group_certificate",
    "trust_snapshot",
    "root_transition",
]


@dataclass(frozen=True, slots=True)
class SigningRequest:
    """Supply the exact statement fields except the four computed identities.

    Attributes
    ----------
    statement_fields : Mapping
        Original context-specific fields; no computed content/schema/length/scope digest,
        secret, command, received code or future-output authority is supplied.
    """

    statement_fields: Mapping[str, FrozenJson]

    def __post_init__(self) -> None:
        """Detach complete typed caller mappings without rewriting their contents."""
        object.__setattr__(
            self,
            "statement_fields",
            cast(Mapping[str, FrozenJson], copy_frozen(self.statement_fields)),
        )


@dataclass(frozen=True, slots=True)
class SignerConfig:
    """Name a locally enrolled signer without exposing its secret or executable.

    Attributes
    ----------
    adapter_ref : str
        Explicit local enrolled adapter reference, never an artifact program path.
    signer_key_id : str
        Exact original key identifier matched to pinned eligible authority.
    public_key : bytes
        Immutable raw32 public-key bytes.
    profile_id : str
        Exact supported original PureEd25519 statement profile.
    """

    adapter_ref: str
    signer_key_id: str
    public_key: bytes
    profile_id: str


@dataclass(frozen=True, slots=True)
class TrustContext:
    """Select independent current/archive authority and explicit evaluation time.

    Attributes
    ----------
    bootstrap_policy_ref, current_snapshot_ref : BlobRef
        Independently selected owner policy and already established current state.
    accepted_sequence_floor : str
        Exact pinned nonnegative decimal floor, never advanced by EMT operations.
    evaluation_mode : {"current", "historical"}
        Explicit policy mode, without implicit current/archive fallback.
    evaluation_time : str
        Original parsed-valid UTC token; no host clock or producer assertion supplies now.
    control_envelopes : tuple of bytes
        Explicit detached root-control envelopes; no hidden signature discovery.
    archived_snapshot_ref : BlobRef or None
        Required selected archive in historical mode; it is never installed as current.
    """

    bootstrap_policy_ref: BlobRef
    current_snapshot_ref: BlobRef
    accepted_sequence_floor: str
    evaluation_mode: Literal["current", "historical"]
    evaluation_time: Utc
    control_envelopes: tuple[bytes, ...]
    archived_snapshot_ref: BlobRef | None = None


@dataclass(frozen=True, slots=True)
class VerificationPolicy:
    """Bind the independent policy to exact required claims, purposes and references.

    Attributes
    ----------
    policy_ref : BlobRef
        Whole reviewed policy bytes supplied through the explicit resolver.
    required_claim_ids : tuple of str
        Unique resolving claim scope; empty only for appropriate root-control objects.
    required_purposes : tuple of str
        Exact original context-specific evidence/control purpose population.
    required_reference_paths : tuple of ReferenceRequirement
        Existing known paths and instances; defaults empty without weakening native gates.
    """

    policy_ref: BlobRef
    required_claim_ids: tuple[str, ...]
    required_purposes: tuple[Purpose, ...]
    required_reference_paths: tuple[ReferenceRequirement, ...] = ()


@dataclass(frozen=True, slots=True)
class Envelope:
    """Keep the original detached statement/signature pair outside content identity.

    Attributes
    ----------
    statement : Mapping
        Whole immutable context-specific signed_statement object.
    signature : str
        Canonical unpadded Base64URL encoding of the exact raw64 signature.
    """

    statement: Mapping[str, FrozenJson]
    signature: str

    def __post_init__(self) -> None:
        """Detach complete statement mappings without changing signed values."""
        object.__setattr__(
            self, "statement", cast(Mapping[str, FrozenJson], copy_frozen(self.statement))
        )
