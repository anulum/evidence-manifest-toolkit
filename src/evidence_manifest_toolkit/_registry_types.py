# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit static registry configuration

"""Represent owner-selected schemas and typed paths without loading artifact code."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from ._values import BlobRef, Digest, DigestBasis

type PathStep = Mapping[str, str]


@dataclass(frozen=True, slots=True)
class ReferencePath:
    """Select references through exact members, indices or known array-each steps.

    Attributes
    ----------
    path_id : str
        Unique reviewed identifier, outside the reserved typed-control namespace.
    steps : tuple of Mapping
        Closed member/name, index/index or each step objects; names are literal.
    absent, null : {"schema_optional", "refuse"}
        Allow absence/null only where the active schema and selected policy permit.
    requirement : {"when_present", "policy_optional"}
        Required present closure or an explicitly optional unaccepted observation.
    """

    path_id: str
    steps: tuple[PathStep, ...]
    absent: Literal["schema_optional", "refuse"]
    null: Literal["schema_optional", "refuse"]
    requirement: Literal["when_present", "policy_optional"]

    def __post_init__(self) -> None:
        """Detach caller step mappings without changing any selected field."""
        object.__setattr__(
            self, "steps", tuple(MappingProxyType(dict(step)) for step in self.steps)
        )


@dataclass(frozen=True, slots=True)
class ReferenceRequirement:
    """Bind required instances to an already known subject/schema/path selection.

    Attributes
    ----------
    subject_digest : str
        Exact subject to which this requirement applies.
    schema_id, path_id : str
        Existing independently selected schema and reviewed reference path.
    instances : tuple of str or None
        Literal concrete pointers, or all known instances including required no-match.
    """

    subject_digest: Digest
    schema_id: str
    path_id: str
    instances: tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class SchemaDependency:
    """Pin one static external schema resource without a network resolver.

    Attributes
    ----------
    uri : str
        Exact selected external resource URI; fragments stay inside pinned bytes.
    schema_ref : BlobRef
        Raw schema identity supplied through the explicit resolver population.
    """

    uri: str
    schema_ref: BlobRef


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    """Supply all fourteen closed schema, traversal, role and qualification fields.

    Attributes
    ----------
    schema_id, owner : str
        Known payload identity and its actual owning source.
    schema_ref : BlobRef
        Exact raw schema bytes identity, distinct from payload or resource identity.
    schema_bytes : bytes
        Complete independently supplied static schema, never executable code.
    media_type : str
        Declared schema media type.
    digest_basis : {"raw_bytes", "jcs_content"}
        Explicit basis; approved schema sources use their exact raw identity.
    reference_paths : tuple of ReferencePath
        Complete reviewed typed selector population.
    common_semantics_id : str
        One member of the finite nine-semantics common catalogue.
    schema_role : str
        Common control/evidence or domain evidence/verification/support role.
    closure_profile_id : str
        Independently known declared-reference closure profile.
    schema_dependencies : tuple of SchemaDependency
        Every statically pinned external dependency.
    domain_support : str
        Not required, required_unqualified or required_qualified; no automatic admission.
    domain_verifier_ref, domain_qualification_ref : BlobRef or None
        Actual selected data references, never artifact-supplied plugin handles.
    """

    schema_id: str
    owner: str
    schema_ref: BlobRef
    schema_bytes: bytes
    media_type: str
    digest_basis: DigestBasis
    reference_paths: tuple[ReferencePath, ...]
    common_semantics_id: str
    schema_role: Literal[
        "common_control",
        "common_evidence",
        "domain_evidence",
        "domain_verification",
        "domain_support",
    ]
    closure_profile_id: str
    schema_dependencies: tuple[SchemaDependency, ...]
    domain_support: Literal["not_required", "required_unqualified", "required_qualified"]
    domain_verifier_ref: BlobRef | None
    domain_qualification_ref: BlobRef | None


@dataclass(frozen=True, slots=True)
class SchemaRegistry:
    """Keep the explicit registry identity outside its immutable content.

    Attributes
    ----------
    snapshot_ref : BlobRef
        Caller-selected registry snapshot identity, authenticated separately under trust.
    entries : tuple of RegistryEntry
        Complete selected cohort, without automatically combining foreign inventories.
    """

    snapshot_ref: BlobRef
    entries: tuple[RegistryEntry, ...]
