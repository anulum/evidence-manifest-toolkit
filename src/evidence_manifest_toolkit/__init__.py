# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — offline evidence operations

"""Construct explicit byte identities and inspect immutable evidence declarations."""

from ._difference import diff
from ._errors import (
    ConfigurationError,
    EmtError,
    InputRefused,
    ReferenceUnavailable,
    SignerUnavailable,
    StorageError,
)
from ._inspection import inspect
from ._interfaces import Resolver, Signer
from ._json import canonicalize_json
from ._references import reference_bytes
from ._registry_types import (
    PathStep,
    ReferencePath,
    ReferenceRequirement,
    RegistryEntry,
    SchemaDependency,
    SchemaRegistry,
)
from ._results import Difference, Inspection, ReferenceObservation, SealResult, VerificationReport
from ._sealing import seal
from ._successor_trust import (
    DelegatedTrustContextV2,
    SoftwareTrustContextV2,
    UnsignedTrustContextV2,
)
from ._trust_types import Envelope, SignerConfig, SigningRequest, TrustContext, VerificationPolicy
from ._values import BlobRef, Digest, DigestBasis, Limits, Reason, Utc
from ._verification import verify

__all__ = [
    "BlobRef",
    "ConfigurationError",
    "DelegatedTrustContextV2",
    "Difference",
    "Digest",
    "DigestBasis",
    "EmtError",
    "Envelope",
    "InputRefused",
    "Inspection",
    "Limits",
    "PathStep",
    "Reason",
    "ReferenceObservation",
    "ReferencePath",
    "ReferenceRequirement",
    "ReferenceUnavailable",
    "RegistryEntry",
    "Resolver",
    "SchemaDependency",
    "SchemaRegistry",
    "SealResult",
    "Signer",
    "SignerConfig",
    "SignerUnavailable",
    "SigningRequest",
    "SoftwareTrustContextV2",
    "StorageError",
    "TrustContext",
    "UnsignedTrustContextV2",
    "Utc",
    "VerificationPolicy",
    "VerificationReport",
    "canonicalize_json",
    "diff",
    "inspect",
    "reference_bytes",
    "seal",
    "verify",
]
