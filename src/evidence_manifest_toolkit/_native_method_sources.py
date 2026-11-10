# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete native implementation environment and qualification sources

"""Keep actual code/environment correspondence separate from independently required qualification."""

from dataclasses import dataclass
from typing import cast

from ._acquisition import acquire_reference, identity_reason
from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._context_sources import ContextSource, acquire_context_source
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue, acquire_document
from ._native_installation import NativeInstallation
from ._values import BlobRef, Reason

_RAW_CONTRACT = BlobRef(
    "sha256:f4dc21580f6961e84835dbf9dac3f0d5328a06e05a23ea73970d60130cc2fbee",
    "3619",
    "application/schema+json",
    "raw_bytes",
)


@dataclass(frozen=True, slots=True)
class NativeMethodInputs:
    """Keep entire independently selected method inputs before installed source matching.

    Attributes
    ----------
    declaration_reference : BlobRef
        Original independently selected full declaration, never a received method selector.
    implementation_reference, implementation_bytes : BlobRef, bytes
        Whole original identity-matching implementation input acquired from the resolver.
    environment : ContextSource
        Complete original strict environment object, without an approval assertion.
    qualification_reference, qualification_bytes : BlobRef, bytes
        Whole original unadmitted qualification evidence, not an accepted flag.
    """

    declaration_reference: BlobRef
    implementation_reference: BlobRef
    implementation_bytes: bytes
    environment: ContextSource
    qualification_reference: BlobRef
    qualification_bytes: bytes


@dataclass(frozen=True, slots=True)
class NativeMethodSources:
    """Retain original selected inputs and actual installed source correspondence.

    Attributes
    ----------
    inputs : NativeMethodInputs
        Complete independently selected inputs after their original acquisition checks.
    installation : NativeInstallation
        Whole actual matched installation after the complete connected rule closure.
        Correspondence grants no independent source, method or class qualification.
    """

    inputs: NativeMethodInputs
    installation: NativeInstallation


def acquire_launch_method_sources(
    method: FixedSource, *, resolver: Resolver, budget: ReferenceBudget
) -> NativeMethodInputs | None:
    """Acquire original whole sources only for the independently selected known raw method.

    Parameters
    ----------
    method : FixedSource
        Whole method declaration after complete original schema/metadata checks.
    resolver : Resolver
        SAME bounded original source, without received executable or source discovery.
    budget : ReferenceBudget
        SAME already charged whole-operation quota, never reset at a method boundary.

    Returns
    -------
    NativeMethodInputs or None
        Original complete known method inputs. Physical installation is not read here.
        None preserves unsupported observer/other contracts,
        which require their actual method; it never selects a weaker class or acceptance.

    Raises
    ------
    ReferenceUnavailable
        An original exact required implementation/environment/qualification source is absent.
    InputRefused
        Actual whole identity/source/metadata/quota or known-method correspondence fails.
    """
    subject = method.source.reference.digest
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, method.source.document).value)
    if "record_contract_ref" not in value:
        return None
    contract = decode_reference(
        value["record_contract_ref"], subject=subject, pointer="/record_contract_ref"
    )
    if contract != _RAW_CONTRACT:
        return None
    reference = decode_reference(
        value["implementation_ref"], subject=subject, pointer="/implementation_ref"
    )
    implementation = acquire_reference(
        reference, resolver=resolver, budget=budget, subject=subject, pointer="/implementation_ref"
    )
    implementation_failure = identity_reason(
        reference, implementation, budget=budget, subject=subject, pointer="/implementation_ref"
    )
    if implementation_failure is not None:
        raise InputRefused(implementation_failure)
    environment_ref = decode_reference(
        value["implementation_environment_ref"],
        subject=subject,
        pointer="/implementation_environment_ref",
    )
    environment = acquire_context_source(
        environment_ref,
        expected_control=None,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer="/implementation_environment_ref",
    )
    if environment.raw_bytes is None:
        raise ReferenceUnavailable(environment_ref)
    if environment.document is None:
        raise InputRefused(environment.reasons[0])
    qualification = decode_reference(
        value["implementation_qualification_ref"],
        subject=subject,
        pointer="/implementation_qualification_ref",
    )
    raw = acquire_reference(
        qualification,
        resolver=resolver,
        budget=budget,
        subject=subject,
        pointer="/implementation_qualification_ref",
    )
    failure = identity_reason(
        qualification,
        raw,
        budget=budget,
        subject=subject,
        pointer="/implementation_qualification_ref",
    )
    if failure is not None:
        raise InputRefused(failure)
    return NativeMethodInputs(
        method.source.reference, reference, implementation, environment, qualification, raw
    )


def compare_native_method_environment(
    sources: NativeMethodSources, actual_environment_json: bytes, *, budget: ReferenceBudget
) -> None:
    """Compare the entire declared method environment with the actual public-entry capture.

    Parameters
    ----------
    sources : NativeMethodSources
        Whole actual sources from the known method, not a caller-created admitted object.
    actual_environment_json : bytes
        Entire ORIGINAL NativeEntryCapture.environment_json from this public invocation.
        It is the current verifier environment, not historical producer process data.
    budget : ReferenceBudget
        SAME operation bounds for strict interpretation of both complete observations.

    Raises
    ------
    InputRefused
        Any full environment fact differs, or its actual strict byte/depth bound fails.
        Equality supplies no independently approved execution environment or method.
    """
    actual = acquire_document(actual_environment_json, limits=budget.limits)
    declared = cast(AcquiredDocument, sources.inputs.environment.document)
    if declared.value != actual.value:
        raise InputRefused(
            Reason(
                "policy_unavailable",
                sources.inputs.declaration_reference.digest,
                None,
                "/implementation_environment_ref",
                "Native method execution environment conflicts.",
            )
        )
