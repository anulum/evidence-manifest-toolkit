# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — closed caller configuration before authentication

"""Validate caller state and known policy selectors without reading objects or calling signers."""

from collections.abc import Mapping

from ._codecs import DECIMAL_PATTERN, DIGEST_PATTERN, decode_reference, reference_value
from ._errors import InputRefused
from ._invocation_wire import CallerTrust, successor_trust_value
from ._reference_paths import configuration_refusal, selector_contains
from ._registry_types import ReferenceRequirement
from ._schema_resources import StaticSchema
from ._successor_configuration import decode_successor_trust
from ._successor_trust import (
    DelegatedTrustContextV2,
    SoftwareTrustContextV2,
    UnsignedTrustContextV2,
)
from ._trust_types import TrustContext, VerificationPolicy
from ._utc import utc_key
from ._values import BlobRef

_PURPOSES = {
    "evidence",
    "deployment",
    "human_review",
    "group_certificate",
    "trust_snapshot",
    "root_transition",
}


def _valid_string(value: object) -> bool:
    """Check nonempty exact Unicode strings without normalization.

    Parameters
    ----------
    value : object
        Complete supplied local scalar.

    Returns
    -------
    bool
        Whether the string admits strict UTF-8 representation.
    """
    if not isinstance(value, str) or not value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def validate_reference_argument(reference: BlobRef, *, pointer: str) -> None:
    """Check the whole original local reference without reading or inventing bytes.

    Parameters
    ----------
    reference : BlobRef
        Entire caller-selected immutable declaration.
    pointer : str
        Actual local configuration field position.

    Raises
    ------
    ConfigurationError
        The argument is not a complete valid BlobRef.
    """
    if not isinstance(reference, BlobRef):
        raise configuration_refusal(pointer)
    if not _valid_string(reference.media_type) or (
        reference.schema_id is not None and not _valid_string(reference.schema_id)
    ):
        raise configuration_refusal(pointer)
    try:
        decode_reference(reference_value(reference), subject=None, pointer=pointer)
    except InputRefused as error:
        raise configuration_refusal(pointer) from error


def validate_trust_argument(trust: object, *, signed_construction: bool) -> TrustContext:
    """Check independently supplied caller state before any authentication attempt.

    Parameters
    ----------
    trust : TrustContext
        Entire supplied caller selection for the installed legacy method. Its full type,
        bootstrap/current/floor/mode/time/archive and ordered envelopes must match.
    signed_construction : bool
        Signed seal requires current mode; verification may explicitly select historical.

    Returns
    -------
    TrustContext
        The same whole legacy caller after validation, without a fabricated successor root.

    Raises
    ------
    ConfigurationError
        A closed field, exact decimal floor, UTC token or envelope population is invalid.
    """
    if not isinstance(trust, TrustContext):
        raise configuration_refusal("/trust")
    validate_reference_argument(trust.bootstrap_policy_ref, pointer="/trust/bootstrap_policy_ref")
    validate_reference_argument(trust.current_snapshot_ref, pointer="/trust/current_snapshot_ref")
    floor = trust.accepted_sequence_floor
    if not isinstance(floor, str) or len(floor) > 256 or DECIMAL_PATTERN.fullmatch(floor) is None:
        raise configuration_refusal("/trust/accepted_sequence_floor")
    if trust.evaluation_mode not in ("current", "historical") or (
        signed_construction and trust.evaluation_mode != "current"
    ):
        raise configuration_refusal("/trust/evaluation_mode")
    if not isinstance(trust.evaluation_time, str):
        raise configuration_refusal("/trust/evaluation_time")
    try:
        utc_key(trust.evaluation_time)
    except InputRefused as error:
        raise configuration_refusal("/trust/evaluation_time") from error
    if not isinstance(trust.control_envelopes, tuple):
        raise configuration_refusal("/trust/control_envelopes")
    for index, envelope in enumerate(trust.control_envelopes):
        if not isinstance(envelope, bytes):
            raise configuration_refusal("/trust/control_envelopes/" + str(index))
    if trust.archived_snapshot_ref is not None:
        validate_reference_argument(
            trust.archived_snapshot_ref, pointer="/trust/archived_snapshot_ref"
        )
    if trust.evaluation_mode == "historical" and trust.archived_snapshot_ref is None:
        raise configuration_refusal("/trust/archived_snapshot_ref")
    return trust


def validate_verification_trust(trust: object) -> CallerTrust:
    """Validate the whole selected caller before selecting its operation method.

    Parameters
    ----------
    trust : TrustContext or successor context
        Entire explicit local selection. A V2 caller retains its own namespace,
        class, Clock binding, archive and authority fields without a legacy root.

    Returns
    -------
    TrustContext or successor context
        Complete validated caller. The fixed V2 decoder rechecks and detaches the
        entire carrier; no received value selects executable code or authority.

    Raises
    ------
    ConfigurationError
        The selected type or any of its complete original fields is invalid.

    Notes
    -----
    Validation admits a caller declaration to policy pairing, not an operation
    result. Each selected method must still evaluate its actual native sources.
    """
    if isinstance(trust, (UnsignedTrustContextV2, SoftwareTrustContextV2, DelegatedTrustContextV2)):
        return decode_successor_trust(successor_trust_value(trust))
    return validate_trust_argument(trust, signed_construction=False)


def validate_requirements(
    requirements: tuple[ReferenceRequirement, ...], *, schemas: Mapping[str, StaticSchema]
) -> None:
    """Check exact subject/schema/path/instance overrides without selecting new paths.

    Parameters
    ----------
    requirements : tuple of ReferenceRequirement
        Complete caller policy override population, with no reserved control labels.
    schemas : Mapping
        Independently validated known static registry and all reviewed selectors.

    Raises
    ------
    ConfigurationError
        A subject, unknown/duplicate selector, reserved label or concrete instance is invalid.
    """
    if not isinstance(requirements, tuple):
        raise configuration_refusal("/policy/required_reference_paths")
    seen: set[tuple[str, str, str]] = set()
    for index, requirement in enumerate(requirements):
        pointer = "/policy/required_reference_paths/" + str(index)
        if not isinstance(requirement, ReferenceRequirement):
            raise configuration_refusal(pointer)
        if (
            not isinstance(requirement.subject_digest, str)
            or DIGEST_PATTERN.fullmatch(requirement.subject_digest) is None
        ):
            raise configuration_refusal(pointer + "/subject_digest")
        if not isinstance(requirement.path_id, str) or requirement.path_id.startswith(
            "typed-control:"
        ):
            raise configuration_refusal(pointer + "/path_id")
        if not isinstance(requirement.schema_id, str) or requirement.schema_id not in schemas:
            raise configuration_refusal(pointer + "/schema_id")
        identity = requirement.subject_digest, requirement.schema_id, requirement.path_id
        if identity in seen:
            raise configuration_refusal(pointer)
        seen.add(identity)
        selected = next(
            (
                path
                for path in schemas[requirement.schema_id].entry.reference_paths
                if path.path_id == requirement.path_id
            ),
            None,
        )
        if selected is None:
            raise configuration_refusal(pointer + "/path_id")
        if requirement.instances is not None:
            if not isinstance(requirement.instances, tuple):
                raise configuration_refusal(pointer + "/instances")
            if any(not isinstance(instance, str) for instance in requirement.instances):
                raise configuration_refusal(pointer + "/instances")
            if len(requirement.instances) != len(set(requirement.instances)):
                raise configuration_refusal(pointer + "/instances")
            for instance in requirement.instances:
                if not selector_contains(selected, instance):
                    raise configuration_refusal(pointer + "/instances")


def validate_policy_argument(
    policy: VerificationPolicy, *, schemas: Mapping[str, StaticSchema]
) -> None:
    """Check closed policy declarations before policy bytes or signatures are evaluated.

    Parameters
    ----------
    policy : VerificationPolicy
        Exact independently selected policy reference, claims, purposes and path overrides.
    schemas : Mapping
        Validated known schema/path population.

    Raises
    ------
    ConfigurationError
        A required reference, unique identity/purpose population or selector is invalid.
    """
    if not isinstance(policy, VerificationPolicy):
        raise configuration_refusal("/policy")
    validate_reference_argument(policy.policy_ref, pointer="/policy/policy_ref")
    for name, population in (
        ("required_claim_ids", policy.required_claim_ids),
        ("required_purposes", policy.required_purposes),
    ):
        if not isinstance(population, tuple) or any(
            not _valid_string(value) for value in population
        ):
            raise configuration_refusal("/policy/" + name)
        if len(population) != len(set(population)):
            raise configuration_refusal("/policy/" + name)
    if any(purpose not in _PURPOSES for purpose in policy.required_purposes):
        raise configuration_refusal("/policy/required_purposes")
    validate_requirements(policy.required_reference_paths, schemas=schemas)
