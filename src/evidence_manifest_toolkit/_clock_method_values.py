# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — fixed closed Clock raw method field domains

"""Validate complete method data without inferring missing error or calibration values."""

from typing import cast

from ._clock_values import clock_integer, clock_unavailable
from ._errors import ConfigurationError
from ._json import JsonValue
from ._utc import utc_key
from ._values import Digest, Reason

COMMON_FIELDS = frozenset(
    {
        "method_id",
        "units",
        "custody_class",
        "host_identity_ref",
        "controller_identity_ref",
        "implementation_environment_ref",
        "boot_domain_ref",
        "valid_from",
        "valid_until",
        "renewal_rule",
        "assumptions_and_limitations_ref",
        "provenance_refs",
    }
)
SAMPLE_TERMS = frozenset(
    {
        "source_encoding",
        "elapsed_holdover",
        "post_exchange_adjustment",
        "acquisition",
        "mapping",
        "quantization",
    }
)
USE_TERMS = frozenset({"acquisition", "mapping", "quantization", "adjustment"})
CLOCK_POINTER = "/required_evaluation_time_qualification/clock_qualification_ref"


def method_configuration_refusal(subject: Digest, pointer: str) -> ConfigurationError:
    """Locate a malformed installed method configuration without received diagnostic text.

    Parameters
    ----------
    subject : str
        Actual raw method source identity.
    pointer : str
        Actual closed field position in that source.

    Returns
    -------
    ConfigurationError
        Complete original typed configuration reason and a fixed safe detail.
    """
    return ConfigurationError(
        Reason("configuration_error", subject, None, pointer, "Invalid Clock method configuration.")
    )


def method_object(
    value: JsonValue, fields: frozenset[str], *, subject: Digest, pointer: str
) -> dict[str, JsonValue]:
    """Require the full fixed object without discarding unexpected members.

    Parameters
    ----------
    value : object
        Entire original parsed source value.
    fields : frozenset of str
        Complete installed member population.
    subject : str
        Actual containing source identity.
    pointer : str
        Actual object position.

    Returns
    -------
    dict
        Original complete object, with no inserted defaults or projected fields.

    Raises
    ------
    ConfigurationError
        The object type or exact member population differs.
    """
    if not isinstance(value, dict) or set(value) != fields:
        raise method_configuration_refusal(subject, pointer)
    return value


def method_integer(
    value: JsonValue, *, subject: Digest, policy_subject: Digest, pointer: str
) -> int:
    """Read one explicit canonical nonnegative nanosecond or ratio component.

    Parameters
    ----------
    value : object
        Whole supplied exact integer string, never a missing-value fallback.
    subject : str
        Actual raw method identity for a wrong JSON type.
    policy_subject : str
        Original selected policy for an unsupported Clock numeric mapping.
    pointer : str
        Actual raw field position.

    Returns
    -------
    int
        Exact bounded-size nonnegative integer, preserving zero only when explicit.

    Raises
    ------
    ConfigurationError
        The original field is not a string.
    InputRefused
        Its numeric spelling/range has no selected Clock mapping.
    """
    if not isinstance(value, str):
        raise method_configuration_refusal(subject, pointer)
    return clock_integer(value, signed=False, subject=policy_subject, pointer=CLOCK_POINTER)


def check_method_header(
    value: dict[str, JsonValue], *, method: str, units: str, subject: Digest, policy_subject: Digest
) -> None:
    """Check the known method, explicit units and entire exact renewal window.

    Parameters
    ----------
    value : dict
        Full already closed raw method record.
    method, units : str
        Literal installed dispatch and dimensional interpretation, never artifact code.
    subject : str
        Actual raw record identity for malformed local fields.
    policy_subject : str
        Original selected policy for unsupported source-method mapping.

    Raises
    ------
    ConfigurationError
        Units, renewal law or UTC field types are invalid.
    InputRefused
        Dispatch is unknown, UTC is malformed, or the full window is empty/reversed.
    """
    if value["method_id"] != method:
        raise clock_unavailable(policy_subject, CLOCK_POINTER)
    if value["units"] != units:
        raise method_configuration_refusal(subject, "/units")
    if value["renewal_rule"] != "fresh_source_model_before_expiry_no_implicit_extension":
        raise method_configuration_refusal(subject, "/renewal_rule")
    for name in ("valid_from", "valid_until"):
        if not isinstance(value[name], str):
            raise method_configuration_refusal(subject, "/" + name)
    beginning = utc_key(
        cast(str, value["valid_from"]), subject_digest=subject, pointer="/valid_from"
    )
    ending = utc_key(
        cast(str, value["valid_until"]), subject_digest=subject, pointer="/valid_until"
    )
    if beginning >= ending:
        raise clock_unavailable(policy_subject, CLOCK_POINTER)
