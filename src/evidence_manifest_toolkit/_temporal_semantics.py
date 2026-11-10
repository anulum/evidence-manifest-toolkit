# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact native temporal relation checks

"""Compare complete valid native UTC fields without supplying a clock or elapsed duration."""

from collections.abc import Mapping
from typing import cast

from ._json import JsonValue
from ._utc import utc_key
from ._values import Digest, Reason


def temporal_reasons(
    document: Mapping[str, JsonValue], *, schema_id: str, subject: Digest
) -> tuple[Reason, ...]:
    """Check original certificate/snapshot interval and revocation ordering.

    Parameters
    ----------
    document : Mapping
        Entire selected schema-valid native subject, retaining original UTC strings.
    schema_id : str
        Independently selected exact known native schema identity.
    subject : str
        Actual containing identity for every temporal diagnostic.

    Returns
    -------
    tuple of Reason
        Original interval-order failures. Chronological validity does not establish
        trusted creation, current qualified time or an elapsed-SI duration.

    Raises
    ------
    InputRefused
        A native field fails the same complete grammar/calendar/source-history law.
    """
    reasons: list[Reason] = []
    if schema_id == "evidence_manifest_toolkit.group_certificate.v1":
        start = utc_key(
            cast(str, document["not_before"]), subject_digest=subject, pointer="/not_before"
        )
        end = utc_key(
            cast(str, document["not_after"]), subject_digest=subject, pointer="/not_after"
        )
        if start >= end:
            reasons.append(
                Reason(
                    "invalid_schema",
                    subject,
                    None,
                    "/not_after",
                    "Certificate validity interval is not increasing.",
                )
            )
    elif schema_id == "evidence_manifest_toolkit.trust_snapshot.v1":
        issued = utc_key(
            cast(str, document["issued_at"]), subject_digest=subject, pointer="/issued_at"
        )
        expiry = utc_key(
            cast(str, document["expires_at"]), subject_digest=subject, pointer="/expires_at"
        )
        if issued >= expiry:
            reasons.append(
                Reason(
                    "invalid_schema",
                    subject,
                    None,
                    "/expires_at",
                    "Snapshot validity interval is not increasing.",
                )
            )
        for index, record in enumerate(cast(list[dict[str, JsonValue]], document["revocations"])):
            pointer = "/revocations/" + str(index) + "/reported_at"
            reported = utc_key(
                cast(str, record["reported_at"]), subject_digest=subject, pointer=pointer
            )
            if reported > issued:
                reasons.append(
                    Reason(
                        "invalid_schema",
                        subject,
                        None,
                        pointer,
                        "Revocation is reported after snapshot issuance.",
                    )
                )
    return tuple(reasons)


def interval_contains(start: str, end: str, instant: str) -> bool:
    """Compare an explicit instant against a half-open exact UTC interval.

    Parameters
    ----------
    start, end : str
        Complete parsed-valid interval bounds; upper equality is excluded.
    instant : str
        Explicit caller/record instant, never a host-clock default.

    Returns
    -------
    bool
        Whether start <= instant < end under the same complete fraction/leap law.

    Raises
    ------
    InputRefused
        Any whole UTC string is invalid or outside supported leap-source history.
    """
    return utc_key(start) <= utc_key(instant) < utc_key(end)
