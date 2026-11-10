# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — authored native reference-purpose diagnostics

"""Retain complete actual failures while selecting fixed known native field wording."""

from ._values import Reason


def native_reference_reason(reason: Reason, *, schema_id: str, pointer: str) -> Reason:
    """Locate the original environment-source refusal without changing its failure facts.

    Parameters
    ----------
    reason : Reason
        Actual identity/read failure with its real subject, claim and source location.
    schema_id : str
        Independently selected known containing schema, never an artifact implementation label.
    pointer : str
        Actual concrete reference position inside that known source.

    Returns
    -------
    Reason
        The original reason with source-selected native field detail, or the unchanged generic
        reason where no such native purpose is defined. No identity or location is invented.
    """
    if pointer == "/environment_ref" and schema_id in (
        "evidence_manifest_toolkit.manifest.v1",
        "evidence_manifest_toolkit.target_descriptor.v1",
    ):
        detail = {
            "reference_unavailable": "The required environment reference is unavailable.",
            "reference_mismatch": "The required environment reference does not match.",
        }.get(reason.code)
        if detail is not None:
            return Reason(
                reason.code, reason.subject_digest, reason.claim_id, reason.pointer, detail
            )
    return reason
