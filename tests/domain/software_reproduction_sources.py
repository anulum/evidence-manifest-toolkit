# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — software pending record public source controls

"""Specify whole source errors and unresolved ordinary or record signature requirements."""

import json
from typing import cast

from tests.domain.reproduction_record_inputs import ReproductionOutcome
from tests.domain.test_verification_report_sources import _array, _bytes, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, reference_bytes

SOFTWARE_RECORD_CASES = (
    "software_receipt_reproduction_match",
    "software_receipt_reproduction_body_missing_no_schema",
    "software_receipt_reproduction_body_schema_no_schema",
    "software_receipt_reproduction_subject_json_no_schema",
    "software_reproduction_body_missing_no_schema",
    "cli_software_receipt_reproduction_match",
    "cli_software_receipt_reproduction_body_missing_no_schema",
)
SOFTWARE_RECORD_INPUTS = {
    name: name.removeprefix("cli_").removeprefix("software_receipt_").removeprefix("software_")
    for name in SOFTWARE_RECORD_CASES
}
PENDING_RECORD_SIGNATURE_CASES = frozenset(
    {
        "obligation_missing_record",
        "obligation_record_no_evidence",
        "software_receipt_obligation_record",
    }
)


def software_record_expected(
    condition: str, inputs: dict[str, object], original: ReproductionOutcome | None
) -> ReproductionOutcome:
    """Keep actual source failures or the original unresolved signature requirement.

    Parameters
    ----------
    condition : str
        Whole actual signed-source, malformed/missing source or unsigned ordinary case.
    inputs : dict
        Complete original native parent and all unchanged public limits.
    original : tuple or None
        Independently specified source outcome from the complete native fixture builder.

    Returns
    -------
    tuple
        Exact public reason and missing argument when applicable. Full native source
        acquisition never supplies independent execution or clears a record signature.
    """
    assert original is not None
    case = condition.removeprefix("cli_")
    content = _object(json.loads(_bytes(inputs["content_json"])))
    if case.startswith("software_reproduction_"):
        limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
        reference = reference_bytes(
            _bytes(inputs["content_json"]),
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id=_text(inputs["schema_id"]),
            limits=limits,
        )
        claim_id = None
        detail = "The required evidence signature is unavailable."
    elif case == "software_receipt_reproduction_match":
        claim = _object(_array(content["claims"])[1])
        reference = BlobRef.from_mapping(_object(_object(claim["validation"])["record_ref"]))
        claim_id = _text(claim["claim_id"])
        detail = "The required validation record signature is unavailable."
    else:
        return original
    return (
        "refused",
        {
            "code": "signature_required",
            "subject_digest": reference.digest,
            "claim_id": claim_id,
            "pointer": None,
            "detail": detail,
        },
        None,
    )
