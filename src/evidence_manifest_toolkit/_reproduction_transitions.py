# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact whole independent validation parent transitions

"""Compare entire earlier and final manifests without accepting execution or authority."""

from copy import deepcopy
from dataclasses import dataclass
from typing import cast

import rfc8785

from ._errors import InputRefused
from ._json import AcquiredDocument, JsonValue, canonicalize_json
from ._reproduction_record_relations import ReproductionRecordSources
from ._reproduction_subjects import ReproductionSubject
from ._values import Limits, Reason


@dataclass(frozen=True, slots=True)
class ReproductionTransition:
    """Retain a whole structurally corresponding single-claim parent transition.

    Attributes
    ----------
    parent, earlier : ReproductionSubject
        Entire actual later and earlier manifests, not a projection of one claim.
    record : ReproductionRecordSources
        Exact actual package/body/identity graph. Its earlier policy/time/run/native
        admission remains independently required, including for inherited records.
    """

    parent: ReproductionSubject
    earlier: ReproductionSubject
    record: ReproductionRecordSources


def reproduction_transition_matches(
    parent: ReproductionSubject,
    earlier: ReproductionSubject,
    record: ReproductionRecordSources,
    *,
    limits: Limits,
) -> bool:
    """Reconstruct the entire parent with only the selected native validation changes.

    Parameters
    ----------
    parent, earlier : ReproductionSubject
        Whole actual native/common-valid source manifests with original numeric custody.
    record : ReproductionRecordSources
        Full explicitly referenced package and its actual earlier body and identity sources.
    limits : Limits
        Original operation bounds, never a larger reconstruction allowance.

    Returns
    -------
    bool
        True only for exact whole canonical correspondence. This is no authorization,
        independent execution, comparison, Clock, non-use or class acceptance verdict.

    Raises
    ------
    InputRefused
        Actual package/body/claim/subject/policy or producer correspondence conflicts,
        or whole canonical reconstruction exceeds an original source bound.
    """
    package = cast(
        dict[str, JsonValue], cast(AcquiredDocument, record.record.source.document).value
    )
    body = cast(dict[str, JsonValue], cast(AcquiredDocument, record.body.source.document).value)
    runner = cast(dict[str, JsonValue], cast(AcquiredDocument, record.runner.source.document).value)
    producer = cast(
        dict[str, JsonValue], cast(AcquiredDocument, record.producer.source.document).value
    )
    target = cast(dict[str, JsonValue], parent.document.value)
    claim_id = record.claim.claim_id
    for source, field, actual, expected in (
        (record.record, "subject_ref", package["subject_ref"], body["subject_ref"]),
        (record.record, "whole_policy_ref", package["whole_policy_ref"], body["whole_policy_ref"]),
        (record.record, "claim_id", package["claim_id"], claim_id),
        (record.body, "claim_id", body["claim_id"], claim_id),
        (
            record.producer,
            "principal_id",
            producer["principal_id"],
            cast(dict[str, JsonValue], target["producer"])["principal"],
        ),
    ):
        if actual != expected:
            raise InputRefused(
                Reason(
                    "invalid_claim",
                    source.source.reference.digest,
                    claim_id,
                    "/" + field,
                    "Independent validation sources conflict.",
                )
            )
    reconstructed = deepcopy(cast(dict[str, JsonValue], earlier.document.value))
    claims = cast(list[dict[str, JsonValue]], reconstructed["claims"])
    selected = next((claim for claim in claims if claim["claim_id"] == claim_id), None)
    if selected is None or selected["origin"] not in ("executed", "simulated", "measured"):
        return False
    selected.update(
        evidence_maturity="validated",
        verdict=body["outcome"],
        validation={
            "status": "independently_reproduced",
            "record_ref": cast(JsonValue, dict(record.record.source.reference.to_mapping())),
            "runner_id": runner["principal_id"],
            "independent_of_producer": True,
        },
    )
    expected_bytes = canonicalize_json(rfc8785.dumps(reconstructed), limits=limits)
    return expected_bytes == parent.canonical_content
