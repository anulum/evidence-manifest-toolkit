# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete ordinary protected obligation inputs

"""Prepare whole original obligation sources before the actual independent selections."""

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

from tests.domain.method_rule_inputs import method_rule_inputs
from tests.domain.protected_certificate_inputs import CertificateSourceCase
from tests.domain.protected_control_inputs import prepare_control_base, protected_control_inputs
from tests.domain.protected_state_inputs import protected_state_inputs
from tests.domain.signature_obligation_inputs import obligation_inputs
from tests.domain.test_policy_selection_sources import _successor_policy
from tests.domain.test_software_sources import _stored_source
from tests.domain.test_successor_trust import _callers, _sources
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import Limits


def protected_obligation_input(case: str, directory: Path) -> CertificateSourceCase:
    """Build whole global-purpose or intrinsic-claim obligations with real source files.

    Parameters
    ----------
    case : str
        Empty explicit required-claim population or independent intrinsic signature demand.
    directory : Path
        Owned complete source store; validation declarations remain unqualified test inputs.

    Returns
    -------
    CertificateSourceCase
        Entire original C0, policy and independently selected source graph. No declared
        validation record is presented as an actual accepted independent reproduction.
    """
    inputs, declared, base, population, originals = prepare_control_base(directory)
    body = _object(json.loads((directory / base.digest[7:]).read_bytes()))
    if case == "global_purpose":
        body["required_claim_ids"] = []
        declared["required_claim_ids"] = []
    else:
        inputs = obligation_inputs("software_receipt_obligation_intrinsic", inputs, directory)
        declared = _object(inputs["policy"])
        body["required_claim_ids"] = declared["required_claim_ids"]
    base = _stored_source(body, directory)
    binding, references, carriers = _sources()
    originals.update(carriers)
    caller = _callers(binding, references, "current")[2]
    rule, selection, controls, objects = protected_control_inputs(base, directory)
    population.update(objects)
    grant, snapshot, objects = protected_state_inputs(base, rule, base, directory)
    population.update(objects)
    caller = replace(
        caller,
        independent_root_selection_ref=base,
        root_grant_ref=grant,
        current_authority_snapshot_ref=snapshot,
        accepted_authority_sequence_floor="1",
        authority_control_selection_ref=selection,
        control_envelopes=controls,
    )
    policy = _successor_policy(base)
    policy.update(
        profile_class=caller.profile_class,
        authority_rule_ref=dict(rule.to_mapping()),
        root_grant_ref=dict(grant.to_mapping()),
    )
    fields, objects = method_rule_inputs(base, directory, profile_class=caller.profile_class)
    population.update(objects)
    policy.update(fields)
    policy_ref = _stored_source(
        policy, directory, schema_id="evidence_manifest_toolkit.authority_policy.v2"
    )
    return CertificateSourceCase(
        dict(inputs),
        dict(declared),
        Limits(**cast(dict[str, int], _object(inputs["limits"]))),
        caller,
        policy_ref,
        population,
        originals,
        None,
        None,
        "",
        "policy_unavailable",
        "The required evaluation-time qualification is unavailable.",
        (),
        None,
    )
