# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole withdrawal source checks through actual verification

"""Exercise ordered whole-state withdrawal conservation through public API and real CLI."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest
from tests.domain.protected_revocation_inputs import (
    REVOCATION_SOURCE_CASES,
    protected_revocation_input,
)
from tests.domain.signature_rule_cli import invoke_rule_cli
from tests.domain.test_cli_evidence_sources import _transport
from tests.domain.test_verification_report_sources import (
    _array,
    _bytes,
    _FileResolver,
    _mapping,
    _object,
    _registry,
    _text,
)

from evidence_manifest_toolkit import InputRefused, ReferenceUnavailable, VerificationPolicy, verify


@pytest.mark.parametrize("case", REVOCATION_SOURCE_CASES)
def test_whole_withdrawal_state_conservation(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Preserve full ordered revocations, state and native errors without admitting authority.

    Parameters
    ----------
    case : str
        Whole source-consistent input or one independently selected conflicting delta.
    tmp_path : Path
        Actual original inputs and native offline store under the owned test allocation.
    capfd : pytest.CaptureFixture
        Real CLI output capture, without substituting a production I/O or provider.
    """
    cli = case.startswith("cli_")
    chosen = protected_revocation_input(case.removeprefix("cli_"), tmp_path)
    before = {path: path.read_bytes() for path in chosen.population.values() if path.exists()}
    inputs = chosen.inputs
    resolver = _FileResolver(chosen.population)
    if cli:
        wire = _object(_mapping(chosen.caller))
        del wire["archived_authority_snapshot_ref"]
        status, report = invoke_rule_cli(
            tmp_path,
            population=chosen.population,
            schema_id=_text(inputs["schema_id"]),
            content_raw=_bytes(inputs["content_json"]),
            registry=inputs["registry"],
            limits=dict(_object(_mapping(chosen.limits))),
            policy={
                "policy_ref": dict(chosen.policy_ref.to_mapping()),
                "required_claim_ids": chosen.declared["required_claim_ids"],
                "required_purposes": ["evidence"],
            },
            trust=wire,
        )
        captured = capfd.readouterr()
        actual = _object(_array(_object(json.loads(captured.out))["reasons"])[0])
        assert captured.out.encode() == _transport({"operation": "verify", "reasons": [actual]})
        assert not captured.err and not report.exists()
        assert status == (3 if chosen.missing is not None else 2)
    else:
        with pytest.raises(ReferenceUnavailable if chosen.missing else InputRefused) as caught:
            verify(
                _bytes(inputs["content_json"]),
                schema_id=_text(inputs["schema_id"]),
                envelopes=(),
                registry=_registry(inputs["registry"]),
                resolver=resolver,
                limits=chosen.limits,
                policy=VerificationPolicy(
                    chosen.policy_ref,
                    tuple(_text(x) for x in _array(chosen.declared["required_claim_ids"])),
                    ("evidence",),
                ),
                trust=chosen.caller,
            )
        actual = asdict(caught.value.reason)
        if chosen.missing:
            assert (
                isinstance(caught.value, ReferenceUnavailable)
                and caught.value.reference == chosen.missing
            )
    expected = (
        {
            "code": "reference_unavailable",
            "subject_digest": None,
            "claim_id": None,
            "pointer": None,
            "detail": "Required reference unavailable.",
        }
        if chosen.missing
        else {
            "code": "policy_unavailable",
            "subject_digest": chosen.expected_subject or chosen.policy_ref.digest,
            "claim_id": None,
            "pointer": chosen.expected_pointer
            or "/required_evaluation_time_qualification/clock_qualification_ref",
            "detail": "Protected state sources conflict."
            if chosen.expected_pointer
            else "The required evaluation-time qualification is unavailable.",
        }
    )
    assert actual == expected
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert all(path.read_bytes() == raw for path, raw in chosen.original_bytes.items())
