# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual earlier rotation key sources through public entry

"""Keep actual public rotation key refusals distinct from protected authority admission."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest
from tests.domain.protected_rotation_inputs import protected_rotation_input
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

from evidence_manifest_toolkit import InputRefused, VerificationPolicy, verify


@pytest.mark.parametrize(
    "case",
    (
        "control_new_key_withdrawn",
        "control_other_key_withdrawn",
        "control_certificate_withdrawn",
        "control_later_withdrawal",
        "control_bad_new_key_length",
        "control_bad_new_key_id",
        "control_bad_withdrawn_key_length",
        "cli_control_new_key_withdrawn",
        "cli_control_bad_new_key_length",
    ),
)
def test_actual_earlier_rotation_keys_and_unchanged_whole_sources(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Check actual whole state/key sources through the genuine API and CLI.

    Parameters
    ----------
    case : str
        Previously withdrawn new key, unrelated withdrawal, later-only withdrawal,
        malformed key data/identity, or actual CLI failure for the same inputs.
    tmp_path : Path
        Owned complete original native source population and actual resolver files.
    capfd : pytest.CaptureFixture
        Real native command stdout/stderr descriptors without replaced production I/O.

    Notes
    -----
    The existing complete native source corpus retains actual original grants,
    states, rotations and genuine published-test-key receipts. The keys are
    unprotected/unenrolled; matching inputs reach the original unavailable Clock
    boundary and never become an accepted protected transition or positive state.
    """
    cli = case.startswith("cli_")
    chosen = protected_rotation_input(case.removeprefix("cli_"), tmp_path)
    before = {path: path.read_bytes() for path in chosen.population.values() if path.exists()}
    inputs = chosen.inputs
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
        assert not captured.err and not report.exists() and status == 2
    else:
        with pytest.raises(InputRefused) as failure:
            verify(
                _bytes(inputs["content_json"]),
                schema_id=_text(inputs["schema_id"]),
                envelopes=(),
                registry=_registry(inputs["registry"]),
                resolver=_FileResolver(chosen.population),
                limits=chosen.limits,
                policy=VerificationPolicy(
                    chosen.policy_ref,
                    tuple(_text(value) for value in _array(chosen.declared["required_claim_ids"])),
                    ("evidence",),
                ),
                trust=chosen.caller,
            )
        actual = asdict(failure.value.reason)
    expected = {
        "code": chosen.expected_code,
        "subject_digest": chosen.expected_subject or chosen.policy_ref.digest,
        "claim_id": None,
        "pointer": chosen.expected_pointer
        or "/required_evaluation_time_qualification/clock_qualification_ref",
        "detail": "Protected state sources conflict."
        if chosen.expected_pointer
        else "The required evaluation-time qualification is unavailable.",
    }
    assert actual == expected
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert all(path.read_bytes() == raw for path, raw in chosen.original_bytes.items())
