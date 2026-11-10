# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete rotation continuity through actual public verification

"""Exercise full source histories without claiming accepted rotation or machine keys."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest
from tests.domain.protected_rotation_inputs import ROTATION_SOURCE_CASES, protected_rotation_input
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


@pytest.mark.parametrize("case", ROTATION_SOURCE_CASES)
def test_complete_rotation_source_continuity(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Keep earlier keys, full sources and typed public refusal semantics exact.

    Parameters
    ----------
    case : str
        Actual complete state/control source or one independently authored contradiction.
    tmp_path : Path
        Owned real whole-source files; original published corpus stays immutable.
    capfd : pytest.CaptureFixture
        Real CLI stdout/stderr descriptors, without replacing any product provider.
    """
    cli = case.startswith("cli_")
    chosen = protected_rotation_input(case.removeprefix("cli_"), tmp_path)
    inputs = chosen.inputs
    before = {path: path.read_bytes() for path in chosen.population.values() if path.exists()}
    resolver = _FileResolver(chosen.population)
    if cli:
        wire = _object(_mapping(chosen.caller))
        if chosen.caller.evaluation_mode == "current":
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
        assert not captured.err and not report.exists() and status == (3 if chosen.missing else 2)
    else:
        with pytest.raises(ReferenceUnavailable if chosen.missing else InputRefused) as error:
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
        actual = asdict(error.value.reason)
        if chosen.missing:
            assert (
                isinstance(error.value, ReferenceUnavailable)
                and error.value.reference == chosen.missing
            )
        elif not chosen.expected_pointer:
            assert all(ref in {ref for ref, _ in resolver.calls} for ref in chosen.required_sources)
    expected = {
        "code": "reference_unavailable" if chosen.missing else chosen.expected_code,
        "subject_digest": None
        if chosen.missing
        else chosen.expected_subject or chosen.policy_ref.digest,
        "claim_id": None,
        "pointer": None
        if chosen.missing
        else chosen.expected_pointer
        or "/required_evaluation_time_qualification/clock_qualification_ref",
        "detail": "Required reference unavailable."
        if chosen.missing
        else "Protected state sources conflict."
        if chosen.expected_pointer
        else "The required evaluation-time qualification is unavailable.",
    }
    if chosen.expected_code == "invalid_schema":
        expected["detail"] = "Input violates its selected schema."
    assert actual == expected
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert all(path.read_bytes() == raw for path, raw in chosen.original_bytes.items())
