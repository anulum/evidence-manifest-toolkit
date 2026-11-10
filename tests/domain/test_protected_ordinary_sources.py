# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — ordinary protected source matching through real public entry

"""Exercise complete receipt/certificate joins and exact API/CLI source refusal contracts."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest
from tests.domain.protected_ordinary_inputs import ORDINARY_SOURCE_CASES, protected_ordinary_input
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


@pytest.mark.parametrize("case", ORDINARY_SOURCE_CASES)
def test_whole_ordinary_protected_sources(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Reject actual whole target, membership, scope and window conflicts before Clock.

    Parameters
    ----------
    case : str
        Entire actual source graph or one independently selected input contradiction.
    tmp_path : Path
        Owned actual flat store, with no source/provider/sampler substitution.
    capfd : pytest.CaptureFixture
        Real module-command stdout and stderr descriptors.
    """
    chosen, envelopes, expected = protected_ordinary_input(case.removeprefix("cli_"), tmp_path)
    before = {path: path.read_bytes() for path in chosen.population.values() if path.exists()}
    inputs = chosen.inputs
    policy = VerificationPolicy(
        chosen.policy_ref,
        tuple(_text(x) for x in _array(chosen.declared["required_claim_ids"])),
        ("evidence",),
    )
    resolver = _FileResolver(chosen.population)
    if case.startswith("cli_"):
        wire = _object(_mapping(chosen.caller))
        if chosen.caller.evaluation_mode == "current":
            del wire["archived_authority_snapshot_ref"]
        status, report = invoke_rule_cli(
            tmp_path,
            population=chosen.population,
            schema_id=_text(inputs["schema_id"]),
            content_raw=_bytes(inputs["content_json"]),
            registry=inputs["registry"],
            limits=_mapping(chosen.limits),
            policy=_mapping(policy),
            trust=wire,
            envelopes=envelopes,
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
                envelopes=envelopes,
                registry=_registry(inputs["registry"]),
                resolver=resolver,
                limits=chosen.limits,
                policy=policy,
                trust=chosen.caller,
            )
        actual = asdict(error.value.reason)
        if chosen.missing:
            assert (
                isinstance(error.value, ReferenceUnavailable)
                and error.value.reference == chosen.missing
            )
        if case in {"matching", "parent", "historical"}:
            assert all(
                reference in {r for r, _ in resolver.calls} for reference in chosen.required_sources
            )
    assert actual == expected
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert all(path.read_bytes() == raw for path, raw in chosen.original_bytes.items())
