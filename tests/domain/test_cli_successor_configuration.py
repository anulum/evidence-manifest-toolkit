# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete caller configuration through the offline CLI

"""Exercise whole V2 caller wire refusals and actual legacy report recovery through processes."""

import json
from pathlib import Path
from typing import Literal

import pytest
from tests.domain.test_cli_evidence_sources import (
    _hashes,
    _inputs,
    _object,
    _run,
    _source,
    _transport,
)
from tests.domain.test_successor_trust import _callers, _sources
from tests.domain.test_verification_report_sources import _mapping


def _refusal(pointer: str, *, subject: str | None = None) -> bytes:
    """Retain the entire independently expected original caller-safe process refusal."""
    return _transport(
        {
            "operation": "verify",
            "reasons": [
                {
                    "code": "configuration_error",
                    "subject_digest": subject,
                    "claim_id": None,
                    "pointer": pointer,
                    "detail": "Invalid local configuration."
                    if subject is None
                    else "Invalid local trust or policy configuration.",
                }
            ],
        }
    )


@pytest.mark.parametrize("profile_index", (0, 1, 2))
@pytest.mark.parametrize("mode", ("current", "historical"))
def test_whole_successor_cli_fields_refuse_without_legacy_downgrade_and_recover(
    profile_index: int, mode: Literal["current", "historical"], tmp_path: Path
) -> None:
    """Locate exact V2 caller faults and recover the entire unchanged legacy report.

    Parameters
    ----------
    profile_index : int
        Independently selected unsigned, software or delegated public caller class.
    mode : {"current", "historical"}
        Original explicit scope, including the complete required software/protected archive.
    tmp_path : Path
        Real caller JSON files, flat original object store and fresh output destinations.

    Notes
    -----
    Binding references are actual original fixture bytes used as carrier declarations only.
    They are deliberately not qualified Clock or authority sources. Pairing must reject
    the original legacy policy rather than invent bootstrap fields or downgrade class.
    """
    source = _source("verify-current-whole-fixture")
    arguments = _inputs(source, tmp_path)
    trust_path = tmp_path / "trust.json"
    legacy_trust = trust_path.read_bytes()
    preserved = _hashes(tmp_path)
    binding, references, originals = _sources()
    caller = _callers(binding, references, mode)[profile_index]
    wire = _object(_mapping(caller))
    for archive in ("archived_software_authorization_ref", "archived_authority_snapshot_ref"):
        if archive in wire and wire[archive] is None:
            del wire[archive]
    faults: list[tuple[dict[str, object], str]] = [
        ({**wire, "namespace": "EMT_CALLER_TRUST_UNKNOWN_V2"}, "/trust/namespace"),
        ({**wire, "evaluation_time": "2026-02-30T12:00:00Z"}, "/trust/evaluation_time"),
    ]
    if profile_index == 0:
        changed_binding = _object(wire["clock_entry_binding"])
        changed_binding["first_sample_source_ref"] = {
            **references[0].to_mapping(),
            "digest": references[0].digest + "\n",
        }
        faults.append(
            (
                {**wire, "clock_entry_binding": changed_binding},
                "/trust/clock_entry_binding/first_sample_source_ref",
            )
        )
    elif profile_index == 1:
        faults.append(
            (
                {**wire, "accepted_authorization_sequence_floor": "1\n"},
                "/trust/accepted_authorization_sequence_floor",
            )
        )
    else:
        faults.append(({**wire, "control_envelopes": ["A"]}, "/trust/control_envelopes/0"))
    faults.append((wire, "/policy_ref"))
    destination = tmp_path / "refused-report.json"
    for supplied, pointer in faults:
        trust_path.write_bytes(_transport(supplied))
        before = _hashes(tmp_path)
        result = _run(arguments + ["--report", str(destination)], tmp_path)
        policy = _object(json.loads((tmp_path / "policy.json").read_bytes()))
        reference = _object(policy["policy_ref"])
        subject = str(reference["digest"]) if pointer == "/policy_ref" else None
        assert (result.returncode, result.stdout, result.stderr) == (
            4,
            _refusal(pointer, subject=subject),
            b"",
        )
        assert not destination.exists()
        assert _hashes(tmp_path) == before
    trust_path.write_bytes(legacy_trust)
    assert _hashes(tmp_path) == preserved
    recovered_path = tmp_path / "whole-legacy-recovery.json"
    recovered = _run(arguments + ["--report", str(recovered_path)], tmp_path)
    expected = _transport(source["expected_entire_VerificationReport"])
    assert (recovered.returncode, recovered.stdout, recovered.stderr) == (0, expected, b"")
    assert recovered_path.read_bytes() == expected
    assert all(path.read_bytes() == raw for path, raw in originals.items())
    assert {k: v for k, v in _hashes(tmp_path).items() if k in preserved} == preserved
