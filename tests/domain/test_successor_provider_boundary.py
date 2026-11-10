# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit method and real missing-provider boundary

"""Exercise complete V2 source selection without a signature provider or legacy state."""

import hashlib
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Literal

from tests.domain.method_rule_inputs import method_rule_inputs
from tests.domain.protected_control_inputs import protected_control_inputs
from tests.domain.protected_state_inputs import protected_state_inputs
from tests.domain.test_cli_evidence_sources import _hashes, _inputs, _run, _source, _transport
from tests.domain.test_policy_selection_sources import _successor_policy
from tests.domain.test_signature_provider_sources import (
    _METHOD_SOURCE,
    _original,
    _without_provider,
)
from tests.domain.test_software_sources import _software_table
from tests.domain.test_successor_trust import _callers, _sources
from tests.domain.test_verification_report_sources import _mapping, _object

from evidence_manifest_toolkit import BlobRef, DelegatedTrustContextV2, SoftwareTrustContextV2

_ROOT = Path(__file__).resolve().parents[2]


def _stored(value: object, directory: Path, *, schema_id: str | None = None) -> BlobRef:
    """Retain a whole actual test carrier in the ordinary read-only object store.

    Parameters
    ----------
    value : object
        Complete independently supplied configuration, never a Clock or authority proof.
    directory : Path
        Existing flat object store, retaining every original source file.
    schema_id : str or None
        Explicit registered assertion for the selected whole enclosing policy only.

    Returns
    -------
    BlobRef
        Full actual raw identity; no source qualification follows from matching bytes.
    """
    raw = _transport(value)
    digest = hashlib.sha256(raw).hexdigest()
    (directory / digest).write_bytes(raw)
    return BlobRef("sha256:" + digest, str(len(raw)), "application/json", "raw_bytes", schema_id)


def test_real_missing_provider_does_not_replace_v2_method_errors_or_legacy_recovery(
    tmp_path: Path,
) -> None:
    """Reach exact V2 policy/state boundaries without Crypto and recover the whole legacy report.

    Parameters
    ----------
    tmp_path : Path
        Owned offline uv/hardlink fault prefix, actual original input files and destinations.

    Notes
    -----
    The operational policy carrier explicitly has no Clock witness. It is not qualified
    time or authority and cannot produce V2 success. The existing native-state boundary
    must refuse it without initializing an unrelated legacy verification provider.
    """
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(tmp_path), TMP=str(tmp_path), TEMP=str(tmp_path)
    )
    python = _without_provider(tmp_path / "absent-provider", environment)
    caller_dir = tmp_path / "caller"
    caller_dir.mkdir()
    source = _source("verify-current-whole-fixture")
    arguments = _inputs(source, caller_dir)
    trust_path, policy_path = caller_dir / "trust.json", caller_dir / "policy.json"
    original_trust, original_policy = trust_path.read_bytes(), policy_path.read_bytes()
    preserved = _hashes(caller_dir)
    error_source = _object(json.loads(_original(_METHOD_SOURCE)))
    output = caller_dir / "refused-report.json"
    first = subprocess.run(
        [str(python), "-B", "-m", "evidence_manifest_toolkit", *arguments, "--report", str(output)],
        cwd=_ROOT / "src",
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert (first.returncode, first.stdout, first.stderr) == (
        4,
        _transport(error_source["expected_entire_ErrorResult"]),
        b"",
    )
    assert not output.exists() and _hashes(caller_dir) == preserved
    policy = _object(json.loads(original_policy))
    original_ref = BlobRef.from_mapping(_object(policy["policy_ref"]))
    ordinary = _object(json.loads((caller_dir / "objects" / original_ref.digest[7:]).read_bytes()))
    for key in ("actual_accepted_configuration", "source_chain_ref"):
        ordinary.pop(key)
    ordinary.update(
        namespace="OWNER_LOCAL_VERIFICATION_POLICY_V1",
        time_rule="Explicit caller UTC under original half-open snapshot/certificate windows; "
        "independently qualified evaluation-time source required.",
        root_and_key_rule="Existing independently owner-approved local bootstrap/current "
        "configuration; no artifact approval or root provisioning.",
        required_evaluation_time_qualification={
            "requirement": "independent previously accepted clock/time-selection method and full "
            "source/capture/controller identity",
            "clock_qualification_ref": None,
            "actual_qualification": "unavailable",
            "caller_utc_string_is_qualification": False,
            "source_contract": "Existing selected common8 UTC/time qualification boundary; this "
            "explicit prospective policy extension needs affected selection and adds no "
            "TrustContext field.",
        },
    )
    ordinary_ref = _stored(ordinary, caller_dir / "objects")
    binding, references, originals = _sources()
    without_signatures = [
        value
        for index, value in enumerate(arguments)
        if value != "--signature" and (index == 0 or arguments[index - 1] != "--signature")
    ]
    modes: tuple[Literal["current", "historical"], ...] = ("current", "historical")
    for mode in modes:
        for caller in _callers(binding, references, mode):
            if isinstance(caller, SoftwareTrustContextV2):
                table = _software_table(
                    ordinary_ref,
                    caller_dir / "objects",
                    sequence=caller.accepted_authorization_sequence_floor,
                )
                caller = replace(
                    caller,
                    software_authorization_ref=table,
                    archived_software_authorization_ref=table if mode == "historical" else None,
                )
            selected = _successor_policy(ordinary_ref)
            selected["profile_class"] = caller.profile_class
            if caller.profile_class != "unsigned_declared":
                selected["authority_rule_ref"] = dict(ordinary_ref.to_mapping())
            if isinstance(caller, DelegatedTrustContextV2):
                selected["root_grant_ref"] = dict(caller.root_grant_ref.to_mapping())
                rule, selection, controls, _ = protected_control_inputs(
                    ordinary_ref, caller_dir / "objects"
                )
                caller = replace(
                    caller,
                    independent_root_selection_ref=ordinary_ref,
                    authority_control_selection_ref=selection,
                    control_envelopes=controls,
                )
                grant, snapshot, _ = protected_state_inputs(
                    ordinary_ref,
                    rule,
                    ordinary_ref,
                    caller_dir / "objects",
                    sequence=caller.accepted_authority_sequence_floor,
                )
                caller = replace(
                    caller,
                    root_grant_ref=grant,
                    current_authority_snapshot_ref=snapshot,
                    archived_authority_snapshot_ref=snapshot
                    if caller.evaluation_mode == "historical"
                    else None,
                )
                selected["root_grant_ref"] = dict(grant.to_mapping())
                selected["authority_rule_ref"] = dict(rule.to_mapping())
            rule_fields, _ = method_rule_inputs(
                ordinary_ref, caller_dir / "objects", profile_class=caller.profile_class
            )
            selected.update(rule_fields)
            wire = _object(_mapping(caller))
            for archive in (
                "archived_software_authorization_ref",
                "archived_authority_snapshot_ref",
            ):
                if wire.get(archive, "absent") is None:
                    del wire[archive]
            trust_path.write_bytes(_transport(wire))
            selected_ref = _stored(
                selected,
                caller_dir / "objects",
                schema_id="evidence_manifest_toolkit.authority_policy.v2",
            )
            for chosen, pointer in (
                (policy, "/policy_ref"),
                (
                    {**policy, "policy_ref": dict(selected_ref.to_mapping())},
                    "/required_evaluation_time_qualification/clock_qualification_ref",
                ),
            ):
                policy_path.write_bytes(_transport(chosen))
                before = _hashes(caller_dir)
                result = subprocess.run(
                    [
                        str(python),
                        "-B",
                        "-m",
                        "evidence_manifest_toolkit",
                        *without_signatures,
                        "--report",
                        str(output),
                    ],
                    cwd=_ROOT / "src",
                    env=environment,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                assert (result.returncode, result.stdout, result.stderr) == (
                    4 if pointer == "/policy_ref" else 2,
                    _transport(
                        {
                            "operation": "verify",
                            "reasons": [
                                {
                                    "code": "configuration_error"
                                    if pointer == "/policy_ref"
                                    else "policy_unavailable",
                                    "subject_digest": original_ref.digest
                                    if pointer == "/policy_ref"
                                    else selected_ref.digest,
                                    "claim_id": None,
                                    "pointer": pointer,
                                    "detail": "Invalid local trust or policy configuration."
                                    if pointer == "/policy_ref"
                                    else "The required evaluation-time qualification is unavailable.",
                                }
                            ],
                        }
                    ),
                    b"",
                )
                assert not output.exists() and _hashes(caller_dir) == before
    trust_path.write_bytes(original_trust)
    policy_path.write_bytes(original_policy)
    destination = caller_dir / "whole-recovery.json"
    recovered = _run(arguments + ["--report", str(destination)], caller_dir)
    expected = _transport(source["expected_entire_VerificationReport"])
    assert (recovered.returncode, recovered.stdout, recovered.stderr) == (0, expected, b"")
    assert destination.read_bytes() == expected
    assert {
        name: sha for name, sha in _hashes(caller_dir).items() if name in preserved
    } == preserved
    assert all(path.read_bytes() == raw for path, raw in originals.items())
