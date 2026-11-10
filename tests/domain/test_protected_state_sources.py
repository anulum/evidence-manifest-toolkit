# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — real public protected state source conservation

"""Exercise whole native source histories without fabricating accepted root or Clock facts."""

import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest
import rfc8785
from tests.domain.method_rule_inputs import method_rule_inputs
from tests.domain.protected_control_inputs import prepare_control_base, protected_control_inputs
from tests.domain.protected_state_inputs import protected_state_inputs
from tests.domain.signature_rule_cli import invoke_rule_cli
from tests.domain.test_cli_evidence_sources import _transport
from tests.domain.test_policy_selection_sources import _successor_policy
from tests.domain.test_software_sources import _stored_source
from tests.domain.test_successor_trust import _callers, _sources
from tests.domain.test_verification_report_sources import (
    _array,
    _bytes,
    _FileResolver,
    _mapping,
    _object,
    _registry,
    _text,
)

from evidence_manifest_toolkit import (
    BlobRef,
    InputRefused,
    Limits,
    ReferenceUnavailable,
    VerificationPolicy,
    reference_bytes,
    verify,
)

type _StateJson = None | bool | int | float | str | list[_StateJson] | dict[str, _StateJson]

_CASES = (
    "current",
    "history",
    "historical",
    "until_withdrawal",
    "withdrawals_retained",
    "missing_root",
    "missing_grant",
    "missing_current",
    "missing_archive",
    "missing_previous",
    "grant_rule",
    "grant_root",
    "grant_rotation",
    "grant_window",
    "snapshot_authority",
    "snapshot_grant",
    "snapshot_window",
    "floor",
    "duplicate_certificates",
    "duplicate_identity_rules",
    "duplicate_revocations",
    "history_sequence",
    "history_time",
    "history_withdrawals",
    "history_depth",
    "archive_sequence",
    "archive_time",
    "root_json",
    "grant_json",
    "snapshot_json",
    "cli_current",
    "cli_missing_current",
)


@pytest.mark.parametrize("case", _CASES)
def test_whole_protected_state_history_through_public_verify(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Preserve exact whole source, stream, floor and withdrawal boundaries in public verification.

    Parameters
    ----------
    case : str
        Whole current/archive/history or independently selected source counterfactual.
    tmp_path : Path
        Actual owned immutable source bodies and explicit missing lookup targets.
    capfd : pytest.CaptureFixture
        Actual module CLI output descriptors, without replacing the verifier or resolver.

    Notes
    -----
    Source-consistent cases reach the actual required Clock refusal. No declaration,
    public test key, empty control list or initial snapshot is admitted as authority.
    """
    cli = case.startswith("cli_")
    case = case.removeprefix("cli_")
    inputs, declared, base, population, originals = prepare_control_base(tmp_path)
    bounds = _object(inputs["limits"])
    limits = Limits(**cast(dict[str, int], bounds))
    binding, references, carriers = _sources()
    originals.update(carriers)
    historical = case in {"historical", "missing_archive", "archive_sequence", "archive_time"}
    caller = _callers(binding, references, "historical" if historical else "current")[2]
    root_raw = b"{" if case == "root_json" else b"\n" + (tmp_path / base.digest[7:]).read_bytes()
    root = reference_bytes(
        root_raw,
        media_type="application/json",
        digest_basis="raw_bytes",
        schema_id=None,
        limits=limits,
    )
    root_path = tmp_path / root.digest[7:]
    root_path.write_bytes(root_raw)
    population[root.digest + "|raw_bytes"] = root_path
    rule, selection, controls, objects = protected_control_inputs(base, tmp_path, root=root)
    population.update(objects)
    grant, current, objects = protected_state_inputs(base, rule, root, tmp_path)
    population.update(objects)

    def body(reference: BlobRef) -> dict[str, object]:
        """Read the entire actual source without projecting any member."""
        return dict(_object(json.loads((tmp_path / reference.digest[7:]).read_bytes())))

    def store(value: dict[str, object], schema: str) -> BlobRef:
        """Keep the complete canonical native body and original public reference calculation."""
        raw = rfc8785.dumps(cast(dict[str, _StateJson], value))
        reference = reference_bytes(
            raw,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id=schema,
            limits=limits,
        )
        path = tmp_path / reference.digest[7:]
        path.write_bytes(raw)
        population[reference.digest + "|jcs_content"] = path
        return reference

    def malformed_source(schema: str) -> BlobRef:
        """Retain actual incomplete JSON bytes and a truthful whole raw reference."""
        raw = b"{"
        reference = reference_bytes(
            raw,
            media_type="application/json",
            digest_basis="raw_bytes",
            schema_id=schema,
            limits=limits,
        )
        path = tmp_path / reference.digest[7:]
        path.write_bytes(raw)
        population[reference.digest + "|raw_bytes"] = path
        return reference

    grant_body = body(grant)
    expected_pointer = ""
    expected_subject: str | None = None
    if case.startswith("grant_") and case != "grant_json":
        field = {
            "grant_rule": "automation_policy_ref",
            "grant_root": "root_selection_source_ref",
            "grant_rotation": "rotation_rule_ref",
        }.get(case)
        if field is not None:
            grant_body[field] = dict((root if case == "grant_rotation" else base).to_mapping())
            expected_pointer = "/" + field
        else:
            grant_body["lifetime"] = {
                "kind": "finite",
                "not_before": "2030-01-01T00:00:00Z",
                "not_after": "2030-01-01T00:00:00Z",
            }
            expected_pointer = "/lifetime/not_after"
    if case == "until_withdrawal":
        grant_body["lifetime"] = {
            "kind": "until_withdrawal",
            "not_before": "2020-01-01T00:00:00Z",
            "not_after": None,
        }
    grant = store(grant_body, "evidence_manifest_toolkit.authority_grant.v2")
    if case.startswith("grant_") and case != "grant_json":
        expected_subject = grant.digest
    if case == "grant_json":
        grant = malformed_source("evidence_manifest_toolkit.authority_grant.v2")
    snapshot = body(current)
    snapshot["root_grant_ref"] = dict(grant.to_mapping())
    revocation: dict[str, object] = {
        "target_kind": "authority_scope",
        "target_ref": dict(base.to_mapping()),
        "reason": "compromise",
        "reported_at": "2020-01-01T00:00:00Z",
        "compromise_window": "unknown",
        "compromise_time_bounds_ref": None,
    }
    previous: BlobRef | None = None
    has_history = case in {
        "history",
        "historical",
        "missing_previous",
        "withdrawals_retained",
    } or case.startswith("history_")
    if has_history:
        parent = {**snapshot, "sequence": "0"}
        if case == "history_sequence":
            parent["sequence"] = "1"
            expected_pointer = "/sequence"
        if case == "history_time":
            parent["issued_at"] = "2022-01-01T00:00:00Z"
            expected_pointer = "/issued_at"
        if case in {"withdrawals_retained", "history_withdrawals"}:
            parent["revocations"] = [revocation]
            if case == "withdrawals_retained":
                snapshot["revocations"] = [revocation]
            else:
                expected_pointer = "/revocations"
        previous = store(parent, "evidence_manifest_toolkit.authority_snapshot.v2")
        snapshot["previous_snapshot_ref"] = dict(previous.to_mapping())
        snapshot["issued_at"] = "2021-01-01T00:00:00Z"
    if case == "history_depth":
        assert previous is not None
        for sequence in ("1", "2", "3"):
            parent = {
                **snapshot,
                "sequence": sequence,
                "issued_at": "2020-01-01T00:00:00Z",
                "previous_snapshot_ref": dict(previous.to_mapping()),
            }
            previous = store(parent, "evidence_manifest_toolkit.authority_snapshot.v2")
            if sequence == "2":
                expected_subject = previous.digest
        snapshot["sequence"] = "4"
        snapshot["previous_snapshot_ref"] = dict(previous.to_mapping())
        limits = replace(limits, max_graph_depth=3)
        expected_pointer = "/previous_snapshot_ref"
    if case in {"snapshot_authority", "snapshot_grant", "snapshot_window"}:
        field = {
            "snapshot_authority": "authority_id",
            "snapshot_grant": "root_grant_ref",
            "snapshot_window": "expires_at",
        }[case]
        snapshot[field] = (
            "different-source-stream"
            if field == "authority_id"
            else dict(base.to_mapping())
            if field == "root_grant_ref"
            else snapshot["issued_at"]
        )
        expected_pointer = "/" + field
    if case.startswith("duplicate_"):
        field = {
            "duplicate_certificates": "certificate_refs",
            "duplicate_identity_rules": "identity_rule_refs",
            "duplicate_revocations": "revocations",
        }[case]
        item = revocation if field == "revocations" else dict(base.to_mapping())
        snapshot[field] = [item, item]
        expected_pointer = "/" + field
    current = store(snapshot, "evidence_manifest_toolkit.authority_snapshot.v2")
    if case.startswith(("snapshot_", "duplicate_", "history_")) and case != "history_depth":
        expected_subject = current.digest
    if case == "snapshot_json":
        current = malformed_source("evidence_manifest_toolkit.authority_snapshot.v2")
    archive = previous if case == "historical" else current
    if historical and case != "historical":
        archive = store(
            {**snapshot, "sequence": "0", "previous_snapshot_ref": None},
            "evidence_manifest_toolkit.authority_snapshot.v2",
        )
    if case in {"archive_sequence", "archive_time"}:
        archived = (
            {**snapshot, "sequence": "2"}
            if case == "archive_sequence"
            else {**snapshot, "issued_at": "2025-01-01T00:00:00Z"}
        )
        archive = store(archived, "evidence_manifest_toolkit.authority_snapshot.v2")
        expected_pointer = "/trust/archived_authority_snapshot_ref"
    caller = replace(
        caller,
        independent_root_selection_ref=root,
        root_grant_ref=grant,
        current_authority_snapshot_ref=current,
        accepted_authority_sequence_floor="2" if case == "floor" else "1",
        authority_control_selection_ref=selection,
        control_envelopes=controls,
        archived_authority_snapshot_ref=archive if historical else None,
    )
    value = _successor_policy(base)
    value.update(
        profile_class=caller.profile_class,
        authority_rule_ref=dict(rule.to_mapping()),
        root_grant_ref=dict(grant.to_mapping()),
    )
    fields, objects = method_rule_inputs(base, tmp_path, profile_class=caller.profile_class)
    population.update(objects)
    value.update(fields)
    policy_ref = _stored_source(
        value, tmp_path, schema_id="evidence_manifest_toolkit.authority_policy.v2"
    )
    population[policy_ref.digest + "|raw_bytes"] = tmp_path / policy_ref.digest[7:]
    missing = {
        "missing_root": root,
        "missing_grant": grant,
        "missing_current": current,
        "missing_archive": archive,
        "missing_previous": previous,
    }.get(case)
    if missing is not None:
        population[missing.digest + "|" + missing.digest_basis] = (
            tmp_path / "intentionally-absent-whole-source"
        )
    actual_bytes = {path: path.read_bytes() for path in population.values() if path.exists()}
    resolver = _FileResolver(population)
    if cli:
        wire = _object(_mapping(caller))
        if not historical:
            del wire["archived_authority_snapshot_ref"]
        status, report = invoke_rule_cli(
            tmp_path,
            population=population,
            schema_id=_text(inputs["schema_id"]),
            content_raw=_bytes(inputs["content_json"]),
            registry=inputs["registry"],
            limits=inputs["limits"],
            policy={
                "policy_ref": dict(policy_ref.to_mapping()),
                "required_claim_ids": declared["required_claim_ids"],
                "required_purposes": ["evidence"],
            },
            trust=wire,
        )
        captured = capfd.readouterr()
        document = _object(json.loads(captured.out))
        actual_reason = _object(_array(document["reasons"])[0])
        assert captured.out.encode() == _transport(
            {"operation": "verify", "reasons": [actual_reason]}
        )
        assert not captured.err and not report.exists()
        assert status == (3 if missing is not None else 2)
    else:
        with pytest.raises(ReferenceUnavailable if missing is not None else InputRefused) as caught:
            verify(
                _bytes(inputs["content_json"]),
                schema_id=_text(inputs["schema_id"]),
                envelopes=(),
                registry=_registry(inputs["registry"]),
                resolver=resolver,
                limits=limits,
                policy=VerificationPolicy(
                    policy_ref,
                    tuple(_text(x) for x in _array(declared["required_claim_ids"])),
                    ("evidence",),
                ),
                trust=caller,
            )
        actual_reason = asdict(caught.value.reason)
    if missing is not None:
        if not cli:
            assert (
                isinstance(caught.value, ReferenceUnavailable) and caught.value.reference == missing
            )
        expected = {
            "code": "reference_unavailable",
            "subject_digest": None,
            "claim_id": None,
            "pointer": None,
            "detail": "Required reference unavailable.",
        }
    elif case.endswith("_json"):
        expected = {
            "code": "invalid_json",
            "subject_digest": root.digest
            if case == "root_json"
            else grant.digest
            if case == "grant_json"
            else current.digest,
            "claim_id": None,
            "pointer": "",
            "detail": "Input is not valid strict JSON.",
        }
    elif expected_pointer or case == "floor":
        expected = {
            "code": "limit_exceeded" if case == "history_depth" else "policy_unavailable",
            "subject_digest": policy_ref.digest
            if case == "floor" or case.startswith("archive_")
            else expected_subject,
            "claim_id": None,
            "pointer": "/trust/accepted_authority_sequence_floor"
            if case == "floor"
            else expected_pointer,
            "detail": "Protected state sources conflict.",
        }
    else:
        expected = {
            "code": "policy_unavailable",
            "subject_digest": policy_ref.digest,
            "claim_id": None,
            "pointer": "/required_evaluation_time_qualification/clock_qualification_ref",
            "detail": "The required evaluation-time qualification is unavailable.",
        }
        if not cli:
            acquired = tuple(reference for reference, _ in resolver.calls)
            assert root in acquired and grant in acquired and current in acquired
            if previous is not None:
                assert previous in acquired
    assert actual_reason == expected
    assert all(path.read_bytes() == raw for path, raw in actual_bytes.items())
    assert all(path.read_bytes() == raw for path, raw in originals.items())
