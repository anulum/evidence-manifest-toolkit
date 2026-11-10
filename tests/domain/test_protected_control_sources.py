# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual whole protected selection through public verification

"""Exercise exact selected control sources without claiming protected state admission."""

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest
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
    ConfigurationError,
    InputRefused,
    Limits,
    ReferenceUnavailable,
    VerificationPolicy,
    verify,
)

_OPERATIONS = (
    "authority_grant",
    "issue_certificate",
    "rotate_authority",
    "issue_snapshot",
    "revoke_descendants",
)
_CASES = (
    "empty",
    *_OPERATIONS,
    "all_operations",
    "raw_whitespace",
    "canonical_digest",
    "missing_receipt",
    "extra_receipt",
    "reordered_receipts",
    "duplicate_receipt",
    "statement_ref",
    "target_ref",
    "signer_key_id",
    "authorizing_state_ref",
    "authorization_ref",
    "scope_ref",
    "operation",
    "missing_rule",
    "missing_selection",
    "rule_format",
    "selection_format",
    "rule_join",
    "root_join",
    "conditions_join",
    "missing_statement",
    "missing_target",
    "statement_bytes",
    "target_bytes",
    "base_missing",
    "base_json",
    "base_object",
    "base_fixture",
    "base_no_clock",
    "base_has_clock",
    "descendant_missing",
    "descendant_bytes",
    "oversized_receipt",
    "cli_empty",
    "cli_signer_key_id",
    "cli_missing_selection",
    "cli_empty_missing_selection",
)


@pytest.mark.parametrize("case", _CASES)
def test_public_whole_protected_control_correspondence(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Preserve actual original sources, whole selected matches and exact typed refusals.

    Parameters
    ----------
    case : str
        Entire matching operation/population or one located original source contradiction.
    tmp_path : Path
        Owned real whole inputs and resolver files; published corpus remains unchanged.
    capfd : pytest.CaptureFixture
        Real command stdout/stderr capture, without replacing any product I/O function.

    Notes
    -----
    Source-consistent graphs reach the actual unqualified Clock refusal, not accepted
    protected state. The generic certificate/all-operation populations select ordinary
    B as a parent, which must fail its fixed native schema before later predicates.
    Published test key signatures are real but unprotected/unenrolled;
    opaque root/custody/procedure sources qualify no authority, time or transition.
    """
    cli = case.startswith("cli_")
    case = case.removeprefix("cli_")
    empty_missing_selection = case == "empty_missing_selection"
    if empty_missing_selection:
        case = "missing_selection"
    inputs, declared, base_ref, population, originals = prepare_control_base(tmp_path)
    original_ref = BlobRef.from_mapping(_object(declared["policy_ref"]))
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    base = _object(json.loads((tmp_path / base_ref.digest[7:]).read_bytes()))
    binding, references, carrier_sources = _sources()
    originals.update(carrier_sources)
    caller = _callers(binding, references, "current")[2]
    policy_value = _successor_policy(base_ref)
    policy_value.update(
        profile_class=caller.profile_class, root_grant_ref=dict(caller.root_grant_ref.to_mapping())
    )
    methods, objects = method_rule_inputs(base_ref, tmp_path, profile_class=caller.profile_class)
    policy_value.update(methods)
    population.update(objects)
    operations = (
        ()
        if case == "empty" or empty_missing_selection
        else _OPERATIONS
        if case in {"all_operations", "reordered_receipts"}
        else (case,)
        if case in _OPERATIONS
        else ("issue_snapshot",)
    )

    def raw_source(raw: bytes) -> BlobRef:
        """Keep an actual deliberate whole-source fault under its correct raw identity."""
        digest = hashlib.sha256(raw).hexdigest()
        path = tmp_path / digest
        path.write_bytes(raw)
        result = BlobRef("sha256:" + digest, str(len(raw)), "application/json", "raw_bytes")
        population[result.digest + "|raw_bytes"] = path
        return result

    rule_base = base_ref
    if case == "base_fixture":
        rule_base = original_ref
    if case in {"base_missing", "base_json", "base_object"}:
        rule_base = raw_source(
            b"{"
            if case == "base_json"
            else b"[]"
            if case == "base_object"
            else b"\n" + (tmp_path / base_ref.digest[7:]).read_bytes()
        )
    if case in {"base_no_clock", "base_has_clock"}:
        changed_base = dict(base)
        if case == "base_no_clock":
            del changed_base["required_evaluation_time_qualification"]
        else:
            changed_base["required_evaluation_time_qualification"] = {
                **_object(base["required_evaluation_time_qualification"]),
                "clock_qualification_ref": dict(base_ref.to_mapping()),
            }
        rule_base = _stored_source(changed_base, tmp_path)
        population[rule_base.digest + "|raw_bytes"] = tmp_path / rule_base.digest[7:]
    rule, selection, envelopes, objects = protected_control_inputs(
        rule_base, tmp_path, root=base_ref, conditions=base_ref, operations=operations
    )
    population.update(objects)
    rule_body = _object(json.loads((tmp_path / rule.digest[7:]).read_bytes()))
    selected = _object(json.loads((tmp_path / selection.digest[7:]).read_bytes()))
    entries = [_object(x) for x in _array(selected["entries"])]
    pointer = "/required_evaluation_time_qualification/clock_qualification_ref"
    error_subject = None
    error_code = "policy_unavailable"
    detail = "The required evaluation-time qualification is unavailable."
    unavailable: BlobRef | None = None
    if case in {"raw_whitespace", "canonical_digest"}:
        raw = json.dumps(json.loads(envelopes[0]), indent=2).encode("utf-8")
        envelopes = (raw,)
        if case == "raw_whitespace":
            entries[0]["envelope_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    if case == "missing_receipt":
        envelopes = ()
    if case == "oversized_receipt":
        envelopes = (b" " * (limits.max_json_bytes + 1),)
    if case == "extra_receipt":
        envelopes += envelopes
    if case == "reordered_receipts":
        envelopes = tuple(reversed(envelopes))
    if case == "duplicate_receipt":
        duplicate = dict(entries[0])
        raw = json.dumps(json.loads(envelopes[0]), indent=2).encode("utf-8")
        duplicate["envelope_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        entries.append(duplicate)
        envelopes += (raw,)
    if case in {
        "statement_ref",
        "target_ref",
        "authorizing_state_ref",
        "authorization_ref",
        "scope_ref",
    }:
        metadata = _object(entries[0][case])
        entries[0][case] = (
            {**metadata, "byte_length": str(int(_text(metadata["byte_length"])) + 1)}
            if case == "target_ref"
            else {**metadata, "media_type": "application/octet-stream"}
        )
    if case == "signer_key_id":
        entries[0][case] = "ed25519:" + "1" * 64
    if case == "operation":
        entries[0][case] = "revoke_descendants"
    if case in {"root_join", "conditions_join"}:
        rule_body[
            "independent_root_selection_ref"
            if case == "root_join"
            else "whole_conditions_and_limitations_ref"
        ] = dict(caller.root_grant_ref.to_mapping())
    if case == "rule_format":
        rule_body["format_version"] = "emt-protected-control-rule-source-r5"
    descendant = None
    if case in {"descendant_missing", "descendant_bytes"}:
        descendant = raw_source(b'{"qualification":"unavailable"}')
        rule_body["bootstrap_rule_ref"] = dict(descendant.to_mapping())
    rule = _stored_source(rule_body, tmp_path)
    population[rule.digest + "|raw_bytes"] = tmp_path / rule.digest[7:]
    selected["control_rule_ref"] = (
        dict(base_ref.to_mapping()) if case == "rule_join" else dict(rule.to_mapping())
    )
    selected["entries"] = entries
    if case == "selection_format":
        selected["format_version"] = "emt-protected-control-selection-source-r5"
    selection = _stored_source(selected, tmp_path)
    population[selection.digest + "|raw_bytes"] = tmp_path / selection.digest[7:]
    grant, snapshot, state_objects = protected_state_inputs(
        rule_base, rule, base_ref, tmp_path, sequence=caller.accepted_authority_sequence_floor
    )
    population.update(state_objects)
    policy_value["root_grant_ref"] = dict(grant.to_mapping())
    caller = replace(
        caller,
        root_grant_ref=grant,
        current_authority_snapshot_ref=snapshot,
        independent_root_selection_ref=base_ref,
        authority_control_selection_ref=selection,
        control_envelopes=envelopes,
    )
    policy_value["authority_rule_ref"] = dict(rule.to_mapping())
    if case in {"missing_rule", "missing_selection", "missing_statement", "missing_target"}:
        unavailable = (
            rule
            if case == "missing_rule"
            else selection
            if case == "missing_selection"
            else BlobRef.from_mapping(
                _object(
                    entries[0]["statement_ref" if case == "missing_statement" else "target_ref"]
                )
            )
        )
        (tmp_path / unavailable.digest[7:]).unlink()
    if case in {"statement_bytes", "target_bytes"}:
        reference = BlobRef.from_mapping(
            _object(entries[0]["statement_ref" if case == "statement_bytes" else "target_ref"])
        )
        (tmp_path / reference.digest[7:]).write_bytes(b"{}")
    if case in {"base_missing", "descendant_missing"}:
        unavailable = rule_base if case == "base_missing" else descendant
        assert unavailable is not None
        (tmp_path / unavailable.digest[7:]).unlink()
    if case == "descendant_bytes":
        assert descendant is not None
        (tmp_path / descendant.digest[7:]).write_bytes(b"{}")
    policy_ref = _stored_source(
        policy_value, tmp_path, schema_id="evidence_manifest_toolkit.authority_policy.v2"
    )
    population[policy_ref.digest + "|raw_bytes"] = tmp_path / policy_ref.digest[7:]
    resolver = _FileResolver(population)
    if cli:
        trust = _object(_mapping(caller))
        del trust["archived_authority_snapshot_ref"]
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
            trust=trust,
        )
        captured = capfd.readouterr()
        error = _object(json.loads(captured.out))
        actual_reason = _object(_array(error["reasons"])[0])
        assert captured.out.encode() == _transport(
            {"operation": "verify", "reasons": [actual_reason]}
        )
        assert not captured.err and not report.exists()
        assert status == (3 if unavailable is not None else 2)
    else:
        failure_type = (
            ReferenceUnavailable
            if unavailable is not None
            else ConfigurationError
            if case == "base_no_clock"
            else InputRefused
        )
        with pytest.raises(failure_type) as caught:
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
    if unavailable is not None:
        if not cli:
            assert (
                isinstance(caught.value, ReferenceUnavailable)
                and caught.value.reference == unavailable
            )
        assert actual_reason == {
            "code": "reference_unavailable",
            "subject_digest": None,
            "claim_id": None,
            "pointer": None,
            "detail": "Required reference unavailable.",
        }
    else:
        if case in {
            "canonical_digest",
            "missing_receipt",
            "extra_receipt",
            "reordered_receipts",
            "duplicate_receipt",
            "statement_ref",
            "target_ref",
            "signer_key_id",
            "authorizing_state_ref",
            "authorization_ref",
            "scope_ref",
            "operation",
        }:
            error_code, error_subject, detail = (
                "scope_missing",
                selection.digest,
                "Protected control selection conflicts.",
            )
            pointer = (
                "/entries"
                if case in {"missing_receipt", "extra_receipt"}
                else "/entries/1/envelope_digest"
                if case == "duplicate_receipt"
                else "/entries/0/"
                + (
                    "envelope_digest"
                    if case in {"canonical_digest", "reordered_receipts"}
                    else case
                )
            )
        if case in {"rule_join", "root_join", "conditions_join"}:
            error_subject, detail = policy_ref.digest, "Protected control rule sources conflict."
            pointer = (
                "/trust/authority_control_selection_ref"
                if case == "rule_join"
                else "/trust/independent_root_selection_ref"
                if case == "root_join"
                else "/whole_conditions_and_limitations_ref"
            )
        if case in {"rule_format", "selection_format"}:
            error_code, error_subject, pointer, detail = (
                "invalid_schema",
                rule.digest if case == "rule_format" else selection.digest,
                "/format_version",
                "Input violates its selected schema.",
            )
        if case in {"statement_bytes", "target_bytes"}:
            error_code, error_subject, pointer, detail = (
                "reference_mismatch",
                selection.digest,
                "/entries/0/" + ("statement_ref" if case == "statement_bytes" else "target_ref"),
                "Reference byte identity does not match.",
            )
        expected = {
            "code": error_code,
            "subject_digest": error_subject or policy_ref.digest,
            "claim_id": None,
            "pointer": pointer,
            "detail": detail,
        }
        if case in {"base_fixture", "base_has_clock"}:
            expected.update(
                pointer="/authority_rule_ref", detail="Protected control rule sources conflict."
            )
        if case == "base_no_clock":
            expected.update(
                code="configuration_error",
                subject_digest=rule_base.digest,
                pointer="/required_evaluation_time_qualification",
                detail="Invalid local trust or policy configuration.",
            )
        if case in {"base_json", "base_object"}:
            expected.update(
                code="invalid_json" if case == "base_json" else "invalid_schema",
                subject_digest=rule_base.digest,
                pointer="",
                detail="Input is not valid strict JSON."
                if case == "base_json"
                else "Complete context object is required.",
            )
        if case == "descendant_bytes":
            expected.update(
                code="reference_mismatch",
                subject_digest=rule.digest,
                pointer="/bootstrap_rule_ref",
                detail="Reference byte identity does not match.",
            )
        if case == "oversized_receipt":
            expected.update(
                code="limit_exceeded",
                subject_digest=None,
                pointer=None,
                detail="JSON input refused.",
            )
        if case in {"revoke_descendants", "rotate_authority"}:
            control_target = next(
                entry
                for entry in entries
                if entry["operation"]
                == ("revoke_descendants" if case == "revoke_descendants" else "rotate_authority")
            )
            expected.update(
                subject_digest=_text(_object(control_target["target_ref"])["digest"]),
                pointer="/root_grant_ref",
                detail="Protected state sources conflict.",
            )
        if case in {"issue_certificate", "all_operations"}:
            expected.update(
                code="invalid_schema",
                subject_digest=rule_base.digest,
                pointer="",
                detail="Input violates its selected schema.",
            )
        assert actual_reason == expected
        if not cli and case in {"empty", *_OPERATIONS, "all_operations", "raw_whitespace"}:
            requested = {reference for reference, _ in resolver.calls}
            assert {rule, selection} <= requested
            for entry in entries:
                assert {
                    BlobRef.from_mapping(_object(entry[name]))
                    for name in ("statement_ref", "target_ref")
                } <= requested
    assert all(path.read_bytes() == raw for path, raw in originals.items())
