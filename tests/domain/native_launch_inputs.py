# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole native launch source input and independent fault oracles

"""Materialise complete real raw-source faults for the original public verification workflow."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from tests.domain.test_native_entry_sources import _native_source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, reference_bytes

if TYPE_CHECKING:
    from tests.domain.reproduction_record_inputs import ReproductionOutcome

NATIVE_LAUNCH_CASES = tuple(
    "reproduction_native_launch_" + case
    for case in (
        "publisher_matching",
        "producer_extra",
        "runner_extra",
        "producer_seat",
        "runner_seat",
        "producer_vendor",
        "runner_vendor",
        "vendor_matching",
        "vendor_whitespace",
        "opaque_key",
        "file_unavailable",
        "process_image_null",
        "historical_paths",
        "command_exp",
        "launcher_pid_fraction",
        "process_pid_exp",
        "file_size_negative_zero",
        "image_size_fraction",
        "large_integer",
        "numeric_string",
        "boolean_pid",
        "fractional_pid",
        "invalid_date",
        "year_zero",
        "year_one_short",
        "invalid_json",
        "duplicate_name",
        "invalid_utf8",
        "primitive",
        "source_missing",
        "basis_jcs",
        "wrong_launcher",
        "unknown_contract",
        "observer_contract",
        "unsupported_identity",
    )
) + tuple(
    "cli_reproduction_native_launch_" + case
    for case in ("runner_seat", "command_exp", "publisher_matching", "source_missing")
)


@dataclass(frozen=True, slots=True)
class NativeLaunchFault:
    """Keep an independent expected native source outcome, never an admitted product value.

    Attributes
    ----------
    kind : str
        Original configuration/refused/unavailable public exception class.
    reason : dict
        Entire independently authored fixed diagnostic, with subject filled from whole sources.
    subject : str
        Exact producer/runner binding, raw source or absent diagnostic subject.
    source : BlobRef or None
        Whole original raw source for its own identity or unavailable-ref assertion.
    """

    kind: Literal["configuration", "refused", "unavailable"]
    reason: dict[str, object]
    subject: Literal["producer", "runner", "raw", "none"]
    source: BlobRef | None = None


def native_launch_input(
    condition: str,
    producer: dict[str, object],
    runner: dict[str, object],
    *,
    rules: dict[str, object],
    base: BlobRef,
    directory: Path,
    limits: Limits,
) -> NativeLaunchFault | None:
    """Change one entire input under the real independent rule and original raw source graph.

    Parameters
    ----------
    condition : str
        Full named source/lexeme/join condition or unmodified actual publisher control.
    producer, runner : dict
        Complete original identity declarations before their whole references are fixed.
    rules : dict
        Entire independent identity/validation selections; changes propagate through every join.
    base : BlobRef
        Existing complete unqualified source for explicit unavailable method/context controls.
    directory : Path
        Owned real input files; no resolver, publisher, clock or native state is mocked.
    limits : Limits
        Complete original public-operation bounds for a genuine JCS-reference control.

    Returns
    -------
    NativeLaunchFault or None
        Entire independent expected diagnostic and original missing source, or None outside
        this surface. No qualification, key possession or successful V2 result is asserted.
    """
    original = condition.removeprefix("cli_")
    if original not in NATIVE_LAUNCH_CASES:
        return None
    case = original.removeprefix("reproduction_native_launch_")
    reason: dict[str, object] = {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": "/trust",
        "detail": "Invalid local configuration.",
    }
    if case == "publisher_matching":
        return NativeLaunchFault("configuration", reason, "none")
    role: Literal["producer", "runner"] = "runner" if case.startswith("runner_") else "producer"
    identity = producer if role == "producer" else runner
    reference = BlobRef.from_mapping(_object(identity["actual_launch_or_declared_source_ref"]))
    value = _object(json.loads((directory / reference.digest[7:]).read_bytes()))
    mode: Literal["producer", "runner", "raw", "none"] = "raw"
    kind: Literal["configuration", "refused", "unavailable"] = "refused"
    pointer: str | None = ""
    detail = "Input violates its selected schema."
    code = "invalid_schema"
    positive = case in {
        "vendor_matching",
        "opaque_key",
        "file_unavailable",
        "process_image_null",
        "historical_paths",
        "large_integer",
        "year_zero",
    }
    if case.endswith("_extra"):
        value["unexpected"] = True
    elif case.endswith("_seat"):
        value["seat"] = "different-declared-seat"
        mode, pointer, detail, code = (
            role,
            "/principal_id",
            "Native launch source conflicts with its declared identity.",
            "invalid_claim",
        )
    elif case.endswith("_vendor") or case == "vendor_whitespace":
        value["declared_vendor"] = (
            "different-declared-vendor"
            if case != "vendor_whitespace"
            else " " + _text(identity["vendor_id"])
        )
        mode, pointer, detail, code = (
            role,
            "/vendor_id",
            "Native launch source conflicts with its declared identity.",
            "invalid_claim",
        )
    elif case == "vendor_matching":
        value["declared_vendor"] = identity["vendor_id"]
    elif case == "opaque_key":
        value["seat_public_key"] = "opaque-declaration-without-a-key-reference-or-proof"
    elif case == "file_unavailable":
        value["executable"] = {"path": "", "size": -1, "sha256": "", "unavailable": "not captured"}
    elif case == "process_image_null":
        value["process"] = {
            **_object(value["process"]),
            "image": None,
            "boot": "",
            "started": "",
            "unavailable": "not captured",
        }
    elif case == "historical_paths":
        value["executable"] = {
            **_object(value["executable"]),
            "path": "/nonexistent/historical-native-launch-source",
        }
        value["process"] = {**_object(value["process"]), "pid": 2147483647}
    elif case == "numeric_string":
        value["command_words"] = "1"
        pointer = "/command_words"
    elif case in {"boolean_pid", "fractional_pid"}:
        value["process"] = {
            **_object(value["process"]),
            "pid": True if case == "boolean_pid" else 1.5,
        }
        pointer = "/process/pid"
    elif case in {"invalid_date", "year_zero", "year_one_short"}:
        value["recorded_at"] = {
            "invalid_date": "2026-02-30T12:00:00.000000Z",
            "year_zero": "0000-02-29T12:00:00.123456Z",
            "year_one_short": "1-01-01T12:00:00.000000Z",
        }[case]
        pointer = "/recorded_at"
        if case == "invalid_date":
            detail = "Invalid UTC calendar fields."
    elif case == "wrong_launcher":
        identity["observer_or_launcher_ref"] = dict(base.to_mapping())
        reason.update(
            code="invalid_claim",
            pointer="/observer_or_launcher_ref",
            detail="Native launch source conflicts with its declared identity.",
        )
        return NativeLaunchFault("refused", reason, role)
    elif case in {"unknown_contract", "observer_contract", "unsupported_identity"}:
        identity_reference = BlobRef.from_mapping(_object(rules["identity_rule_ref"]))
        independent = _object(json.loads((directory / identity_reference.digest[7:]).read_bytes()))
        launcher_reference = BlobRef.from_mapping(
            _object(independent["launcher_or_observer_procedure_ref"])
        )
        launcher = _object(json.loads((directory / launcher_reference.digest[7:]).read_bytes()))
        if case == "unsupported_identity":
            independent["permitted_identity_classes"] = [
                "declared_by_launcher_under_the_seat_account",
                "vendor_by_client_program_only",
            ]
            producer.update(
                identity_class="vendor_by_client_program_only",
                process_identity_ref=dict(base.to_mapping()),
                key_possession_ref=dict(base.to_mapping()),
            )
        else:
            if case == "unknown_contract":
                launcher["record_contract_ref"] = dict(base.to_mapping())
            else:
                launcher = {
                    key: item
                    for key, item in launcher.items()
                    if key not in {"record_contract_ref", "vendor_source", "key_source"}
                }
                launcher.update(
                    capture_contract_ref=dict(base.to_mapping()),
                    observer_authority_policy_ref=dict(base.to_mapping()),
                    endpoint_rule_ref=dict(base.to_mapping()),
                )
            launcher_reference = _stored(launcher, directory)
            independent["launcher_or_observer_procedure_ref"] = dict(
                launcher_reference.to_mapping()
            )
        updated = _stored(independent, directory)
        validation_reference = BlobRef.from_mapping(_object(rules["validation_rule_ref"]))
        validation = _object(json.loads((directory / validation_reference.digest[7:]).read_bytes()))
        validation["independent_identity_policy_ref"] = dict(updated.to_mapping())
        rules.update(
            identity_rule_ref=dict(updated.to_mapping()),
            validation_rule_ref=dict(_stored(validation, directory).to_mapping()),
        )
        for whole_identity in (producer, runner):
            whole_identity.update(
                whole_policy_ref=dict(updated.to_mapping()),
                observer_or_launcher_ref=dict(launcher_reference.to_mapping()),
            )
        reason["pointer"] = {
            "unknown_contract": "/record_contract_ref",
            "observer_contract": "/launcher_or_observer_procedure_ref",
            "unsupported_identity": "/identity_class",
        }[case]
        return NativeLaunchFault("configuration", reason, "none")
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    lexical = {
        "command_exp": ("command_words", "1e0", "/command_words"),
        "launcher_pid_fraction": ("launcher_pid", "1.0", "/launcher_pid"),
        "process_pid_exp": ("pid", "1e1", "/process/pid"),
        "file_size_negative_zero": ("size", "-0", "/executable/size"),
        "image_size_fraction": ("size", "1.0", "/process/image/size"),
        "large_integer": ("size", "9007199254740993", "/executable/size"),
    }
    if case in lexical:
        field, token, pointer = lexical[case]
        current = (
            _object(value["executable"])["size"]
            if field == "size"
            else _object(value["process"])["pid"]
            if field == "pid"
            else value[field]
        )
        needle = json.dumps(field).encode() + b":" + str(current).encode()
        offset = raw.rfind(needle) if case == "image_size_fraction" else raw.find(needle)
        assert offset >= 0
        raw = (
            raw[:offset]
            + json.dumps(field).encode()
            + b":"
            + token.encode()
            + raw[offset + len(needle) :]
        )
        detail = "Native launch integer token is invalid."
    if case in {"invalid_json", "duplicate_name", "invalid_utf8"}:
        raw = (
            b"{"
            if case == "invalid_json"
            else raw[:-1] + b',"seat":"duplicate"}'
            if case == "duplicate_name"
            else b"\xff"
        )
        code, detail = "invalid_json", "Input is not valid strict JSON."
    if case == "primitive":
        raw = b"[]"
    if case == "source_missing":
        raw = b'{"genuinely_absent_original_native_source":true}'
    reference = _native_source(raw, directory, "application/json")
    if case == "basis_jcs":
        reference = reference_bytes(
            raw,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id=None,
            limits=limits,
        )
        (directory / reference.digest[7:]).write_bytes(raw)
        mode, pointer, detail = (
            role,
            "/actual_launch_or_declared_source_ref",
            "Native launch source requires original raw bytes.",
        )
    identity["actual_launch_or_declared_source_ref"] = dict(reference.to_mapping())
    if case == "source_missing":
        (directory / reference.digest[7:]).unlink()
        reason.update(
            code="reference_unavailable", pointer=None, detail="Required reference unavailable."
        )
        return NativeLaunchFault("unavailable", reason, "none", reference)
    if positive:
        return NativeLaunchFault("configuration", reason, "none", reference)
    reason.update(code=code, pointer=pointer, detail=detail)
    return NativeLaunchFault(kind, reason, mode, reference)


def native_launch_expected(
    fault: NativeLaunchFault, *, producer: BlobRef, runner: BlobRef
) -> "ReproductionOutcome":
    """Bind the complete independent diagnostic to its original whole source identity.

    Parameters
    ----------
    fault : NativeLaunchFault
        Independently authored source/join/schema/lexeme outcome, never a product result.
    producer, runner : BlobRef
        Actual complete final binding references after all named input mutations.

    Returns
    -------
    tuple
        Original public exception class, entire five-field reason and missing full Ref.
    """
    reason = dict(fault.reason)
    reason["subject_digest"] = (
        producer.digest
        if fault.subject == "producer"
        else runner.digest
        if fault.subject == "runner"
        else fault.source.digest
        if fault.subject == "raw" and fault.source is not None
        else None
    )
    return fault.kind, reason, fault.source if fault.kind == "unavailable" else None
