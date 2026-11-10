# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete successor caller value boundaries

"""Exercise public immutable carrier construction using complete original source references."""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, asdict, fields, is_dataclass, replace
from pathlib import Path
from typing import Literal

import pytest
from tests.domain.test_verification_report_sources import _array, _mapping, _object, _text

from evidence_manifest_toolkit import (
    BlobRef,
    ConfigurationError,
    DelegatedTrustContextV2,
    SoftwareTrustContextV2,
    UnsignedTrustContextV2,
    Utc,
)
from evidence_manifest_toolkit._immutable import FrozenJson

_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_BINDING_FIELDS = (
    "first_sample_source_ref",
    "source_profile_ref",
    "boot_domain_ref",
    "verification_controller_identity_ref",
    "process_start_identity_ref",
    "entry_observation_method_ref",
    "implementation_environment_ref",
)
type _Caller = UnsignedTrustContextV2 | SoftwareTrustContextV2 | DelegatedTrustContextV2


def _sources() -> tuple[dict[str, FrozenJson], tuple[BlobRef, ...], dict[Path, bytes]]:
    """Retain real original objects for carrier-only declarations, never qualified Clock facts.

    Returns
    -------
    tuple
        Complete binding, actual raw references and every unchanged original source byte.
        The referenced fixture objects are deliberately not asserted to be native Clock sources.
    """
    case = _FIXTURES / "verify-current-whole-fixture.json"
    raw = case.read_bytes()
    pins = _FIXTURES / "source-pins.json"
    pinned = next(
        _object(row)
        for row in _array(_object(json.loads(pins.read_bytes()))["original_cases"])
        if _object(row)["case_id"] == "verify-current-whole-fixture"
    )
    assert hashlib.sha256(raw).hexdigest() == pinned["source_sha256"]
    source = _object(json.loads(raw))
    records = _object(_object(source["complete_library_inputs"])["resolver_input_population"])
    originals = {case: raw, pins: pins.read_bytes()}
    references: list[BlobRef] = []
    for key in sorted(records)[:7]:
        record = _object(records[key])
        path = _FIXTURES / "objects" / _text(record["sha256"])
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        assert len(data) == record["byte_length"]
        originals[path] = data
        references.append(
            BlobRef(
                "sha256:" + hashlib.sha256(data).hexdigest(),
                str(len(data)),
                "application/octet-stream",
                "raw_bytes",
            )
        )
    assert len(references) == len(_BINDING_FIELDS) == 7
    binding: dict[str, FrozenJson] = {
        "format_version": "emt-clock-entry-binding-source-r4",
        "request_id": "unqualified-original-source-carrier:" + hashlib.sha256(raw).hexdigest(),
    }
    for name, reference in zip(_BINDING_FIELDS, references, strict=True):
        binding[name] = dict(reference.to_mapping())
    return binding, tuple(references), originals


def _callers(
    binding: Mapping[str, FrozenJson],
    references: tuple[BlobRef, ...],
    mode: Literal["current", "historical"],
) -> tuple[UnsignedTrustContextV2, SoftwareTrustContextV2, DelegatedTrustContextV2]:
    """Construct all complete public carriers without acquiring or accepting source authority.

    Parameters
    ----------
    binding : Mapping
        All nine independently declared binding fields.
    references : tuple of BlobRef
        Actual whole fixture source references, unqualified for native Clock or authority use.
    mode : {"current", "historical"}
        Exact original requested scope and its corresponding archive-field requirement.

    Returns
    -------
    tuple
        All three complete public values with original reference bytes and exact decimal floors.
    """
    archive = references[4] if mode == "historical" else None
    return (
        UnsignedTrustContextV2(
            "EMT_CALLER_TRUST_UNSIGNED_V2",
            "unsigned_declared",
            mode,
            Utc("2026-10-03T12:00:00Z"),
            binding,
        ),
        SoftwareTrustContextV2(
            "EMT_CALLER_TRUST_SOFTWARE_V2",
            "software_local_unprotected",
            mode,
            Utc("2026-10-03T12:00:00Z"),
            binding,
            references[0],
            "9007199254740993",
            archived_software_authorization_ref=archive,
        ),
        DelegatedTrustContextV2(
            "EMT_CALLER_TRUST_DELEGATED_V2",
            "protected_delegated",
            mode,
            Utc("2026-10-03T12:00:00Z"),
            binding,
            references[0],
            references[1],
            references[2],
            "9" * 256,
            (),
            references[3],
            archived_authority_snapshot_ref=archive,
        ),
    )


def test_complete_current_and_historical_carriers_detach_all_original_binding_values() -> None:
    """Preserve every field and nested reference after actual caller mutations and replacements."""
    binding, references, originals = _sources()
    expected = _mapping(binding)
    modes: tuple[Literal["current", "historical"], ...] = ("current", "historical")
    callers: list[_Caller] = []
    for mode in modes:
        unsigned, software, delegated = _callers(binding, references, mode)
        callers.extend((unsigned, software, delegated))
        assert [field.name for field in fields(unsigned)] == [
            "namespace",
            "profile_class",
            "evaluation_mode",
            "evaluation_time",
            "clock_entry_binding",
        ]
        assert [field.name for field in fields(software)] == [
            "namespace",
            "profile_class",
            "evaluation_mode",
            "evaluation_time",
            "clock_entry_binding",
            "software_authorization_ref",
            "accepted_authorization_sequence_floor",
            "archived_software_authorization_ref",
        ]
        assert [field.name for field in fields(delegated)] == [
            "namespace",
            "profile_class",
            "evaluation_mode",
            "evaluation_time",
            "clock_entry_binding",
            "independent_root_selection_ref",
            "root_grant_ref",
            "current_authority_snapshot_ref",
            "accepted_authority_sequence_floor",
            "control_envelopes",
            "archived_authority_snapshot_ref",
            "authority_control_selection_ref",
        ]
        assert software.accepted_authorization_sequence_floor == "9007199254740993"
        assert delegated.accepted_authority_sequence_floor == "9" * 256
        assert software.software_authorization_ref == references[0]
        assert delegated.authority_control_selection_ref == references[3]
        assert (software.archived_software_authorization_ref is None) == (mode == "current")
        assert (delegated.archived_authority_snapshot_ref is None) == (mode == "current")
        assert replace(unsigned).clock_entry_binding is not unsigned.clock_entry_binding
        assert replace(software).clock_entry_binding is not software.clock_entry_binding
        assert replace(delegated).clock_entry_binding is not delegated.clock_entry_binding
    profile = binding["source_profile_ref"]
    assert isinstance(profile, dict)
    profile["digest"] = "changed-after-construction"
    binding["request_id"] = "changed-after-construction"
    for caller in callers:
        assert _mapping(caller.clock_entry_binding) == expected
        assert caller.clock_entry_binding is not binding
        for member in fields(caller):
            with pytest.raises(FrozenInstanceError):
                setattr(caller, member.name, getattr(caller, member.name))
    assert all(path.read_bytes() == raw for path, raw in originals.items())


def _configuration_update(value: object, changes: dict[str, object]) -> object:
    """Apply an untyped application's complete field changes through the public dataclass API.

    Parameters
    ----------
    value : object
        Actual public carrier instance selected by the application.
    changes : dict
        Original external field population, including deliberately malformed caller values.

    Returns
    -------
    object
        Newly validated public carrier; malformed values must fail during construction.
    """
    assert is_dataclass(value) and not isinstance(value, type)
    return replace(value, **changes)


def test_complete_carrier_constraints_refuse_conflicts_and_restore_original_values() -> None:
    """Refuse whole carrier contradictions through public constructors and recover original values."""
    binding, references, originals = _sources()
    unsigned, software, delegated = _callers(binding, references, "current")
    failures: list[tuple[_Caller, dict[str, object], str]] = [
        (unsigned, {"namespace": "EMT_CALLER_TRUST_SOFTWARE_V2"}, "/trust/namespace"),
        (unsigned, {"profile_class": "protected_delegated"}, "/trust/profile_class"),
        (unsigned, {"evaluation_mode": "unsupported"}, "/trust/evaluation_mode"),
        (unsigned, {"evaluation_time": "2026-02-30T12:00:00Z"}, "/trust/evaluation_time"),
        (
            software,
            {"accepted_authorization_sequence_floor": "00"},
            "/trust/accepted_authorization_sequence_floor",
        ),
        (software, {"software_authorization_ref": None}, "/trust/software_authorization_ref"),
        (software, {"archived_software_authorization_ref": references[1]}, "/trust"),
        (software, {"evaluation_mode": "historical"}, "/trust"),
        (
            delegated,
            {"accepted_authority_sequence_floor": "9" * 257},
            "/trust/accepted_authority_sequence_floor",
        ),
        (delegated, {"archived_authority_snapshot_ref": references[1]}, "/trust"),
        (delegated, {"evaluation_mode": "historical"}, "/trust"),
        (delegated, {"control_envelopes": []}, "/trust/control_envelopes"),
        (delegated, {"control_envelopes": ("not-bytes",)}, "/trust/control_envelopes"),
        (delegated, {"control_envelopes": (b"",)}, "/trust/control_envelopes/0"),
    ]
    for member, changes, pointer in failures:
        with pytest.raises(ConfigurationError) as caught:
            _configuration_update(member, changes)
        assert asdict(caught.value.reason) == {
            "code": "configuration_error",
            "subject_digest": None,
            "claim_id": None,
            "pointer": pointer,
            "detail": "Invalid local configuration.",
        }
    for field in _BINDING_FIELDS:
        changed = dict(binding)
        changed[field] = {**dict(references[0].to_mapping()), "digest": "invalid"}
        with pytest.raises(ConfigurationError) as caught:
            replace(unsigned, clock_entry_binding=changed)
        assert caught.value.reason.pointer == "/trust/clock_entry_binding/" + field + "/digest"
    cyclic: dict[str, FrozenJson] = dict(binding)
    cyclic["cycle"] = cyclic
    with pytest.raises(ConfigurationError) as caught:
        replace(unsigned, clock_entry_binding=cyclic)
    assert caught.value.reason.pointer == "/trust/clock_entry_binding"
    case = json.loads((_FIXTURES / "verify-current-whole-fixture.json").read_bytes())
    token = case["complete_library_inputs"]["trust"]["control_envelopes"][0]
    actual_envelope = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    declared = replace(delegated, control_envelopes=(actual_envelope,))
    assert declared.control_envelopes == (actual_envelope,)
    assert _mapping(declared.clock_entry_binding) == _mapping(binding)
    for caller in _callers(binding, references, "current"):
        assert _mapping(caller.clock_entry_binding) == _mapping(binding)
    assert all(path.read_bytes() == raw for path, raw in originals.items())


def test_public_constructor_refuses_missing_or_changed_whole_packaged_resource(
    tmp_path: Path,
) -> None:
    """Exercise real detached-package resource faults without modifying canonical source files.

    Parameters
    ----------
    tmp_path : Path
        Owned complete package copies, native child entry scripts and coverage data.
    """
    binding, _, originals = _sources()
    package = _ROOT / "src/evidence_manifest_toolkit"
    original_schema = (package / "_schemas/successor_caller_trust.json").read_bytes()
    script = tmp_path / "construct_carrier.py"
    script.write_text(
        "\n".join(Path(__file__).read_text().splitlines()[:7]) + "\n\nimport json,sys\n"
        "from collections.abc import Mapping\n"
        "from dataclasses import asdict,fields\n"
        "from pathlib import Path\n"
        "import evidence_manifest_toolkit as e\n"
        "assert Path(e.__file__).resolve().is_relative_to(Path(sys.argv[2]).resolve())\n"
        "def plain(value: object) -> object:\n"
        "    if isinstance(value,Mapping):\n"
        "        return {k:plain(v) for k,v in value.items()}\n"
        "    if isinstance(value,tuple):\n"
        "        return [plain(v) for v in value]\n"
        "    return value\n"
        "try:\n"
        "    value=e.UnsignedTrustContextV2('EMT_CALLER_TRUST_UNSIGNED_V2',"
        "'unsigned_declared','current',e.Utc('2026-10-03T12:00:00Z'),json.loads(sys.argv[1]))\n"
        "except e.ConfigurationError as error:\n"
        "    print(json.dumps(asdict(error.reason)))\n"
        "    raise SystemExit(4) from None\n"
        "print(json.dumps({f.name:plain(getattr(value,f.name)) for f in fields(value)}))\n"
    )
    expected = {
        "namespace": "EMT_CALLER_TRUST_UNSIGNED_V2",
        "profile_class": "unsigned_declared",
        "evaluation_mode": "current",
        "evaluation_time": "2026-10-03T12:00:00Z",
        "clock_entry_binding": _mapping(binding),
    }
    for state in ("complete", "missing", "changed"):
        parent = tmp_path / ("successor-package-" + state)
        clone = parent / "evidence_manifest_toolkit"
        shutil.copytree(
            package,
            clone,
            ignore=shutil.ignore_patterns(
                "__pycache__", *(["successor_caller_trust.json"] if state == "missing" else [])
            ),
        )
        selected = clone / "_schemas/successor_caller_trust.json"
        if state == "changed":
            selected.write_bytes(original_schema + b"\n")
        for path in package.glob("*.py"):
            assert (
                hashlib.sha256((clone / path.name).read_bytes()).digest()
                == hashlib.sha256(path.read_bytes()).digest()
            )
        environment = {
            **os.environ,
            "PYTHONPATH": str(parent),
            "PYTHONDONTWRITEBYTECODE": "1",
            "COVERAGE_FILE": os.environ.get("COVERAGE_FILE", str(tmp_path / "carrier.coverage")),
        }
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "coverage",
                "run",
                "--branch",
                "--parallel-mode",
                "--rcfile",
                str(_ROOT / "pyproject.toml"),
                "--source=evidence_manifest_toolkit._successor_trust,evidence_manifest_toolkit._successor_formats",
                str(script),
                json.dumps(_mapping(binding)),
                str(parent),
            ],
            cwd=parent,
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert result.stderr == b""
        if state == "complete":
            assert result.returncode == 0 and json.loads(result.stdout) == expected
        else:
            assert result.returncode == 4
            assert json.loads(result.stdout) == {
                "code": "configuration_error",
                "subject_digest": None,
                "claim_id": None,
                "pointer": "/trust",
                "detail": "Invalid local configuration.",
            }
    assert (package / "_schemas/successor_caller_trust.json").read_bytes() == original_schema
    assert all(path.read_bytes() == raw for path, raw in originals.items())


def test_complete_carriers_reject_noncanonical_reference_and_floor_lexemes() -> None:
    """Refuse terminal newlines admitted by shape regexes and preserve complete recovery values."""
    binding, references, originals = _sources()
    unsigned, software, delegated = _callers(binding, references, "current")
    before = [_mapping(value) for value in (unsigned, software, delegated)]
    bad_binding = dict(binding)
    first = dict(references[0].to_mapping())
    first["digest"] += "\n"
    bad_binding["first_sample_source_ref"] = first
    bad_request = dict(binding)
    bad_request["request_id"] = "\ud800"
    cases: tuple[tuple[object, dict[str, object], str], ...] = (
        (unsigned, {"clock_entry_binding": bad_request}, "/trust/clock_entry_binding/request_id"),
        (
            unsigned,
            {"clock_entry_binding": bad_binding},
            "/trust/clock_entry_binding/first_sample_source_ref",
        ),
        (
            software,
            {
                "software_authorization_ref": replace(
                    references[0], digest=references[0].digest + "\n"
                )
            },
            "/trust/software_authorization_ref",
        ),
        (
            delegated,
            {
                "root_grant_ref": replace(
                    references[1], byte_length=references[1].byte_length + "\n"
                )
            },
            "/trust/root_grant_ref",
        ),
        (
            software,
            {"accepted_authorization_sequence_floor": "1\n"},
            "/trust/accepted_authorization_sequence_floor",
        ),
        (
            delegated,
            {"accepted_authority_sequence_floor": "1\n"},
            "/trust/accepted_authority_sequence_floor",
        ),
    )
    for value, changes, pointer in cases:
        with pytest.raises(ConfigurationError) as caught:
            _configuration_update(value, changes)
        assert asdict(caught.value.reason) == {
            "code": "configuration_error",
            "subject_digest": None,
            "claim_id": None,
            "pointer": pointer,
            "detail": "Invalid local configuration.",
        }
    recovered = _callers(binding, references, "current")
    assert [_mapping(value) for value in recovered] == before
    assert all(path.read_bytes() == raw for path, raw in originals.items())
