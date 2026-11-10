# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original canonical and raw byte identity sources

"""Exercise the original110 byte cases and repairs through the real public helpers."""

import hashlib
import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import TypedDict, cast

import pytest

from evidence_manifest_toolkit import (
    ConfigurationError,
    DigestBasis,
    InputRefused,
    Limits,
    canonicalize_json,
    reference_bytes,
)


class LimitFields(TypedDict):
    """Describe the six complete original controlled limit-fixture fields.

    Attributes
    ----------
    max_json_bytes, max_blob_bytes : int
        Explicit whole JSON acquisition and individual reference read bounds.
    max_total_reference_bytes, max_reference_count : int
        Explicit shared closure byte and unique-node bounds.
    max_graph_depth, max_json_depth : int
        Original selected closure and JSON container depth bounds.
    """

    max_json_bytes: int
    max_blob_bytes: int
    max_total_reference_bytes: int
    max_reference_count: int
    max_graph_depth: int
    max_json_depth: int


class SourceCase(TypedDict):
    """Retain the complete portable original raw input, oracles and explicit recovery link.

    Attributes
    ----------
    case_id : str
        Original immutable case name, including published binary64 identity when applicable.
    explicit_limits : LimitFields
        All six original acquisition bounds, including deliberately malformed controls.
    schema_id_declaration : str or None
        Exact declaration label without registration or schema acceptance.
    expected_code, expected_error_class : str or None
        Original before-call refusal code/type, absent for successful canonicalization.
    expected_raw_BlobRef, expected_canonical_BlobRef : dict or None
        Entire independently frozen five-field value expectations, including optional None.
    original_recovery_id : str or None
        Explicit original distinct repair case, without replacing the failed input.
    raw_hex, expected_canonical_hex : str or None
        Entire original source and expected canonical bytes; failed canonicalization has None.
    """

    case_id: str
    explicit_limits: LimitFields
    schema_id_declaration: str | None
    expected_code: str | None
    expected_error_class: str | None
    expected_raw_BlobRef: dict[str, str | None] | None
    expected_canonical_BlobRef: dict[str, str | None] | None
    original_recovery_id: str | None
    raw_hex: str
    expected_canonical_hex: str | None


_FIXTURE = Path(__file__).parent / "fixtures/json-reference-source-vectors.json"
_CASES = cast(list[SourceCase], json.loads(_FIXTURE.read_bytes())["cases"])
_BY_ID = {case["case_id"]: case for case in _CASES}


def _canonical_case(case: SourceCase) -> None:
    """Compare complete public canonical bytes or the original typed refusal.

    Parameters
    ----------
    case : SourceCase
        Entire unchanged source case with original bytes, positive/negative limits and oracle.
    """
    original = bytes.fromhex(case["raw_hex"])
    limits = Limits(**case["explicit_limits"])
    code = case["expected_code"]
    if code is None:
        expected = case["expected_canonical_hex"]
        assert expected is not None
        assert canonicalize_json(original, limits=limits) == bytes.fromhex(expected)
    else:
        error_type = ConfigurationError if code == "configuration_error" else InputRefused
        with pytest.raises(error_type) as caught:
            canonicalize_json(original, limits=limits)
        assert type(caught.value).__name__ == case["expected_error_class"]
        assert caught.value.reason.code == code
    assert bytes.fromhex(case["raw_hex"]) == original


def _reference_case(case: SourceCase, basis: DigestBasis) -> None:
    """Compare every public returned reference field without changing source serialization.

    Parameters
    ----------
    case : SourceCase
        Complete original controlled bytes, declaration labels, limits and reference oracle.
    basis : {"raw_bytes", "jcs_content"}
        Explicit original identity mode; invalid JSON still has raw byte custody.
    """
    original = bytes.fromhex(case["raw_hex"])
    limits = Limits(**case["explicit_limits"])
    code = case["expected_code"]
    if basis == "raw_bytes" and code != "configuration_error":
        code = None
    if code is None:
        actual = reference_bytes(
            original,
            media_type="application/json",
            digest_basis=basis,
            schema_id=case["schema_id_declaration"],
            limits=limits,
        )
        expected = (
            case["expected_raw_BlobRef"]
            if basis == "raw_bytes"
            else case["expected_canonical_BlobRef"]
        )
        assert asdict(actual) == expected
    else:
        error_type = ConfigurationError if code == "configuration_error" else InputRefused
        with pytest.raises(error_type) as caught:
            reference_bytes(
                original,
                media_type="application/json",
                digest_basis=basis,
                schema_id=case["schema_id_declaration"],
                limits=limits,
            )
        assert type(caught.value).__name__ == case["expected_error_class"]
        assert caught.value.reason.code == code
    assert bytes.fromhex(case["raw_hex"]) == original


@pytest.mark.parametrize("case", _CASES, ids=[case["case_id"] for case in _CASES])
def test_canonicalize_original_bytes_and_recovery(case: SourceCase) -> None:
    """Check entire original canonical outputs/refusals and each original explicit repair.

    Parameters
    ----------
    case : SourceCase
        One of the original110 immutable cases, including all published numeric rows.
    """
    _canonical_case(case)
    recovery = case["original_recovery_id"]
    if recovery is not None:
        _canonical_case(_BY_ID[recovery])


@pytest.mark.parametrize("basis", ("raw_bytes", "jcs_content"))
@pytest.mark.parametrize("case", _CASES, ids=[case["case_id"] for case in _CASES])
def test_reference_original_basis_whole_fields_and_recovery(
    case: SourceCase, basis: DigestBasis
) -> None:
    """Check each original raw/canonical identity and independent repaired input.

    Parameters
    ----------
    case : SourceCase
        Entire original raw input with independently frozen complete reference expectations.
    basis : {"raw_bytes", "jcs_content"}
        Exact caller-selected identity mode, without parsing malformed raw custody as evidence.
    """
    _reference_case(case, basis)
    recovery = case["original_recovery_id"]
    if recovery is not None:
        _reference_case(_BY_ID[recovery], basis)


@pytest.mark.parametrize("leaf", (b'"\\u0001"', b'{"\\u0001":null}'))
def test_canonical_native_recursion_refusal_and_same_process_recovery(leaf: bytes) -> None:
    """Keep deep-document failures typed across acquisition and canonical serialization.

    Parameters
    ----------
    leaf : bytes
        Canonical escaped string value or object key at the deepest source level.

    Notes
    -----
    The real interpreter limit remains unchanged. Complete valid JSON inputs near
    that boundary either retain their exact canonical bytes or return the original
    limit refusal; an implementation exception must never escape the public API.
    Escaped values and object keys exercise the writer's actual string callbacks
    and object-key ordering at the real interpreter boundary.
    """
    recursion_limit = sys.getrecursionlimit()
    limits = Limits(1048576, 1048576, 16777216, 1024, 64, recursion_limit + 64)
    refused = 0
    for depth in range(max(1, recursion_limit - 128), recursion_limit + 1):
        original = b"[" * depth + leaf + b"]" * depth
        try:
            canonical = canonicalize_json(original, limits=limits)
        except InputRefused as error:
            refused += 1
            assert asdict(error.reason) == {
                "code": "limit_exceeded",
                "subject_digest": None,
                "claim_id": None,
                "pointer": None,
                "detail": "JSON input refused.",
            }
        else:
            assert canonical == original
    assert refused > 0
    recovery = b'{"recovery":"\\u0001"}'
    assert canonicalize_json(recovery, limits=limits) == recovery
    assert sys.getrecursionlimit() == recursion_limit


def test_cli_native_recursion_refuses_before_report_publication(tmp_path: Path) -> None:
    """Return the complete typed depth refusal through the real inspection command.

    Parameters
    ----------
    tmp_path : Path
        Fresh owned input/configuration/output directory for the native CLI process.
    """
    original = b"[" * (sys.getrecursionlimit() + 32) + b"0" + b"]" * (sys.getrecursionlimit() + 32)
    content = tmp_path / "content.json"
    content.write_bytes(original)
    limits = tmp_path / "limits.json"
    limits.write_text(
        json.dumps(
            {
                "max_json_bytes": 1048576,
                "max_blob_bytes": 1048576,
                "max_total_reference_bytes": 16777216,
                "max_reference_count": 1024,
                "max_graph_depth": 64,
                "max_json_depth": sys.getrecursionlimit() + 64,
            }
        ),
        encoding="utf-8",
    )
    report = tmp_path / "report.json"
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "evidence_manifest_toolkit",
            "inspect",
            "--content",
            str(content),
            "--limits",
            str(limits),
            "--report",
            str(report),
        ],
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 2 and result.stderr == b""
    assert json.loads(result.stdout) == {
        "operation": "inspect",
        "reasons": [
            {
                "code": "limit_exceeded",
                "subject_digest": None,
                "claim_id": None,
                "pointer": None,
                "detail": "JSON input refused.",
            }
        ],
    }
    assert not report.exists() and content.read_bytes() == original


def test_original_document_with_unmatched_closer_and_full_recovery() -> None:
    """Refuse an extra closing container while retaining the complete raw byte identity."""
    case = _BY_ID["manifest-reordered"]
    original = bytes.fromhex(case["raw_hex"])
    malformed = original + b"]"
    limits = Limits(**case["explicit_limits"])
    raw_expected = {
        "digest": "sha256:" + hashlib.sha256(malformed).hexdigest(),
        "byte_length": str(len(malformed)),
        "media_type": "application/json",
        "digest_basis": "raw_bytes",
        "schema_id": case["schema_id_declaration"],
    }
    expected_reason = {
        "code": "invalid_json",
        "subject_digest": None,
        "claim_id": None,
        "pointer": None,
        "detail": "Input is not valid strict JSON.",
    }
    with pytest.raises(InputRefused) as canonical_failure:
        canonicalize_json(malformed, limits=limits)
    assert asdict(canonical_failure.value.reason) == expected_reason
    with pytest.raises(InputRefused) as reference_failure:
        reference_bytes(
            malformed,
            media_type="application/json",
            digest_basis="jcs_content",
            schema_id=case["schema_id_declaration"],
            limits=limits,
        )
    assert asdict(reference_failure.value.reason) == expected_reason
    raw_reference = reference_bytes(
        malformed,
        media_type="application/json",
        digest_basis="raw_bytes",
        schema_id=case["schema_id_declaration"],
        limits=limits,
    )
    assert asdict(raw_reference) == raw_expected
    expected = case["expected_canonical_hex"]
    assert expected is not None
    assert canonicalize_json(original, limits=limits) == bytes.fromhex(expected)
    assert original == bytes.fromhex(case["raw_hex"]) and malformed == original + b"]"


def test_original_wrong_limit_object_precedes_document_refusal() -> None:
    """Keep the original noninstance configuration refusal before complete source acquisition."""
    packet: dict[str, list[dict[str, object]]] = json.loads(
        (Path(__file__).parent / "fixtures/limits-validate-source-vectors.json").read_bytes()
    )
    wrong_case = next(case for case in packet["cases"] if case["case_id"] == "noninstance-mapping")
    wrong_limits = cast(dict[str, object], wrong_case["input"])
    unchanged_limits = dict(wrong_limits)
    source_case = _BY_ID["manifest-reordered"]
    original = bytes.fromhex(source_case["raw_hex"])
    malformed = original + b"]"
    with pytest.raises(ConfigurationError) as caught:
        canonicalize_json(malformed, limits=cast(Limits, wrong_limits))
    assert asdict(caught.value.reason) == wrong_case["expected_reason"]
    limits = Limits(**source_case["explicit_limits"])
    expected = source_case["expected_canonical_hex"]
    assert expected is not None
    assert canonicalize_json(original, limits=limits) == bytes.fromhex(expected)
    assert wrong_limits == unchanged_limits
    assert original == bytes.fromhex(source_case["raw_hex"]) and malformed == original + b"]"
