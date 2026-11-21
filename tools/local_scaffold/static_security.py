# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Retain native static findings and admit only four exact source-bound attributions.

Two are the reviewed provider imports of the signature module (B413). Two are the import and
the single call of the fixed NTP capture (B404, B603): one constant argument vector with an
absolute executable, no shell, standard input from /dev/null and a one-variable environment.
Each is admitted only at its exact line and only while its whole module matches its digest.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import math
import sys
import tempfile
import time
from pathlib import Path

from .audit_context import encode, trusted_root
from .audit_store import open_store
from .dependencies import verify_sources_and_producers
from .inputs import Json, parse_json, read_bytes
from .policy import EXPECTED_GRAPH, LEAF_SECONDS
from .processes import ProcessObservation, run_process
from .provenance import public_bytes
from .reports import Fault, Report

_SIGNATURE = "src/evidence_manifest_toolkit/_native_signature.py"
_SIGNATURE_SHA256 = "e92a70ce9b1fb1b95eb9a685f55c7508d084fa092648c41e264247c01fcc7b17"
_SOURCE_LINES = frozenset({14, 15})
_CAPTURE = "src/evidence_manifest_toolkit/_timesyncd_capture.py"
_CAPTURE_SHA256 = "085bb4b2b145cddfa96a94df609edff853f70f5a510cf506bf2f27dbb685178a"
_CAPTURE_FINDINGS = frozenset({("B404", 20), ("B603", 83)})


def inspect_findings(
    data: bytes,
    native_exit: int,
    signature: bytes | None,
    provider_version: str,
    report: Report,
    capture: bytes | None = None,
) -> None:
    """Classify complete native findings against the exact reviewed provider source.

    Parameters
    ----------
    data : bytes
        Original complete native Bandit JSON, never a synthesized clean result.
    native_exit : int
        Actual scanner completion status supplied by the owning operation.
    signature : bytes | None
        Exact source bytes delivered to the scanner for the reviewed signature module.
    provider_version : str
        Actual installed provider version already bound by the full producer guard.
    report : Report
        Receives schema, native failure and every unreviewed finding.
    capture : bytes | None
        Exact source bytes delivered to the scanner for the reviewed NTP capture module.

    Raises
    ------
    Fault
        The complete native JSON or finding shape is invalid or unbounded.

    Notes
    -----
    This semantic reader grants no producer authority. The owning operation runs
    the fixed real scanner, binds installed producers and verifies original bytes.
    """
    if type(native_exit) is not int:
        raise Fault("configuration_invalid", "native-static-report", 4)
    value = parse_json(data, "native-static-report")
    if not isinstance(value, dict):
        raise Fault("configuration_invalid", "native-static-report", 4)
    findings = value.get("results")
    if not isinstance(findings, list):
        raise Fault("configuration_invalid", "native-static-report", 4)
    if value.get("errors") != [] or native_exit not in (0, 1):
        report.add("tool_failed", "native-static-report")
    if (native_exit == 0) != (findings == []):
        report.add("tool_failed", "native-static-report")
    seen: set[tuple[object, object]] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise Fault("configuration_invalid", "native-static-report", 4)
        line = finding.get("line_number")
        place = (finding.get("filename"), line)
        accepted = place not in seen and (
            (
                finding.get("test_id") == "B413"
                and finding.get("filename") == _SIGNATURE
                and type(line) is int
                and line in _SOURCE_LINES
                and signature is not None
                and hashlib.sha256(signature).hexdigest() == _SIGNATURE_SHA256
                and provider_version == "3.24.0"
            )
            or (
                finding.get("filename") == _CAPTURE
                and type(line) is int
                and (finding.get("test_id"), line) in _CAPTURE_FINDINGS
                and capture is not None
                and hashlib.sha256(capture).hexdigest() == _CAPTURE_SHA256
            )
        )
        if not accepted:
            report.add("policy_refusal", "native-static-report")
        else:
            seen.add(place)


def verify(root: Path, report: Report, timeout: float = LEAF_SECONDS) -> None:
    """Inspect every maintained Python source and retain the complete native result.

    Parameters
    ----------
    root : Path
        Inspected source data; no received Python or scanner configuration executes.
    report : Report
        Receives all source, native-tool, finding and output-integrity refusals.
    timeout : float
        Finite positive caller ceiling no greater than the fixed leaf budget.

    Raises
    ------
    Fault
        Required source, native output or evidence publication is unavailable,
        malformed, altered or outside its resource/deadline boundary.

    Notes
    -----
    Bandit labels these exact imports as deprecated PyCrypto. They import the
    independently reviewed PyCryptodome 3.24.0 provider. Whole source identity,
    exact native locations and the complete installed producer graph must agree;
    other B413 findings remain refusals. Native severity and confidence stay all.
    The NTP capture module's subprocess import and its one fixed call are admitted
    the same way, at their two exact lines and only while the module matches its
    reviewed digest; any other subprocess finding remains a refusal.
    """
    if isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= LEAF_SECONDS:
        raise Fault("configuration_invalid", exit_code=4)
    deadline = time.monotonic() + timeout
    original = public_bytes(root, report)
    selected = {
        name: data
        for name, data in original.items()
        if name.endswith(".py") and name.startswith(("src/", "tools/"))
    }
    if not selected:
        raise Fault("input_unavailable", "python-source", 3)
    verify_sources_and_producers(root, report)
    if report.exit_code:
        return
    observation = ProcessObservation()
    with tempfile.TemporaryDirectory(prefix="emt-static-") as temporary:
        view = Path(temporary)
        for name, data in selected.items():
            destination = view / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        for name in ("src", "tools"):
            (view / name).mkdir(exist_ok=True)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Fault("tool_timeout", exit_code=3)
        result = run_process(
            [
                sys.executable,
                "-I",
                "-B",
                "-m",
                "bandit",
                "--ini",
                "/dev/null",
                "--ignore-nosec",
                "--severity-level",
                "all",
                "--confidence-level",
                "all",
                "-r",
                "src",
                "tools",
                "-f",
                "json",
                "-o",
                "native-report.json",
            ],
            view,
            remaining,
            observation=observation,
        )
        raw = read_bytes(view, "native-report.json")
        source_identity: dict[str, Json] = {
            name: hashlib.sha256(data).hexdigest() for name, data in selected.items()
        }
        with open_store(trusted_root(), write=True) as store:
            entry: dict[str, Json] = {
                "producer": "bandit",
                "version": EXPECTED_GRAPH["bandit"],
                "native_exit": result.exit_code,
                "report_sha256": store.object(raw),
                "stdout_sha256": store.object(result.stdout),
                "stderr_sha256": store.object(result.stderr),
                "source_sha256": hashlib.sha256(encode(source_identity)).hexdigest(),
            }
            store.object(encode(entry))
        if public_bytes(root, report) != original or any(
            read_bytes(view, name) != data for name, data in selected.items()
        ):
            raise Fault("source_identity_mismatch", "python-source")
        inspect_findings(
            raw,
            result.exit_code,
            selected.get(_SIGNATURE),
            importlib.metadata.version("pycryptodome"),
            report,
            selected.get(_CAPTURE),
        )
        if time.monotonic() >= deadline:
            raise Fault("tool_timeout", exit_code=3)
