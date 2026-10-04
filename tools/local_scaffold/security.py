# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Consume a separately produced real pip-audit snapshot without network fallback."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packaging.utils import canonicalize_name

from .inputs import json_object, read_bytes
from .policy import AUDIT_PRODUCED_AT, AUDIT_SHA256, EXPECTED_GRAPH
from .reports import Report


def verify(root: Path, report: Report) -> None:
    """Verify producer-admitted snapshot bytes, freshness and the complete real graph.

    Parameters
    ----------
    root : Path
        Repository supplying original dependency provenance and the separately sealed private pip-audit snapshot.
    report : Report
        Receives producer/digest/time-window/complete103-graph/vulnerability mismatches; no live network audit or seal refresh occurs.

    Raises
    ------
    Fault
        Raised for unsafe/unavailable/unbounded or malformed retained snapshot input.
    """
    name = ".tool-cache/security/pip-audit.json"
    source = "dependency-provenance.json"
    snapshot = json_object(root, source).get("security_audit")
    expected = {
        "producer": "pip-audit",
        "version": EXPECTED_GRAPH["pip-audit"],
        "sha256": AUDIT_SHA256,
        "produced_at": AUDIT_PRODUCED_AT,
    }
    if not isinstance(snapshot, dict) or set(snapshot) != set(expected):
        report.add("configuration_invalid", source, 4)
        return
    if snapshot != expected:
        report.add("source_identity_mismatch", source)
    stamp = snapshot["produced_at"]
    try:
        produced = datetime.fromisoformat(stamp) if isinstance(stamp, str) else None
    except ValueError:
        produced = None
    if produced is None or produced.tzinfo is None:
        report.add("configuration_invalid", source, 4)
        return
    age = datetime.now(UTC) - produced
    if age > timedelta(days=1) or age < -timedelta(minutes=5):
        report.add("tool_unavailable", name, 3)
        return
    data = read_bytes(root, name)
    if hashlib.sha256(data).hexdigest() != AUDIT_SHA256:
        report.add("source_identity_mismatch", name)
    value = json_object(root, name)
    dependencies = value.get("dependencies")
    if not isinstance(dependencies, list) or set(value) != {"dependencies", "fixes"}:
        report.add("configuration_invalid", name, 4)
        return
    actual: dict[str, str] = {}
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {"name", "version", "vulns"}:
            report.add("policy_refusal", name)
            continue
        dependency_name, version = dependency["name"], dependency["version"]
        if not isinstance(dependency_name, str) or not isinstance(version, str):
            report.add("policy_refusal", name)
            continue
        key = canonicalize_name(dependency_name)
        if key in actual or dependency["vulns"] != []:
            report.add("policy_refusal", name)
        actual[key] = version
    if actual != EXPECTED_GRAPH or value["fixes"] != []:
        report.add("dependency_alignment.wrong-producer", name)
