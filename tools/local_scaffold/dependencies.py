# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Check locked development dependencies against their actual installed producers."""

from __future__ import annotations

import hashlib
import importlib.metadata
import platform
import re
import tomllib
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.utils import InvalidName, canonicalize_name

from .inputs import json_object, read_bytes, read_text, yaml_object
from .maintained_dependency import check_maintained_dependency
from .metadata import installed_graph
from .package_metadata import check_package_metadata, direct_input_pins
from .policy import (
    EXPECTED_GRAPH,
    LOCK_SHA256,
    NATIVE_TOOLS,
    PROVENANCE_SHA256,
    PYTHON_SUPPORTED_RANGE,
)
from .quality_configuration import check_quality_configuration
from .reports import Fault, Report


def native_tool(role: str) -> Path:
    """Resolve a fixed producer-verified tool; input never supplies an executable.

    Parameters
    ----------
    role : str
        Authored native-tool role selected from NATIVE_TOOLS, such as actionlint or gitleaks.

    Returns
    -------
    Path
        Fixed trusted-source binary whose complete SHA-256 matches its producer binding.

    Raises
    ------
    Fault
        Raised when the bounded producer read fails or its exact digest differs.
    """
    repository = Path(__file__).resolve().parents[2]
    record = next(item for item in NATIVE_TOOLS if item["role"] == role)
    name = str(record["binary_relative_path"])
    data = read_bytes(repository, name, 100_000_000)
    if hashlib.sha256(data).hexdigest() != record["binary_sha256"]:
        raise Fault("source_identity_mismatch", name)
    return repository / name


def verify_sources_and_producers(root: Path, report: Report) -> None:
    """Inspect the whole lock, direct inputs, producer/licence bindings and hooks.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives lock/direct-input, installed graph, producer licence/artifact, hook and security-snapshot refusals.

    Raises
    ------
    Fault
        Raised for unavailable/malformed bounded inputs or invalid producer configuration.
    """
    if platform.python_version() not in SpecifierSet(PYTHON_SUPPORTED_RANGE):
        raise Fault("dependency_alignment.incompatible-patch", "dependency-provenance.json")
    lock = read_text(root, "requirements-dev.txt")
    if hashlib.sha256(lock.encode()).hexdigest() != LOCK_SHA256:
        report.add("dependency_alignment.missing-hash", "requirements-dev.txt")
    installed = installed_graph()
    if installed != EXPECTED_GRAPH:
        report.add("dependency_alignment.missing-transitive", "dependency-provenance.json")
    blocks = re.findall(r"(?m)^([\w.-]+)==([^\s]+)((?:[^\n]*\n)(?:    [^\n]*\n)*)", lock)
    locked: dict[str, str] = {}
    for name, version, hashes in blocks:
        key = canonicalize_name(name)
        if key in locked or not re.search(r"--hash=sha256:[0-9a-f]{64}(?:\s|$)", hashes):
            report.add("dependency_alignment.missing-hash", "requirements-dev.txt")
        locked[key] = version
    if locked != EXPECTED_GRAPH:
        report.add("dependency_alignment.missing-transitive", "requirements-dev.txt")
    direct = direct_input_pins(root)
    provenance_bytes = read_bytes(root, "dependency-provenance.json")
    if hashlib.sha256(provenance_bytes).hexdigest() != PROVENANCE_SHA256:
        report.add("dependency_alignment.licence-drift", "dependency-provenance.json")
    provenance = json_object(root, "dependency-provenance.json")
    packages = provenance.get("packages")
    if not isinstance(packages, list):
        raise Fault("configuration_invalid", "dependency-provenance.json", 4)
    for record in packages:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            raise Fault("configuration_invalid", "dependency-provenance.json", 4)
        name = str(record["name"])
        try:
            key = canonicalize_name(name, validate=True)
        except InvalidName as error:
            raise Fault("configuration_invalid", "dependency-provenance.json", 4) from error
        if (record.get("role") == "direct") != (key in direct):
            report.add("dependency_alignment.hook-drift", "requirements-dev.in")
        if key in direct and direct[key] != record.get("version"):
            report.add("dependency_alignment.hook-drift", "requirements-dev.in")
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            if record.get("role") == "direct":
                report.add("dependency_alignment.missing-tool", "dependency-provenance.json", 3)
            else:
                report.add("dependency_alignment.missing-transitive", "dependency-provenance.json")
            continue
        metadata = distribution.read_text("METADATA")
        if metadata is None:
            report.add("dependency_alignment.wrong-producer", "dependency-provenance.json")
        elif hashlib.sha256(metadata.encode()).hexdigest() != record.get("metadata_sha256"):
            report.add("dependency_alignment.wrong-producer", "dependency-provenance.json")
        artifact = record.get("source_artifact")
        if key == "rfc8785" and record.get("version") == "0.1.4+emt.1":
            check_maintained_dependency(root, artifact, lock, report)
        elif not isinstance(artifact, dict) or not isinstance(artifact.get("url"), str):
            report.add("dependency_alignment.mutable-download", "dependency-provenance.json")
        elif not str(artifact["url"]).startswith("https://files.pythonhosted.org/packages/"):
            report.add("dependency_alignment.mutable-download", "dependency-provenance.json")
        elif "--hash=sha256:" + str(artifact.get("sha256")) not in lock:
            report.add("dependency_alignment.missing-hash", "requirements-dev.txt")
    try:
        configuration = tomllib.loads(read_text(root, "pyproject.toml"))
    except tomllib.TOMLDecodeError as error:
        raise Fault("configuration_invalid", "pyproject.toml", 4) from error
    check_package_metadata(configuration, report)
    tooling = configuration.get("tool")
    typing = tooling.get("mypy") if isinstance(tooling, dict) else None
    if (
        not isinstance(typing, dict)
        or typing.get("strict") is not True
        or typing.get("python_version") != "3.13"
    ):
        report.add("dependency_alignment.hook-drift", "pyproject.toml")
    check_quality_configuration(yaml_object(root, ".pre-commit-config.yaml"), report)


def verify(root: Path, report: Report) -> None:
    """Check all installed sources and separately admitted current registry advisories.

    Parameters
    ----------
    root : Path
        Inspected inputs, never a producer or admission authority.
    report : Report
        Receives complete source, producer and current advisory refusals.

    Raises
    ------
    Fault
        Required original inputs or the current trusted admission are unavailable,
        unsafe, invalid or changed.
    """
    verify_sources_and_producers(root, report)
    from .security import verify as verify_security

    verify_security(root, report)
