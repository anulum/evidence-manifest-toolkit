# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Inspect native attribution, JSON sidecars and actual licensed source bytes."""

from __future__ import annotations

import hashlib
import math
import os
import sys
import tempfile
import time
from pathlib import Path

from .identity import SPDX_PREFIX
from .inputs import parse_json, read_bytes, read_text
from .inventory import owned_tree
from .ownership_header import has_native_header
from .policy import ASSETS, LEAF_SECONDS, LICENCE_SHA256, MAX_FILE, MAX_TREE, PROVENANCE_SHA256
from .processes import ProcessResult, run_process
from .reports import Fault, Report
from .source_materials import check_source_material

COPYRIGHTS = (
    "SPDX-FileCopyrightText: 1996-2026 Miroslav Šotek <protoscience@anulum.li> (concepts)",
    "SPDX-FileCopyrightText: 2020-2026 Miroslav Šotek <protoscience@anulum.li> (code)",
)


def header_check(name: str, text: str, report: Report) -> None:
    """Validate the native invisible/comment header and reject conflicting SPDX.

    Parameters
    ----------
    name : str
        Maintained lexical filename selecting invisible Markdown/HTML, bare licence or hash-comment ownership syntax.
    text : str
        Original decoded source/notice text; every SPDX declaration is checked for conflict.
    report : Report
        Receives exact ownership/header/SPDX conflicts without rewriting source.
    """
    if name.endswith((".md", ".html")):
        if not has_native_header(text, style="invisible"):
            report.add("source_provenance.visible-header", name)
    elif name.endswith(".license"):
        if not has_native_header(text, style="bare"):
            report.add("source_provenance.wrong-notice", name)
    else:
        if not has_native_header(text, style="comment"):
            code = (
                "source_provenance.missing-spdx"
                if SPDX_PREFIX not in text[:1000]
                else "source_provenance.wrong-notice"
            )
            report.add(code, name)
    declarations = [
        line.split(SPDX_PREFIX, 1)[1].strip()
        for line in text.splitlines()
        if line.lstrip().startswith(("# " + SPDX_PREFIX, SPDX_PREFIX))
    ]
    if declarations != ["AGPL-3.0-or-later"]:
        report.add("source_provenance.conflicting-spdx", name)


def public_bytes(root: Path, report: Report) -> dict[str, bytes]:
    """Read every bounded owned public input without traversing private caches.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives owned-tree findings; cached and owner-private working documents are outside the public projection.

    Returns
    -------
    dict[str, bytes]
        Every original owned public file's complete bounded bytes keyed by lexical name.

    Raises
    ------
    Fault
        Raised for owned-tree resource/availability or no-follow file read failure.
    """
    return {
        name: read_bytes(root, name, MAX_FILE)
        for name in owned_tree(root, report)
        if not name.startswith("docs/internal/")
    }


def analyse_reuse(root: Path, timeout: float = LEAF_SECONDS) -> ProcessResult:
    """Run unchanged native REUSE on every original public byte under one deadline.

    Original relative names, licences, sidecars and nested policy files are
    retained. A private temporary tree excludes only the already defined cache
    and internal-document scope. Received Git ignores cannot suppress public
    files. The absolute producer runs in isolated mode without executable
    discovery and never imports received code.
    Original and delivered bytes must still agree after the real producer exits.
    Original source bytes plus both complete native capture ceilings share MAX_TREE;
    the generic per-pipe default remains unchanged for every other producer.

    Parameters
    ----------
    root : Path
        Repository whose original public bytes are captured into an owned complete REUSE view.
    timeout : float
        Finite positive inclusive budget, at most LEAF_SECONDS; original capture, native REUSE, final identity checks and cleanup share it.

    Returns
    -------
    ProcessResult
        Unmodified native REUSE exit/captures after exact view/original identity verification; received Git configuration/modules are not executed.

    Raises
    ------
    Fault
        Raised for invalid budget, unavailable native producer, changed original/view bytes or exhausted deadline.
    """
    if (
        isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > LEAF_SECONDS
    ):
        raise Fault("configuration_invalid", exit_code=4)
    deadline = time.monotonic() + timeout
    report = Report("source_provenance")
    original = public_bytes(root, report)
    if report.exit_code:
        raise Fault("policy_refusal", exit_code=report.exit_code)
    capture_budget = (MAX_TREE - sum(len(data) for data in original.values())) // 2
    if capture_budget <= 0:
        raise Fault("resource_limit")
    with tempfile.TemporaryDirectory(prefix="emt-reuse-") as temporary:
        directory = Path(temporary)
        for name, data in original.items():
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Fault("tool_timeout", exit_code=3)
        result = run_process(
            [sys.executable, "-I", "-m", "reuse", "--root", str(directory), "lint", "--json"],
            directory,
            remaining,
            max_capture_bytes=capture_budget,
            environment={
                **os.environ,
                "PATH": os.devnull,
                "GIT_CEILING_DIRECTORIES": str(directory.parent),
            },
        )
        if public_bytes(directory, report) != original or public_bytes(root, report) != original:
            raise Fault("source_identity_mismatch")
        if report.exit_code:
            raise Fault("policy_refusal", exit_code=report.exit_code)
    if time.monotonic() >= deadline:
        raise Fault("tool_timeout", exit_code=3)
    return result


def verify(root: Path, report: Report) -> None:
    """Validate actual source ownership and run the installed REUSE checker.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives owned/third-party licence/header/provenance and actual native REUSE refusals.

    Raises
    ------
    Fault
        Raised for unsafe/unavailable/unbounded input or native process/identity failure.
    """
    files = owned_tree(root, report)
    for name in files:
        if name.startswith("docs/internal/"):
            continue
        try:
            if check_source_material(root, name, report):
                continue
            if name in ASSETS:
                if hashlib.sha256(read_bytes(root, name, MAX_FILE)).hexdigest() != ASSETS[name]:
                    report.add("source_provenance.third-party", name)
                continue
            if name == "LICENSE" or name.startswith("LICENSES/"):
                if name in ("LICENSE", "LICENSES/AGPL-3.0-or-later.txt"):
                    if hashlib.sha256(read_bytes(root, name)).hexdigest() != LICENCE_SHA256:
                        report.add("source_provenance.third-party", name)
                continue
            if name.lower().endswith(".json"):
                value = parse_json(read_bytes(root, name), name)
                sidecar_name = name + ".license"
                if sidecar_name not in files:
                    report.add("source_provenance.json-sidecar", name)
                    continue
                sidecar = read_text(root, sidecar_name)
                if not check_source_material(root, sidecar_name, report) and any(
                    line not in sidecar.splitlines() for line in COPYRIGHTS
                ):
                    report.add("source_provenance.copyright-record", sidecar_name)
                for key in ("SPDX-License-Identifier", "spdx_license_identifier"):
                    if (
                        isinstance(value, dict)
                        and key in value
                        and value[key] != "AGPL-3.0-or-later"
                    ):
                        report.add("source_provenance.conflicting-spdx", name)
                if name == "capability-inventory.json":
                    if not isinstance(value, dict):
                        raise Fault("configuration_invalid", name, 4)
                    source = value.get("source_metadata")
                    digest = hashlib.sha256(read_bytes(root, "repository-domain.json")).hexdigest()
                    if source != {"path": "repository-domain.json", "sha256": digest}:
                        report.add("source_provenance.generated-drift", name)
            else:
                header_check(name, read_text(root, name), report)
        except Fault as fault:
            report.observe(fault)
    if (
        hashlib.sha256(read_bytes(root, "dependency-provenance.json")).hexdigest()
        != PROVENANCE_SHA256
    ):
        report.add("source_provenance.third-party", "dependency-provenance.json")
    result = analyse_reuse(root)
    if result.exit_code:
        report.add("source_provenance.reuse-invalid", "REUSE.toml")
