# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual native renderer source projection

"""Render complete original tools/src documentation from a relocated real source tree."""

from pathlib import Path

import pytest
import yaml

from local_scaffold.documentation_projection import project_documentation_configuration
from local_scaffold.reports import Fault
from tests.conftest import payload, run_guard, snapshots


def test_native_tools_and_runtime_projection_with_original_configuration_recovery(
    root: Path,
) -> None:
    """Resolve both original source directories, refuse config drift and recover unchanged bytes.

    Parameters
    ----------
    root : Path
        Complete real repository copy, including original API pages, runtime and templates.

    Notes
    -----
    The public documentation guard invokes actual strict MkDocs rendering for
    baseline and recovery. A path containing spaces exercises native path binding.
    No configuration, template, source module or renderer is substituted.
    """
    relocated = root.with_name("original documentation source with spaces")
    root.rename(relocated)
    before = snapshots(relocated)
    original = (relocated / "mkdocs.yml").read_bytes()
    assert b"watch: [tools, src]" in original
    assert b"paths: [tools, src]" in original
    baseline = run_guard("documentation", relocated)
    payload(baseline, 0)
    assert snapshots(relocated) == before

    config = relocated / "mkdocs.yml"
    config.write_bytes(original.replace(b"paths: [tools, src]", b"paths: [tools]"))
    changed = snapshots(relocated)
    refused = payload(run_guard("documentation", relocated), 2)
    reasons = refused["reasons"]
    assert isinstance(reasons, list)
    assert {
        "code": "documentation.renderer-failure",
        "location": "mkdocs.yml",
        "detail": "Required local infrastructure condition failed: documentation.renderer-failure.",
    } in reasons
    assert snapshots(relocated) == changed

    config.write_bytes(original)
    recovered = run_guard("documentation", relocated)
    assert (recovered.returncode, recovered.stdout, recovered.stderr) == (0, baseline.stdout, b"")
    assert snapshots(relocated) == before


@pytest.mark.parametrize(
    "case",
    (
        "object",
        "watch-kind",
        "watch-path",
        "plugins-kind",
        "plugins-missing",
        "paths-kind",
        "paths-path",
        "theme",
    ),
)
def test_captured_configuration_rejects_structural_drift(root: Path, case: str) -> None:
    """Refuse adverse original renderer configuration through its public projection API."""
    original = (root / "mkdocs.yml").read_bytes()
    config = yaml.safe_load(original)
    if case == "object":
        config = []
    elif case == "watch-kind":
        config["watch"] = "tools"
    elif case == "watch-path":
        config["watch"] = ["other"]
    elif case == "plugins-kind":
        config["plugins"] = {}
    elif case == "plugins-missing":
        config["plugins"] = []
    elif case == "paths-kind":
        next(p for p in config["plugins"] if isinstance(p, dict) and "mkdocstrings" in p)[
            "mkdocstrings"
        ]["handlers"]["python"]["paths"] = "tools"
    elif case == "paths-path":
        next(p for p in config["plugins"] if isinstance(p, dict) and "mkdocstrings" in p)[
            "mkdocstrings"
        ]["handlers"]["python"]["paths"] = ["other"]
    else:
        config["theme"] = []
    before = snapshots(root)
    with pytest.raises(Fault) as error:
        project_documentation_configuration(
            yaml.safe_dump(config).encode(), root, root / "templates"
        )
    assert error.value.exit_code == (2 if case == "object" else 4)
    assert snapshots(root) == before
