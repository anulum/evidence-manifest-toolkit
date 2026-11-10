# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — development package declaration alignment

"""Check the complete local development package without admitting runtime qualification."""

from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version

from .inputs import read_text
from .reports import Fault, Report

_PROJECT = {
    "name": "evidence-manifest-toolkit",
    "version": "0.0.0.dev0",
    "description": "Explicit offline evidence references, detached statements and common verification",
    "readme": "README.md",
    "requires-python": ">=3.13.18,<3.14",
    "license": "AGPL-3.0-or-later",
    "license-files": ["LICENSE", "LICENSES/*.txt"],
    "authors": [{"name": "Miroslav Šotek", "email": "protoscience@anulum.li"}],
    "dependencies": [
        "jsonschema==4.26.0",
        "referencing==0.37.0",
        "pycryptodome==3.24.0",
        "rfc8785==0.1.4+emt.1",
    ],
    "scripts": {"emt": "evidence_manifest_toolkit._cli:main"},
}
_BUILD = {"requires": ["poetry-core==2.5.0"], "build-backend": "poetry.core.masonry.api"}
_POETRY = {
    "packages": [{"include": "evidence_manifest_toolkit", "from": "src"}],
    "include": [
        {
            "path": "src/evidence_manifest_toolkit/_native_entry_method.json",
            "format": ["sdist", "wheel"],
        },
        {
            "path": "src/evidence_manifest_toolkit/_native_entry_method.json.license",
            "format": ["sdist", "wheel"],
        },
        {
            "path": "src/evidence_manifest_toolkit/_qpu_registry_bindings.json",
            "format": ["sdist", "wheel"],
        },
        {
            "path": "src/evidence_manifest_toolkit/_qpu_registry_bindings.json.license",
            "format": ["sdist", "wheel"],
        },
        {"path": "src/evidence_manifest_toolkit/_schemas/*.json", "format": ["sdist", "wheel"]},
        {
            "path": "src/evidence_manifest_toolkit/_schemas/*.json.license",
            "format": ["sdist", "wheel"],
        },
        {"path": "src/evidence_manifest_toolkit/py.typed", "format": ["sdist", "wheel"]},
        {"path": "src/evidence_manifest_toolkit/py.typed.license", "format": ["sdist", "wheel"]},
    ],
}


def direct_input_pins(root: Path) -> dict[str, str]:
    """Read complete exact direct pins through the one declared local runtime include.

    Parameters
    ----------
    root : Path
        Bounded local source root; input lines never select arbitrary include paths or URLs.

    Returns
    -------
    dict of str to str
        Every unique direct development and runtime name with its exact declared version.

    Raises
    ------
    Fault
        A line is unpinned, duplicated or malformed, or selects an unrecognized include
        or download option. Actual input read faults retain their native diagnostics.
    """
    result: dict[str, str] = {}
    filenames = ["requirements-dev.in"]
    for name in filenames:
        for raw in read_text(root, name).splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if name == "requirements-dev.in" and line == "-r requirements-runtime.in":
                if "requirements-runtime.in" in filenames:
                    raise Fault("configuration_invalid", name, 4)
                filenames.append("requirements-runtime.in")
                continue
            if name == "requirements-runtime.in" and line == "--find-links vendor/rfc8785":
                continue
            package, separator, version = line.partition("==")
            if not separator or not version or any(character.isspace() for character in line):
                raise Fault("configuration_invalid", name, 4)
            try:
                key = canonicalize_name(package, validate=True)
                Version(version)
            except (InvalidName, InvalidVersion) as error:
                raise Fault("configuration_invalid", name, 4) from error
            if key in result:
                raise Fault("configuration_invalid", name, 4)
            result[key] = version
    return result


def check_package_metadata(
    configuration: Mapping[str, object],
    report: Report,
    *,
    refusal_code: Literal[
        "dependency_alignment.runtime-dep", "repository_inventory.private-packaged"
    ] = "dependency_alignment.runtime-dep",
) -> None:
    """Require the original scaffold or the complete known development package declaration.

    Parameters
    ----------
    configuration : Mapping
        Entire locally acquired TOML, without loading its backend or console entrypoint.
    report : Report
        Retains the existing runtime-dependency refusal if any known declaration differs.
    refusal_code : str
        Existing caller gate's exact package refusal; configuration never selects this value.

    Notes
    -----
    The development package is not a release or qualified capability. Source locks,
    installed producers, licenses and separately admitted audit evidence retain their
    independent gates. No project metadata can override those checks.
    """
    tooling = configuration.get("tool")
    poetry = tooling.get("poetry") if isinstance(tooling, dict) else None
    if "project" not in configuration and "build-system" not in configuration and poetry is None:
        return
    if (
        configuration.get("project") != _PROJECT
        or configuration.get("build-system") != _BUILD
        or poetry != _POETRY
    ):
        report.add(refusal_code, "pyproject.toml")
