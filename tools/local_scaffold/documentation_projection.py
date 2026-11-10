# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — captured native documentation source paths

"""Project the entire captured renderer configuration onto its exact owned source paths."""

from pathlib import Path

import yaml

from .inputs import Json, parse_yaml, relative_path
from .reports import Fault


def _object(value: Json) -> dict[str, Json]:
    """Require the captured renderer's existing object shape without fabricating defaults.

    Parameters
    ----------
    value : Json
        Complete original decoded configuration node.

    Returns
    -------
    dict
        Original mutable mapping used only for explicit local path projection.

    Raises
    ------
    Fault
        The required original configuration node is not an object.
    """
    if not isinstance(value, dict):
        raise Fault("configuration_invalid", "mkdocs.yml", 4)
    return value


def project_documentation_configuration(data: bytes, root: Path, templates: Path) -> bytes:
    """Preserve complete pinned configuration while binding actual docs and both source directories.

    Parameters
    ----------
    data : bytes
        Entire original captured MkDocs bytes, already independently source-hash checked.
    root : Path
        Actual caller's bounded source root; no received executable or plugin is imported.
    templates : Path
        Owned temporary directory containing only the complete captured pinned template.

    Returns
    -------
    bytes
        Full native YAML preserving nav, plugins, strict/private/docstring/inspection controls
        and every unrelated field, with only explicit source/template paths projected.

    Raises
    ------
    Fault
        A required captured structure or recognized source selection differs, or a path is unsafe.
    """
    configuration = _object(parse_yaml(data, "mkdocs.yml"))
    watch = configuration.get("watch")
    if not isinstance(watch, list) or watch not in (["tools"], ["tools", "src"]):
        raise Fault("configuration_invalid", "mkdocs.yml", 4)
    configuration["docs_dir"] = str(relative_path(root, "docs"))
    configuration["watch"] = [str(relative_path(root, str(name))) for name in watch]
    _object(configuration["theme"])["custom_dir"] = str(templates)
    plugins = configuration["plugins"]
    if not isinstance(plugins, list):
        raise Fault("configuration_invalid", "mkdocs.yml", 4)
    selected = [
        plugin for plugin in plugins if isinstance(plugin, dict) and "mkdocstrings" in plugin
    ]
    if len(selected) != 1:
        raise Fault("configuration_invalid", "mkdocs.yml", 4)
    handlers = _object(_object(selected[0])["mkdocstrings"])["handlers"]
    python = _object(_object(handlers)["python"])
    paths = python.get("paths")
    if not isinstance(paths, list) or paths not in (["tools"], ["tools", "src"]):
        raise Fault("configuration_invalid", "mkdocs.yml", 4)
    python["paths"] = [str(relative_path(root, str(name))) for name in paths]
    return yaml.safe_dump(configuration, sort_keys=False).encode("utf-8")
