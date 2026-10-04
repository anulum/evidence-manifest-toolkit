# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Inspect honest public scope, real links, native docstrings and strict rendering."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import markdown

from .bindings import DOCUMENTATION_TEMPLATE_SHA256
from .identity import SPDX_PREFIX
from .inputs import read_bytes, read_text, relative_path, yaml_object
from .inventory import owned_tree
from .policy import ASSETS, FUNDING, HEADER, MAX_FILE, MKDOCS_SHA256
from .processes import run_process
from .production_names import check_text
from .reports import Fault, Report


class RenderedPage(HTMLParser):
    """Collect actual rendered anchors and visible text without executing markup.

    Attributes
    ----------
    anchors : set[str]
        Nonempty id/name anchors observed in native Markdown-rendered HTML.
    visible : list[str]
        Actual parsed visible character data; invisible ownership comments are excluded.
    """

    def __init__(self) -> None:
        """Initialise independent page observations for one actual renderer output."""
        super().__init__(convert_charrefs=True)
        self.anchors: set[str] = set()
        self.visible: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Retain real named anchors from rendered HTML elements.

        Parameters
        ----------
        tag : str
            HTMLParser element tag; anchor collection depends on id/name attributes.
        attrs : list[tuple[str, str | None]]
            Actual parsed attribute pairs; nonempty id and name values enter the page's anchor set.
        """
        for key, value in attrs:
            if key in ("id", "name") and value:
                self.anchors.add(value)

    def handle_data(self, data: str) -> None:
        """Record visible text; invisible ownership comments are excluded by HTML.

        Parameters
        ----------
        data : str
            Visible parsed HTML character data appended to this page's text observations.
        """
        self.visible.append(data)


def page(text: str) -> RenderedPage:
    """Render maintained Markdown with actual heading slugs and parse its HTML.

    Parameters
    ----------
    text : str
        Maintained Markdown rendered with toc, fenced-code and table extensions.

    Returns
    -------
    RenderedPage
        Observed heading anchors and visible HTML text; source ownership comments are not visible text.
    """
    result = RenderedPage()
    result.feed(markdown.markdown(text, extensions=["toc", "fenced_code", "tables"]))
    return result


def native_documentation(root: Path, report: Report) -> None:
    """Require native documentation on every maintained module, class and function.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives native-doc-gap reasons for undocumented maintained Python modules, classes and functions.

    Raises
    ------
    Fault
        Raised for invalid maintained Python syntax or unavailable/unbounded source input.
    """
    for name in owned_tree(root, report):
        if not name.endswith((".py", ".pyi")) or name.startswith("docs/internal/"):
            continue
        try:
            module = ast.parse(read_text(root, name))
        except SyntaxError as error:
            raise Fault("documentation.native-doc-gap", name) from error
        nodes = [
            module,
            *(
                node
                for node in ast.walk(module)
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            ),
        ]
        if any(not ast.get_docstring(node) for node in nodes):
            report.add("documentation.native-doc-gap", name)


def verify(root: Path, report: Report) -> None:
    """Validate public claims, local targets, assets and the real configured renderer.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives claim/link/asset/ownership/doc/renderer refusals, including any private rendered path.

    Raises
    ------
    Fault
        Raised for unavailable or unsafe inputs, cache symlinks, native process interruption/deadline or bounded resource failure.
    """
    files = owned_tree(root, report)
    for name in files:
        if not name.endswith(".md") or name.startswith(("LICENSES/", "docs/internal/")):
            continue
        text = read_text(root, name)
        rendered = page(text)
        visible = " ".join(rendered.visible)
        check_text(visible, name, report)
        if not text.startswith("<!--\n" + "\n".join(HEADER) + "\n-->") or SPDX_PREFIX in visible:
            report.add("documentation.visible-provenance", name)
        if re.search(
            r"(?:\.coordination/|agentic-shared/|codex-[0-9a-f]|gpt-[0-9]|/home/|/media/)", text
        ):
            report.add("documentation.private-plan", name)
        if re.search(
            r"(?:pip install evidence.manifest.toolkit|emt (?:seal|verify).*implemented|from evidence_manifest_toolkit import)",
            text,
            re.IGNORECASE,
        ):
            report.add("documentation.fake-api", name)
        if re.search(
            r"(?:\[!\[|doi\.org/10\.|api\.scorecard\.dev|pypi\.org/project/evidence.manifest.toolkit)",
            text,
            re.IGNORECASE,
        ):
            report.add("documentation.fake-release", name)
        for destination in re.findall(r"!?\[[^\]]*\]\(([^\s)]+)\)", text):
            url = urlsplit(destination)
            if url.scheme or url.netloc:
                continue
            target = root / name
            if url.path:
                candidate = target.parent / unquote(url.path)
                try:
                    # Lexical normalisation preserves symlink ancestors for the
                    # no-follow input check; resolving would erase that evidence.
                    relative = Path(os.path.abspath(candidate)).relative_to(root).as_posix()
                except ValueError:
                    report.add("documentation.local-link", name)
                    continue
                target = relative_path(root, relative)
            if not target.is_file():
                report.add("documentation.local-link", name)
            elif url.fragment and target.suffix == ".md":
                linked = page(read_text(root, target.relative_to(root).as_posix()))
                if unquote(url.fragment) not in linked.anchors:
                    report.add("documentation.local-link", name)
    for name, digest in ASSETS.items():
        if hashlib.sha256(read_bytes(root, name, MAX_FILE)).hexdigest() != digest:
            report.add("documentation.asset-drift", name)
    if yaml_object(root, ".github/FUNDING.yml") != FUNDING:
        report.add("documentation.funding-drift", ".github/FUNDING.yml")
    native_documentation(root, report)
    if report.exit_code != 0:
        return
    configuration = read_bytes(root, "mkdocs.yml")
    if hashlib.sha256(configuration).hexdigest() != MKDOCS_SHA256:
        report.add("documentation.renderer-failure", "mkdocs.yml")
        return
    if [name for name in files if name.startswith("overrides/")] != ["overrides/main.html"]:
        report.add("documentation.renderer-failure", "overrides/main.html")
        return
    template = read_bytes(root, "overrides/main.html")
    if hashlib.sha256(template).hexdigest() != DOCUMENTATION_TEMPLATE_SHA256:
        report.add("documentation.renderer-failure", "overrides/main.html")
        return
    cache = root / ".tool-cache"
    if cache.is_symlink():
        raise Fault("repository_inventory.symlink-entry", ".tool-cache")
    cache.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="docs-", dir=cache))
    try:
        with tempfile.TemporaryDirectory(prefix="renderer-", dir=cache) as staging:
            workspace = Path(staging)
            templates = workspace / "overrides"
            templates.mkdir()
            (templates / "main.html").write_bytes(template)
            projected = (
                configuration.decode()
                .replace(
                    "watch: [tools]",
                    "docs_dir: "
                    + json.dumps(str(root / "docs"))
                    + "\nwatch: ["
                    + json.dumps(str(root / "tools"))
                    + "]",
                )
                .replace("  custom_dir: overrides", "  custom_dir: " + json.dumps(str(templates)))
                .replace("paths: [tools]", "paths: [" + json.dumps(str(root / "tools")) + "]")
            )
            config = workspace / "mkdocs.yml"
            config.write_text(projected)
            result = run_process(
                [
                    sys.executable,
                    "-I",
                    "-m",
                    "mkdocs",
                    "build",
                    "--strict",
                    "--config-file",
                    str(config),
                    "--site-dir",
                    str(output),
                ],
                root,
            )
        if result.exit_code:
            report.add("documentation.renderer-failure", "mkdocs.yml")
        elif not (output / "index.html").is_file():
            report.add("documentation.renderer-failure", "docs/index.md")
        elif os.path.lexists(output / "internal"):
            report.add("documentation.private-plan", "docs/internal")
    finally:
        shutil.rmtree(output)
