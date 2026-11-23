# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Validate actual public pages, native source documentation and strict rendering."""

import ctypes
import json
import os
import select
import signal
import struct
import subprocess
import time
from html.parser import HTMLParser
from pathlib import Path

import pytest

from tests.conftest import SOURCE, payload, run_guard, snapshots, source_python
from tests.test_atomic_publication import actual_strace as actual_strace


class DialogNames(HTMLParser):
    """Inspect accessible dialog labels in the original native HTML output."""

    def __init__(self) -> None:
        """Collect labels from one independent generated public page."""
        super().__init__()
        self.names: list[str | None] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Record the authored accessible name on each actual dialog element."""
        attributes = dict(attrs)
        if attributes.get("role") == "dialog":
            self.names.append(attributes.get("aria-label"))


@pytest.mark.parametrize(
    "case",
    [
        "file-link",
        "anchor",
        "outside",
        "visible",
        "api",
        "release",
        "private",
        "asset",
        "docstring",
        "syntax",
        "funding",
        "renderer",
        "rendered-broken",
        "cache-link",
        "interface-docstring",
    ],
)
def test_public_documentation_refusals(root: Path, case: str) -> None:
    """Supply concrete invalid public input and observe the genuine guard/tool."""
    path = root / "README.md"
    text = path.read_text()
    additions = {
        "file-link": "[missing](missing.md)",
        "anchor": "[anchor](README.md#does-not-exist)",
        "outside": "[outside](../../private.md)",
        "visible": "SPDX-License-Identifier" + ": AGPL-3.0-or-later",
        "api": "emt seal is implemented",
        "release": "https://doi.org/10.1234/false",
        "private": "[private](.coordination/private.md)",
    }
    if case in additions:
        path.write_text(text + "\n" + additions[case] + "\n")
    elif case == "asset":
        (root / "docs/assets/anulum_logo.png").write_bytes(b"wrong actual logo")
    elif case in ("docstring", "syntax"):
        source = root / "tools/check_repository_metadata.py"
        source.write_text(
            source.read_text() + "\ndef undocumented() -> None:\n    return None\n"
            if case == "docstring"
            else "not valid python )\n"
        )
    elif case == "funding":
        funding = root / ".github/FUNDING.yml"
        funding.write_text(funding.read_text().replace("github: anulum", "github: foreign"))
    elif case == "renderer":
        (root / "mkdocs.yml").write_text("plugins: [not-installed]\n")
    elif case == "cache-link":
        import shutil

        shutil.rmtree(root / ".tool-cache")
        (root / ".tool-cache").symlink_to(root / "docs", target_is_directory=True)
    elif case == "interface-docstring":
        source = root / "tools/received_interface.pyi"
        source.write_text(
            (root / "tools/check_repository_metadata.py").read_text().split('"""', 1)[0]
            + '\n"""Received interface under inspection."""\n'
            + "def observed_digest(data: bytes) -> str:\n    ...\n"
        )
    else:
        (root / "docs/index.md").write_text(
            (root / "docs/index.md").read_text() + "\n::: actual_missing_reference_module\n"
        )
    payload(run_guard("documentation", root), 2)


def test_real_renderer_and_empty_roster(root: Path) -> None:
    """Complete renderer acceptance includes honest empty support state."""
    before = snapshots(root)
    a = run_guard("documentation", root)
    b = run_guard("documentation", root)
    payload(a, 0)
    assert a.stdout == b.stdout
    assert snapshots(root) == before


@pytest.mark.parametrize("fault", ["missing", "modified", "malicious", "extra", "link"])
def test_received_template_refusal_prevents_execution(root: Path, fault: str) -> None:
    """Refuse actual unknown or changed executable overrides before native rendering."""
    template = root / "overrides/main.html"
    marker = root.parent / "received-template-was-executed"
    received = "{{ cycler.__init__.__globals__.os.system(" + repr("touch " + str(marker)) + ") }}"
    if fault == "missing":
        template.unlink()
    elif fault == "modified":
        template.write_text(template.read_text() + "\nReceived extra template content.\n")
    elif fault == "malicious":
        template.write_text(template.read_text() + "\n" + received + "\n")
    elif fault == "extra":
        (template.parent / "base.html").write_text(received)
    else:
        template.unlink()
        template.symlink_to(root / "docs/index.md")
    before = snapshots(root)
    value = payload(run_guard("documentation", root), 2)
    assert value["reasons"]
    assert not marker.exists()
    assert snapshots(root) == before
    assert not any(
        p.name.startswith(("renderer-", "docs-")) for p in (root / ".tool-cache").iterdir()
    )


def test_late_received_template_and_config_changes_cannot_execute(root: Path) -> None:
    """Only captured pinned bytes reach the renderer after real input substitution."""
    cache = root / ".tool-cache"
    marker = root.parent / "late-received-template-was-executed"
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert descriptor >= 0
    assert libc.inotify_add_watch(descriptor, os.fsencode(cache), 0x100) >= 0
    process = subprocess.Popen(
        source_python(str(SOURCE / "tools/check_documentation.py"), "--root", str(root), "--json"),
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    changed = False
    try:
        deadline = time.monotonic() + 25
        while not changed and time.monotonic() < deadline:
            assert select.select([descriptor], [], [], max(0, deadline - time.monotonic()))[0]
            data = os.read(descriptor, 65536)
            offset = 0
            while offset < len(data):
                _, mask, _, length = struct.unpack_from("iIII", data, offset)
                name = data[offset + 16 : offset + 16 + length].split(b"\0", 1)[0].decode()
                offset += 16 + length
                if mask & 0x100 and name.startswith("renderer-"):
                    assert libc.inotify_add_watch(descriptor, os.fsencode(cache / name), 0x8) >= 0
                elif mask & 0x8 and name == "mkdocs.yml":
                    template = root / "overrides/main.html"
                    template.write_text(
                        template.read_text()
                        + "\n{{ cycler.__init__.__globals__.os.system("
                        + repr("touch " + str(marker))
                        + ") }}\n"
                    )
                    (root / "mkdocs.yml").write_text("plugins: [received-uninstalled-plugin]\n")
                    changed = True
        assert changed
        before = snapshots(root)
        stdout, stderr = process.communicate(timeout=30)
        payload(subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), 0)
        assert not marker.exists()
        assert snapshots(root) == before
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        os.close(descriptor)
    assert not any(p.name.startswith(("renderer-", "docs-")) for p in cache.iterdir())


def test_real_renderer_excludes_private_documents_and_assets(root: Path, tmp_path: Path) -> None:
    """Original native rendering keeps private pages, assets and search content out."""
    private = root / "docs/internal/rendering-custody"
    private.mkdir(parents=True, exist_ok=True)
    marker = "Owner-private rendering sentinel"
    (private / "owner-review.md").write_text(
        (root / "docs/index.md").read_text().split("-->", 1)[0]
        + "-->\n\n# Private owner review\n\n"
        + marker
        + "\n"
    )
    (private / "retained-source.bin").write_bytes(b"actual private retained source bytes")
    before = snapshots(root)
    payload(run_guard("documentation", root), 0)
    output = tmp_path / "actual-public-documentation"
    rendered = subprocess.run(
        source_python(
            "-m",
            "mkdocs",
            "build",
            "--strict",
            "--config-file",
            str(root / "mkdocs.yml"),
            "--site-dir",
            str(output),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert rendered.returncode == 0, rendered.stderr.decode()
    assert not (output / "internal").exists()
    for name in (
        "index.html",
        "ARCHITECTURE/index.html",
        "validation-tooling/index.html",
        "THREAT_MODEL/index.html",
        "adr/0001-repository-boundary/index.html",
    ):
        assert (output / name).is_file()
        dialogs = DialogNames()
        dialogs.feed((output / name).read_text())
        assert dialogs.names == ["Search"], name
    search = json.loads((output / "search/search_index.json").read_bytes())
    assert all(not item["location"].startswith("internal/") for item in search["docs"])
    assert marker not in (output / "search/search_index.json").read_text()
    assert snapshots(root) == before


@pytest.mark.parametrize(
    "destination",
    ["#evidence-manifest-toolkit", "docs/assets/anulum_logo.png#xywh=0,0,10,10"],
)
def test_real_local_anchors_and_media_fragments(root: Path, destination: str) -> None:
    """Accept genuine same-page anchors and non-Markdown media destinations."""
    path = root / "README.md"
    path.write_text(path.read_text() + "\n[Observed local target](" + destination + ")\n")
    before = snapshots(root)
    payload(run_guard("documentation", root), 0)
    assert snapshots(root) == before


def test_actual_documentation_interruption_cleans_owned_output(root: Path) -> None:
    """Interrupt the real public renderer operation and preserve its owned inputs."""
    before = snapshots(root)
    process = subprocess.Popen(
        source_python(str(SOURCE / "tools/check_documentation.py"), "--root", str(root), "--json"),
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10
        while not list((root / ".tool-cache").glob("docs-*")):
            assert process.poll() is None, "Renderer exited before the interruption boundary."
            assert time.monotonic() < deadline
            time.sleep(0.01)
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=15)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
    value = payload(
        subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), 3
    )
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    assert any(isinstance(reason, dict) and reason["code"] == "interrupted" for reason in reasons)
    assert not list((root / ".tool-cache").glob("docs-*"))
    assert snapshots(root) == before


@pytest.mark.parametrize("signum", ["SIGTERM", "SIGINT"])
def test_actual_event_loop_startup_interruption_has_no_resource_warnings(
    root: Path, tmp_path: Path, actual_strace: Path, signum: str
) -> None:
    """A real signal at native loop socket creation leaves no output or warnings."""
    before = snapshots(root)
    trace = tmp_path / (signum + "-loop-startup.native-trace")
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-o",
            str(trace),
            "-e",
            "trace=socketpair,rt_sigprocmask,execve,close",
            "-e",
            "inject=socketpair:signal=" + signum + ":when=1",
            *source_python(
                str(SOURCE / "tools/check_documentation.py"), "--root", str(root), "--json"
            ),
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    value = payload(result, 3)
    assert value["reasons"] == [
        {
            "code": "interrupted",
            "location": None,
            "detail": "Required local infrastructure condition failed: interrupted.",
        }
    ]
    raw = trace.read_bytes()
    assert b"socketpair(" in raw and signum.encode() in raw
    assert b"mkdocs" not in raw
    assert snapshots(root) == before
    assert not list((root / ".tool-cache").glob("docs-*"))


@pytest.mark.parametrize("fault", ["missing-index", "private-directory", "private-symlink"])
def test_actual_renderer_success_with_missing_output_is_refused(root: Path, fault: str) -> None:
    """Genuine renderer success cannot pass missing or private real output paths."""
    cache = root / ".tool-cache"
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert descriptor >= 0
    assert libc.inotify_add_watch(descriptor, os.fsencode(cache), 0x100) >= 0
    before = snapshots(root)
    process = subprocess.Popen(
        source_python(str(SOURCE / "tools/check_documentation.py"), "--root", str(root), "--json"),
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    removed = False
    directory: Path | None = None
    try:
        deadline = time.monotonic() + 25
        while not removed and time.monotonic() < deadline:
            assert select.select([descriptor], [], [], max(0, deadline - time.monotonic()))[0]
            data = os.read(descriptor, 65536)
            offset = 0
            while offset < len(data):
                _, mask, _, length = struct.unpack_from("iIII", data, offset)
                name = data[offset + 16 : offset + 16 + length].split(b"\0", 1)[0].decode()
                offset += 16 + length
                if mask & 0x100 and name.startswith("docs-"):
                    directory = cache / name
                    assert libc.inotify_add_watch(descriptor, os.fsencode(directory), 0x8) >= 0
                elif mask & 0x8 and name == "index.html":
                    assert directory is not None and directory.is_dir()
                    index = directory / name
                    assert index.is_file() and index.stat().st_size > 0
                    if fault == "missing-index":
                        index.unlink()
                    elif fault == "private-directory":
                        (directory / "internal").mkdir()
                        (directory / "internal/retained-owner-record.txt").write_bytes(
                            b"actual retained private output bytes"
                        )
                    else:
                        (directory / "internal").symlink_to(directory / "absent-private-target")
                    removed = True
        assert removed
        stdout, stderr = process.communicate(timeout=15)
        value = payload(
            subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), 2
        )
        code = (
            "documentation.renderer-failure"
            if fault == "missing-index"
            else "documentation.private-plan"
        )
        assert value["reasons"] == [
            {
                "code": code,
                "location": "docs/index.md" if fault == "missing-index" else "docs/internal",
                "detail": "Required local infrastructure condition failed: " + code + ".",
            }
        ]
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        os.close(descriptor)
    assert snapshots(root) == before
    assert not any(path.name.startswith("docs-") for path in cache.iterdir())


def test_real_cache_link_after_configuration_read_is_refused(
    root: Path, tmp_path: Path, actual_strace: Path
) -> None:
    """A genuine late cache substitution is refused before creating renderer output."""
    cache = root / ".tool-cache"
    held = root.parent / "actual-retained-documentation-cache"
    assert not held.exists()
    before = snapshots(root)
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert descriptor >= 0
    assert libc.inotify_add_watch(descriptor, os.fsencode(root / "mkdocs.yml"), 0x10) >= 0
    trace = tmp_path / "actual-late-documentation-cache.native-trace"
    process = subprocess.Popen(
        [
            str(actual_strace),
            "-f",
            "-qq",
            "-s",
            "4096",
            "-o",
            str(trace),
            "-e",
            "trace=newfstatat,lstat,stat,statx,openat,close,execve,exit_group",
            "-e",
            "inject=newfstatat:delay_enter=1ms",
            "-e",
            "inject=lstat:delay_enter=1ms",
            *source_python(
                str(SOURCE / "tools/check_documentation.py"), "--root", str(root), "--json"
            ),
        ],
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        assert select.select([descriptor], [], [], 55)[0]
        assert os.read(descriptor, 4096)
        cache.rename(held)
        cache.symlink_to(held, target_is_directory=True)
        stdout, stderr = process.communicate(timeout=25)
        value = payload(
            subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), 2
        )
        assert value["reasons"] == [
            {
                "code": "repository_inventory.symlink-entry",
                "location": ".tool-cache",
                "detail": "Required local infrastructure condition failed: "
                "repository_inventory.symlink-entry.",
            }
        ]
        raw = trace.read_bytes()
        assert b"DELAYED" in raw and os.fsencode(root / "mkdocs.yml") in raw
        assert os.fsencode(cache) in raw and b"S_IFLNK" in raw
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        os.close(descriptor)
        if held.exists():
            cache.unlink()
            held.rename(cache)
    assert snapshots(root) == before
    assert cache.is_dir() and not cache.is_symlink() and not held.exists()


_PRIVATE_LOCATIONS = (
    b".coordination/",
    b"/media/anulum",
    b"/home/anulum",
    b"aaa_God_of_the_Math_Collection",
)
_PRIVATE_LOCATION_REFUSALS = frozenset(
    {".gitignore", "tests/test_documentation.py", "tools/local_scaffold/documentation.py"}
)


def test_no_tracked_file_names_a_private_location() -> None:
    """Keep every tracked file, fixtures included, free of private workstation locations.

    The documentation policy refuses these locations in rendered pages. The repository is
    public, so the same refusal holds for every tracked file; only the files that state the
    refusal itself may hold the strings.
    """
    listed = subprocess.run(
        ["git", "-C", str(SOURCE), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    offenders = []
    for name in listed.decode("utf-8").split("\0"):
        if not name or name in _PRIVATE_LOCATION_REFUSALS:
            continue
        content = (SOURCE / name).read_bytes()
        if any(location in content for location in _PRIVATE_LOCATIONS):
            offenders.append(name)
    assert offenders == []
