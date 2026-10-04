# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Check public parser limits on actual bytes and finite native files."""

import math
import os
from pathlib import Path

import pytest

from local_scaffold.inputs import (
    decode,
    parse_json,
    read_bytes,
    relative_path,
    root_directory,
    validate_value,
    yaml_object,
)
from local_scaffold.reports import Fault
from tests.conftest import payload, run_guard, snapshots


@pytest.mark.parametrize("value", [{1: "not-string"}, object(), math.inf, [0] * 100001])
def test_json_value_refusals(value: object) -> None:
    """Non-JSON types and true count limits refuse under the public parser API."""
    with pytest.raises(Fault):
        validate_value(value)


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":1,"a":2}',
        b"[NaN]",
        b"[Infinity]",
        b'"\\ud800"',
        b'"\\u001b"',
        b"[" * 65 + b"0" + b"]" * 65,
        b" " * 1048577,
    ],
)
def test_raw_parser_refusals(data: bytes) -> None:
    """Native byte parsing refuses malformed scalar/depth/size input before use."""
    with pytest.raises(Fault):
        parse_json(data)


@pytest.mark.parametrize(
    "text",
    [
        "a: &alias [1]\nb: *alias\n",
        "a: 1\na: 2\n",
        "!!python/object:os.system {}\n",
        "a: !custom value\n",
        "[one,two]",
        "a: [",
        "? [one,two]\n: value\n",
        "a: 2026-10-02\n",
        "a: .inf\n",
        "<<: {a: 1}\n",
        "a: " + "[" * 65 + "0" + "]" * 65,
    ],
)
def test_safe_yaml_refusals(root: Path, text: str) -> None:
    """Real YAML events, explicit types and native parser errors remain closed."""
    (root / "config.yml").write_text(text)
    with pytest.raises(Fault):
        yaml_object(root, "config.yml")


def test_actual_regular_file_and_path_limits(root: Path) -> None:
    """A real FIFO never blocks a read and unsafe relative paths never escape."""
    os.mkfifo(root / "named-pipe")
    with pytest.raises(Fault) as pipe:
        read_bytes(root, "named-pipe")
    assert pipe.value.code == "repository_inventory.special-file"
    with pytest.raises(Fault):
        relative_path(root, "../outside")
    with pytest.raises(Fault):
        decode(b"\x7f")
    with pytest.raises(Fault):
        parse_json(b" " * 1048577)
    assert parse_json(b'{"v":[true,false,null,1,1.5,"scalar"]}') == {
        "v": [True, False, None, 1, 1.5, "scalar"]
    }


def test_exact_value_limit_and_workflow_lines(root: Path) -> None:
    """True value counting admits its exact boundary and refuses an extra item."""
    data = b"[" + b",".join([b'"x"'] * 99999) + b"]"
    assert len(data) < 1048576
    parsed = parse_json(data)
    assert isinstance(parsed, list)
    assert len(parsed) == 99999
    path = root / "large.yml"
    path.write_text("# comment\n" * 1001)
    with pytest.raises(Fault):
        yaml_object(root, "large.yml", workflow=True)


def test_actual_post_stat_read_bound() -> None:
    """A genuine zero-size proc regular file must still obey the read byte cap."""
    with pytest.raises(Fault) as error:
        read_bytes(Path("/proc"), str(os.getpid()) + "/status", 1)
    assert error.value.code == "resource_limit"


def test_actual_unavailable_ancestor_and_root_file(root: Path) -> None:
    """Real denied traversal and nondirectory roots retain native availability meaning."""
    regular = root / "regular-file"
    regular.write_text("actual file")
    with pytest.raises(Fault) as file:
        root_directory(str(regular))
    assert file.value.exit_code == 3 and file.value.code == "root_unavailable"
    directory = root / "denied-directory"
    directory.mkdir()
    (directory / "child").write_text("actual unreadable path")
    directory.chmod(0)
    try:
        with pytest.raises(Fault) as traversal:
            relative_path(root, "denied-directory/child")
        assert traversal.value.code == "input_unavailable" and traversal.value.exit_code == 3
    finally:
        directory.chmod(0o700)


def test_actual_symlink_and_missing_repository_roots(root: Path, tmp_path: Path) -> None:
    """The public guard refuses an actual root link and reports a missing root unavailable."""
    before = snapshots(root)
    linked = tmp_path / "linked-root"
    linked.symlink_to(root, target_is_directory=True)
    for candidate, expected_exit, expected_reason in (
        (linked, 2, "root_symlink"),
        (tmp_path / "missing-root", 3, "root_unavailable"),
    ):
        report = payload(run_guard("repository_metadata", candidate), expected_exit)
        reasons = report["reasons"]
        assert isinstance(reasons, list) and len(reasons) == 1
        reason = reasons[0]
        assert isinstance(reason, dict) and reason["code"] == expected_reason
        assert reason["location"] is None
    assert snapshots(root) == before
