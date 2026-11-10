# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete native source generation correspondence

"""Keep an entire prior descriptor distinct from the actual current installation."""

import hashlib
import json
from importlib.resources import files
from pathlib import Path

import pytest
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow
from tests.domain.test_verification_report_sources import _array, _object, _text

from evidence_manifest_toolkit import BlobRef

_PREVIOUS = (
    Path(__file__).parent / "fixtures/native-implementation-before-registry-description.json"
)
_PREVIOUS_SHA256 = "1980d2ef1ed7c361e70ce203c4500d2237b54874086a9483f0f4c83c483aa753"


@pytest.mark.parametrize("generation", ("previous", "current"))
def test_entire_native_descriptor_generation_through_public_verification(
    generation: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Refuse the full previous descriptor and retain current-source consistency separately.

    Parameters
    ----------
    generation : str
        Exact whole historical descriptor or the complete actual current generation.
    tmp_path : Path
        Owned whole original source/Clock/method inputs and a genuine bounded file Resolver.
    capfd : pytest.CaptureFixture
        Native public workflow output capture, without a substituted observation/provider.

    Notes
    -----
    The previous whole descriptor retains its own source generation. Each current
    row must match the entire actual installed file, including newly added modules.
    Matching current source reaches the pending
    V2 state refusal; it supplies no qualified Clock, method, authority or class.
    """
    previous = _PREVIOUS.read_bytes()
    assert len(previous) == 25286 and hashlib.sha256(previous).hexdigest() == _PREVIOUS_SHA256
    package = files("evidence_manifest_toolkit")
    current = package.joinpath("_native_launch_implementation.json").read_bytes()
    old = _object(json.loads(previous))
    new = _object(json.loads(current))
    assert set(old) == set(new) == {"method_id", "method_version", "implementation_files"}
    assert old["method_id"] == new["method_id"] == "whole_native_launch_source_interpretation"
    assert old["method_version"] == new["method_version"] == "1"
    old_rows = [_object(row) for row in _array(old["implementation_files"])]
    new_rows = [_object(row) for row in _array(new["implementation_files"])]
    assert len(old_rows) == 149
    names = [_text(row["filename"]) for row in new_rows]
    assert names == sorted(set(names))
    old_cli = next(row for row in old_rows if row["filename"] == "_cli_operations.py")
    new_cli = next(row for row in new_rows if row["filename"] == "_cli_operations.py")
    assert old_cli["sha256"] != new_cli["sha256"]
    for row in new_rows:
        raw = package.joinpath(*_text(row["filename"]).split("/")).read_bytes()
        assert str(len(raw)) == row["byte_length"]
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
    selected = previous if generation == "previous" else current
    selected_ref = BlobRef(
        "sha256:" + hashlib.sha256(selected).hexdigest(),
        str(len(selected)),
        "application/json",
        "raw_bytes",
    )
    calls: list[tuple[BlobRef | str, int]] = []
    assert_whole_clock_source_workflow(
        "native_binding_installation_descriptor_changed"
        if generation == "previous"
        else "native_binding_matching",
        tmp_path,
        capfd,
        launcher_implementation_bytes=selected,
        resolver_calls=calls,
    )
    assert selected_ref in {reference for reference, _ in calls}
    assert all(type(cap) is int and cap > 0 for _, cap in calls)
    assert _PREVIOUS.read_bytes() == previous
    assert package.joinpath("_native_launch_implementation.json").read_bytes() == current
