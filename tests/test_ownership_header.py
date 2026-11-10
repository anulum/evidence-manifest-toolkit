# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — native ownership public-source tests

"""Exercise native source, notice and invisible headers through the real public guard."""

import shutil
from pathlib import Path

import pytest

from tests.conftest import SOURCE, payload, run_guard, snapshots

_STYLES = (
    ("comment", "src/evidence_manifest_toolkit/_utc.py"),
    ("bare", "src/evidence_manifest_toolkit/py.typed.license"),
    ("invisible", "docs/api.md"),
)


@pytest.fixture
def ownership_root(tmp_path: Path) -> Path:
    """Copy a small complete original licensing cohort, without producing surrogate source.

    Parameters
    ----------
    tmp_path : Path
        Owned Samsung root for genuine whole-source inputs and native REUSE outputs.

    Returns
    -------
    Path
        Real unchanged project/runtime/third-party/fixture bytes and complete native licensing.
    """
    objects = SOURCE / "tests/domain/fixtures/evidence-command-sources/objects"
    original_object = next(path for path in sorted(objects.iterdir()) if path.suffix != ".license")
    names = [
        "REUSE.toml",
        "LICENSE",
        "LICENSES/AGPL-3.0-or-later.txt",
        "LICENSES/Apache-2.0.txt",
        "dependency-provenance.json",
        "dependency-provenance.json.license",
        "src/evidence_manifest_toolkit/_utc.py",
        "src/evidence_manifest_toolkit/py.typed",
        "src/evidence_manifest_toolkit/py.typed.license",
        "docs/api.md",
        "vendor/rfc8785/rfc8785-0.1.4+emt.1-py3-none-any.whl",
        "vendor/rfc8785/rfc8785-0.1.4+emt.1-py3-none-any.whl.license",
        "vendor/rfc8785/upstream-typing.patch",
        "vendor/rfc8785/upstream-typing.patch.license",
        "tests/domain/fixtures/diagnostic-source-vectors.json",
        "tests/domain/fixtures/diagnostic-source-vectors.json.license",
        "tests/domain/fixtures/blobref-mapping-source-vectors.json",
        "tests/domain/fixtures/blobref-mapping-source-vectors.json.license",
        "tests/domain/fixtures/cli-signer-empty-installation-source.json",
        "tests/domain/fixtures/cli-signer-empty-installation-source.json.license",
        "tests/domain/fixtures/inspection-common-source-vectors.json",
        "tests/domain/fixtures/inspection-common-source-vectors.json.license",
        "tests/domain/fixtures/json-reference-source-vectors.json",
        "tests/domain/fixtures/qpu-registry-source.json",
        "tests/domain/fixtures/qpu-registry-source.json.license",
        "tests/domain/fixtures/json-reference-source-vectors.json.license",
        str(original_object.relative_to(SOURCE)),
        str(original_object.relative_to(SOURCE)) + ".license",
    ]
    for name in names:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / name, target)
    return tmp_path


@pytest.mark.parametrize("style, name", _STYLES, ids=[row[0] for row in _STYLES])
@pytest.mark.parametrize("change", ("foundation", "project", "empty-description"))
def test_native_full_header_refusal_and_unchanged_public_recovery(
    ownership_root: Path, style: str, name: str, change: str
) -> None:
    """Preserve valid descriptive headers and refuse every selected complete header disagreement.

    Parameters
    ----------
    ownership_root : Path
        Genuine finite original source cohort checked through the complete public command.
    style : str
        Existing native comment, notice or invisible syntax.
    name : str
        Actual original file whose complete ownership header is examined.
    change : str
        Wrong fixed foundation, wrong project or missing seventh-line description.
    """
    before = snapshots(ownership_root)
    baseline = run_guard("source_provenance", ownership_root)
    payload(baseline, 0)
    path = ownership_root / name
    original = path.read_bytes()
    text = original.decode()
    if change == "foundation":
        altered = text.replace("ORCID: 0009-0009-3560-0851", "ORCID: 0000-0000-0000-0000", 1)
    elif change == "project":
        altered = text.replace("EVIDENCE-MANIFEST-TOOLKIT —", "OTHER-PROJECT —", 1)
    else:
        assert change == "empty-description"
        lines = text.splitlines(keepends=True)
        index = 7 if style == "invisible" else 6
        prefix = "# " if style == "comment" else ""
        lines[index] = prefix + "EVIDENCE-MANIFEST-TOOLKIT — \n"
        altered = "".join(lines)
    assert altered.encode() != original
    path.write_text(altered)
    changed = snapshots(ownership_root)
    actual = payload(run_guard("source_provenance", ownership_root), 2)
    reasons = actual["reasons"]
    assert isinstance(reasons, list)
    code = (
        "source_provenance.visible-header"
        if style == "invisible"
        else "source_provenance.wrong-notice"
    )
    assert {
        "code": code,
        "location": name,
        "detail": "Required local infrastructure condition failed: " + code + ".",
    } in reasons
    assert snapshots(ownership_root) == changed
    path.write_bytes(original)
    recovered = run_guard("source_provenance", ownership_root)
    assert (recovered.returncode, recovered.stdout, recovered.stderr) == (0, baseline.stdout, b"")
    assert snapshots(ownership_root) == before
