# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — original source material public correspondence

"""Retain complete original licensed materials and refuse changed bytes through source CLI."""

from pathlib import Path

import pytest

from tests.conftest import payload, run_guard, snapshots
from tests.test_ownership_header import ownership_root as ownership_root


@pytest.mark.parametrize(
    "case",
    (
        "wheel",
        "patch",
        "wheel-license",
        "patch-license",
        "typing-marker",
        "raw-object",
        "raw-notice",
        "refusal-vectors",
        "signer-vectors",
        "inspection-vectors",
        "json-vectors",
        "qpu-vectors",
    ),
)
def test_native_material_refusal_and_full_original_byte_recovery(
    ownership_root: Path, case: str
) -> None:
    """Refuse every selected original material disagreement without changing its healthy source.

    Parameters
    ----------
    ownership_root : Path
        Complete small genuine source cohort including the native REUSE producer inputs.
    case : str
        One actual fixed third-party artifact, marker or original raw fixture disagreement.

    Notes
    -----
    Baseline and recovery run the real full public source-provenance command over
    this original cohort. They do not qualify the complete repository or scientific runtime.
    """
    before = snapshots(ownership_root)
    baseline = run_guard("source_provenance", ownership_root)
    payload(baseline, 0)
    names = {
        "wheel": "vendor/rfc8785/rfc8785-0.1.4+emt.1-py3-none-any.whl",
        "patch": "vendor/rfc8785/upstream-typing.patch",
        "wheel-license": "vendor/rfc8785/rfc8785-0.1.4+emt.1-py3-none-any.whl.license",
        "patch-license": "vendor/rfc8785/upstream-typing.patch.license",
        "typing-marker": "src/evidence_manifest_toolkit/py.typed",
        "refusal-vectors": "tests/domain/fixtures/blobref-mapping-source-vectors.json",
        "signer-vectors": "tests/domain/fixtures/cli-signer-empty-installation-source.json",
        "inspection-vectors": "tests/domain/fixtures/inspection-common-source-vectors.json",
        "json-vectors": "tests/domain/fixtures/json-reference-source-vectors.json",
        "qpu-vectors": "tests/domain/fixtures/qpu-registry-source.json",
    }
    if case in names:
        name = names[case]
    else:
        folder = ownership_root / "tests/domain/fixtures/evidence-command-sources/objects"
        name = str(
            next(
                path for path in sorted(folder.iterdir()) if path.suffix != ".license"
            ).relative_to(ownership_root)
        )
        if case == "raw-notice":
            name += ".license"
        else:
            assert case == "raw-object"
    path = ownership_root / name
    original = path.read_bytes()
    changed_bytes = b"x" if case == "typing-marker" else bytes([original[0] ^ 1]) + original[1:]
    path.write_bytes(changed_bytes)
    changed = snapshots(ownership_root)
    actual = payload(run_guard("source_provenance", ownership_root), 2)
    reasons = actual["reasons"]
    assert isinstance(reasons, list)
    code = (
        "source_identity_mismatch"
        if case
        in (
            "raw-object",
            "refusal-vectors",
            "signer-vectors",
            "inspection-vectors",
            "json-vectors",
            "qpu-vectors",
        )
        else "source_provenance.wrong-notice"
        if case in ("typing-marker", "raw-notice")
        else "source_provenance.third-party"
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
