# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — maintained wheel source correspondence

"""Check the exact maintained RFC wheel and every original derivation source."""

import hashlib
from pathlib import Path

from .inputs import Json, read_bytes
from .reports import Report

_WHEEL = "vendor/rfc8785/rfc8785-0.1.4+emt.1-py3-none-any.whl"
_WHEEL_SHA256 = "e04761706fcbbb5f0afd5fa74a7e6ea7484ce97f073adb5372ab8ee93230c48e"
_PROVENANCE = "vendor/rfc8785/source-provenance.json"
_PROVENANCE_SHA256 = "548226480527c0a1d254f769c670277d5cf204fa74390323aee6eee3aad90ffe"
MAINTAINED_ARTIFACT = {
    "kind": "maintained_wheel",
    "filename": "rfc8785-0.1.4+emt.1-py3-none-any.whl",
    "path": _WHEEL,
    "url": None,
    "bytes": 23461,
    "sha256": _WHEEL_SHA256,
    "provenance": {"path": _PROVENANCE, "sha256": _PROVENANCE_SHA256},
}
MAINTAINED_SOURCE_INPUTS = (
    (_WHEEL, 23461, _WHEEL_SHA256),
    (_PROVENANCE, 1010, _PROVENANCE_SHA256),
    (
        "vendor/rfc8785/upstream-typing.patch",
        294,
        "81ea57a384abcaf2894c79417ab978442b7c93a1f250357c05e59ec1002d62b8",
    ),
    (
        "tools/vendor_rfc8785.py",
        6692,
        "9c0cb9b6ecb839557a8d86d9ade25e67d766224698a6538cebc2245ca870d2fe",
    ),
    (
        "LICENSES/Apache-2.0.txt",
        10174,
        "0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594",
    ),
)


def check_maintained_dependency(root: Path, artifact: Json, lock: str, report: Report) -> None:
    """Bind one exact local dependency artifact to its complete already reviewed derivation.

    Parameters
    ----------
    root : Path
        Bounded caller source root containing the original maintained wheel and inputs.
    artifact : Json
        Entire declared source artifact; received paths never select files or executables.
    lock : str
        Complete development lock retaining the exact local wheel SHA-256.
    report : Report
        Retains producer/source/hash mismatches alongside every other dependency gate.

    Raises
    ------
    Fault
        A fixed required local input cannot be acquired under the original bounded reader.

    Notes
    -----
    This reads fixed files only. It performs no build, install, download, algorithm
    comparison, signature operation or fresh audit, and grants no qualification.
    """
    if artifact != MAINTAINED_ARTIFACT:
        report.add("dependency_alignment.wrong-producer", "dependency-provenance.json")
        return
    for name, length, digest in MAINTAINED_SOURCE_INPUTS:
        source = read_bytes(root, name, length + 1)
        if len(source) != length or hashlib.sha256(source).hexdigest() != digest:
            report.add("dependency_alignment.wrong-producer", name)
    if "--hash=sha256:" + _WHEEL_SHA256 not in lock:
        report.add("dependency_alignment.missing-hash", "requirements-dev.txt")
