# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit original data material identity

"""Check byte-preserved licensed artifacts and original opaque fixture identities."""

import hashlib
import re
from pathlib import Path

from .inputs import read_bytes
from .limits import MAX_FILE
from .reports import Report

_PINNED = {
    "vendor/rfc8785/rfc8785-0.1.4+emt.1-py3-none-any.whl": (
        23461,
        "e04761706fcbbb5f0afd5fa74a7e6ea7484ce97f073adb5372ab8ee93230c48e",
    ),
    "vendor/rfc8785/upstream-typing.patch": (
        294,
        "81ea57a384abcaf2894c79417ab978442b7c93a1f250357c05e59ec1002d62b8",
    ),
    "vendor/rfc8785/rfc8785-0.1.4+emt.1-py3-none-any.whl.license": (
        372,
        "c099bcdba2fe52b8d31599d710473b1f2fa25eb1c9a909dee83bc807a37a6de0",
    ),
    "vendor/rfc8785/upstream-typing.patch.license": (
        379,
        "41937a3e4bb478bd69bf28fa010b75bfbbef53628a6357f54631045ad2fb8332",
    ),
}
_OBJECTS = "tests/domain/fixtures/evidence-command-sources/objects/"
_FIXTURES = "tests/domain/fixtures/evidence-command-sources/"
_ORIGINAL_NOTICE = (
    b"SPDX-FileCopyrightText: 2020-2026 Miroslav \xc5\xa0otek\n"
    b"SPDX-License-Identifier"
    b": AGPL-3.0-or-later\n"
)
_TYPING_MARKER = "src/evidence_manifest_toolkit/py.typed"
_ORIGINAL_VECTORS = {
    "tests/domain/fixtures/qpu-registry-source.json": (
        2173128,
        "757fe0dcdf59a8ef2859218eee9cc3f2e5f425d484e47f9637c4118b66b7c6d8",
    ),
    "tests/domain/fixtures/blobref-mapping-source-vectors.json": (
        49063,
        "322fe583658374a7f700bce2d0ba27bfc2b2f9d9592bb1a9239494a631246d8d",
    ),
    "tests/domain/fixtures/cli-signer-empty-installation-source.json": (
        783092,
        "a1bffc4b083651fbc90e1f5833ddc6effe19d42bb65fe1f0583ab2e839d5f46b",
    ),
    "tests/domain/fixtures/inspection-common-source-vectors.json": (
        430272,
        "34b9db63528e775a4a520c3ed5104cd75dfccc29054b807aff528f0c509338ae",
    ),
    "tests/domain/fixtures/json-reference-source-vectors.json": (
        1242843,
        "e2eaa831015a5a37ff34f520b0a19d02176c70f841426dc40a0b3c4b12bffbef",
    ),
}


def check_source_material(root: Path, name: str, report: Report) -> bool:
    """Check one explicitly recognized material without decoding it as source code.

    Parameters
    ----------
    root : Path
        Bounded caller root; all file reads retain original no-follow and resource checks.
    name : str
        Actual owned lexical filename, not a received executable or alternative URI.
    report : Report
        Retains byte-identity, empty-marker or missing fixture-attribution refusals.

    Returns
    -------
    bool
        True only for a recognized material that has been checked, including failures.
        Other files remain subject to the ordinary source and native license checks.

    Raises
    ------
    Fault
        A required material or notice cannot be read under the original source bounds.
    """
    expected = _PINNED.get(name)
    if expected is not None:
        length, digest = expected
        raw = read_bytes(root, name, length + 1)
        if len(raw) != length or hashlib.sha256(raw).hexdigest() != digest:
            report.add("source_provenance.third-party", name)
        return True
    original_vector = _ORIGINAL_VECTORS.get(name)
    if original_vector is not None:
        length, digest = original_vector
        raw = read_bytes(root, name, length + 1)
        if len(raw) != length or hashlib.sha256(raw).hexdigest() != digest:
            report.add("source_identity_mismatch", name)
        read_bytes(root, name + ".license")
        return True
    if name.endswith(".license") and (
        name.startswith(_FIXTURES) or name.removesuffix(".license") in _ORIGINAL_VECTORS
    ):
        if name == "tests/domain/fixtures/json-reference-source-vectors.json.license":
            return read_bytes(root, name) == (
                b"SPDX-FileCopyrightText: 2026 Miroslav \xc5\xa0otek\n"
                b"SPDX-License-Identifier"
                b": AGPL-3.0-or-later\n"
            )
        return read_bytes(root, name) == _ORIGINAL_NOTICE
    if name == _TYPING_MARKER:
        if read_bytes(root, name, 1) != b"":
            report.add("source_provenance.wrong-notice", name)
        read_bytes(root, name + ".license")
        return True
    digest = name.removeprefix(_OBJECTS)
    if name.startswith(_OBJECTS) and re.fullmatch(r"[0-9a-f]{64}", digest):
        raw = read_bytes(root, name, MAX_FILE)
        if hashlib.sha256(raw).hexdigest() != digest:
            report.add("source_identity_mismatch", name)
        read_bytes(root, name + ".license")
        return True
    return False
