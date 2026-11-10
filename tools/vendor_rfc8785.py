# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — reproducible maintained JCS dependency wheel

"""Build the local annotation-corrected dependency from one exact upstream wheel."""

import argparse
import base64
import csv
import hashlib
import io
import sys
import zipfile
from collections.abc import Sequence
from pathlib import Path

UPSTREAM_SHA256 = "520d690b448ecf0703691c76e1a34a24ddcd4fc5bc41d589cb7c58ec651bcd48"
ORIGINAL_IMPLEMENTATION_SHA256 = "c25bc3a046528482d53bee3487b837f31dd9c05f33e8f13288c7aab320932cec"
PATCHED_IMPLEMENTATION_SHA256 = "b5a8ffef37b23f2ace6eb0a770c46ba1335f69d4ff7823799e7bc89206cead8f"
LOCAL_VERSION = "0.1.4+emt.1"
WHEEL_NAME = "rfc8785-" + LOCAL_VERSION + "-py3-none-any.whl"


def _record(members: dict[str, bytes], record_name: str) -> bytes:
    """Compute the wheel's complete installed-file digest and size table.

    Parameters
    ----------
    members : dict
        Entire exact member contents excluding RECORD itself.
    record_name : str
        Actual renamed local distribution metadata member.

    Returns
    -------
    bytes
        Deterministic UTF-8 CSV with every SHA-256/length and RECORD's empty self fields.
    """
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, content in sorted(members.items()):
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
        )
        writer.writerow((name, "sha256=" + digest, str(len(content))))
    writer.writerow((record_name, "", ""))
    return stream.getvalue().encode("utf-8")


def build_wheel(upstream: Path, destination: Path) -> str:
    """Apply the selected one-annotation correction and accurately version the local wheel.

    Parameters
    ----------
    upstream : Path
        Exact official rfc8785 0.1.4 wheel, checked by its entire published SHA-256.
    destination : Path
        Fresh exclusive output using the complete local-version wheel filename.

    Returns
    -------
    str
        SHA-256 of the newly built complete wheel, distinct from the official upstream hash.

    Raises
    ------
    ValueError
        Upstream identity, member population, exact source or destination filename differs.
    OSError
        Source/output access fails or the exclusive destination already exists.
    BadZipFile
        The selected source is not a complete readable wheel archive.
    """
    original = upstream.read_bytes()
    if hashlib.sha256(original).hexdigest() != UPSTREAM_SHA256 or destination.name != WHEEL_NAME:
        raise ValueError("Exact source wheel and local output filename are required.")
    old_metadata = "rfc8785-0.1.4.dist-info/"
    new_metadata = "rfc8785-" + LOCAL_VERSION + ".dist-info/"
    expected = {
        "rfc8785/__init__.py",
        "rfc8785/_impl.py",
        "rfc8785/py.typed",
        old_metadata + "LICENSE",
        old_metadata + "METADATA",
        old_metadata + "WHEEL",
        old_metadata + "RECORD",
    }
    with zipfile.ZipFile(io.BytesIO(original)) as archive:
        if set(archive.namelist()) != expected or len(archive.namelist()) != len(expected):
            raise ValueError("Exact upstream wheel member population is required.")
        members = {
            name.replace(old_metadata, new_metadata): archive.read(name)
            for name in sorted(expected - {old_metadata + "RECORD"})
        }
    implementation = members["rfc8785/_impl.py"]
    if hashlib.sha256(implementation).hexdigest() != ORIGINAL_IMPLEMENTATION_SHA256:
        raise ValueError("Exact whole upstream implementation is required.")
    patched = implementation.replace(b"match: re.Match)", b"match: re.Match[str])")
    if hashlib.sha256(patched).hexdigest() != PATCHED_IMPLEMENTATION_SHA256:
        raise ValueError("Exact selected annotation correction is required.")
    members["rfc8785/_impl.py"] = patched
    members["rfc8785/__init__.py"] = members["rfc8785/__init__.py"].replace(
        b'__version__ = "0.1.4"', ('__version__ = "' + LOCAL_VERSION + '"').encode("ascii")
    )
    members[new_metadata + "METADATA"] = members[new_metadata + "METADATA"].replace(
        b"\nVersion: 0.1.4\n", ("\nVersion: " + LOCAL_VERSION + "\n").encode("ascii")
    )
    members[new_metadata + "NOTICE"] = (
        b"Locally maintained EVIDENCE-MANIFEST-TOOLKIT variant of Trail of Bits rfc8785 0.1.4.\n"
        b"Upstream authorship, Apache-2.0 license and canonicalization algorithms are preserved.\n"
        b"The implementation change only parameterizes re.Match as re.Match[str].\n"
        b"Package/version metadata and RECORD identify this local build; it is not an upstream release.\n"
    )
    record_name = new_metadata + "RECORD"
    members[record_name] = _record(members, record_name)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    content = output.getvalue()
    with destination.open("xb") as stream:
        stream.write(content)
    return hashlib.sha256(content).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    """Build one explicitly selected local dependency artifact without downloading or installing.

    Parameters
    ----------
    argv : Sequence of str or None
        Maintenance arguments: exact upstream wheel followed by fresh destination wheel.
        None reads this tool's process arguments, independently of the emt command grammar.

    Returns
    -------
    int
        Zero after complete exclusive wheel creation, or one with a fixed refusal sentence.
        Invocation errors use argparse's ordinary maintenance exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    try:
        digest = build_wheel(args.upstream, args.destination)
    except (OSError, ValueError, zipfile.BadZipFile):
        print("The selected dependency wheel could not be built.", file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
