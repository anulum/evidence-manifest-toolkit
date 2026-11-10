# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete installed QPU source resource integrity

"""Exercise public construction against byte-identical packages with actual resource faults."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tests.domain.test_qpu_registry_sources import _construction_sources


def test_complete_qpu_construction_refuses_missing_or_changed_installed_binding(
    tmp_path: Path,
) -> None:
    """Keep every production Python byte while testing the whole installed source resource.

    Parameters
    ----------
    tmp_path : Path
        Owned complete package copies and native public-caller script. These are resource
        fault tests; no current wheel installation or native trust qualification is claimed.
    """
    root = Path(__file__).resolve().parents[2]
    package = root / "src/evidence_manifest_toolkit"
    original = (package / "_qpu_registry_bindings.json").read_bytes()
    _, _, content = _construction_sources()
    script = tmp_path / "construct_qpu_content.py"
    script.write_text(
        "\n".join(Path(__file__).read_text().splitlines()[:7])
        + '\n\n"""Construct complete source-selected content through the public API."""\n'
        "import json,sys\nfrom dataclasses import asdict\nfrom pathlib import Path\n"
        "import evidence_manifest_toolkit as e\n"
        "from tests.domain.test_qpu_registry_sources import _construction_sources\n"
        "from tests.domain.test_verification_report_sources import _FileResolver\n"
        "assert Path(e.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())\n"
        "registry,limits,content=_construction_sources()\n"
        "try:\n"
        "    result=e.seal(content,schema_id='evidence_manifest_toolkit.group_certificate.v1',"
        "registry=registry,resolver=_FileResolver({}),limits=limits)\n"
        "except e.ConfigurationError as error:\n"
        "    print(json.dumps(asdict(error.reason)))\n"
        "    raise SystemExit(4) from None\n"
        "print(json.dumps({'canonical_content':result.canonical_content.decode('utf-8'),"
        "'content_ref':asdict(result.content_ref),'envelope_json':result.envelope_json}))\n"
    )
    for state in ("complete", "missing", "changed"):
        parent = tmp_path / ("successor-package-qpu-" + state)
        clone = parent / "evidence_manifest_toolkit"
        shutil.copytree(
            package,
            clone,
            ignore=shutil.ignore_patterns(
                "__pycache__", *(["_qpu_registry_bindings.json"] if state == "missing" else [])
            ),
        )
        if state == "changed":
            (clone / "_qpu_registry_bindings.json").write_bytes(original + b"\n")
        for path in package.rglob("*.py"):
            assert (
                hashlib.sha256((clone / path.relative_to(package)).read_bytes()).digest()
                == hashlib.sha256(path.read_bytes()).digest()
            )
        environment = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join((str(parent), str(root))),
            "PYTHONDONTWRITEBYTECODE": "1",
            "COVERAGE_FILE": os.environ.get("COVERAGE_FILE", str(tmp_path / "qpu.coverage")),
        }
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "coverage",
                "run",
                "--branch",
                "--parallel-mode",
                "--rcfile",
                str(root / "pyproject.toml"),
                "--source=evidence_manifest_toolkit._qpu_registry",
                str(script),
                str(parent),
            ],
            cwd=parent,
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert result.stderr == b""
        value = json.loads(result.stdout)
        if state == "complete":
            assert result.returncode == 0 and value == {
                "canonical_content": content.decode("utf-8"),
                "content_ref": {
                    "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                    "byte_length": str(len(content)),
                    "media_type": "application/json",
                    "digest_basis": "jcs_content",
                    "schema_id": "evidence_manifest_toolkit.group_certificate.v1",
                },
                "envelope_json": None,
            }
        else:
            assert result.returncode == 4 and value == {
                "code": "configuration_error",
                "subject_digest": None,
                "claim_id": None,
                "pointer": "/registry/entries",
                "detail": "Invalid local configuration.",
            }
    assert (package / "_qpu_registry_bindings.json").read_bytes() == original
