# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — real missing-provider CLI source and recovery

"""Exercise original verifier absence through an isolated interpreter and genuine public CLI."""

import base64
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
from importlib.metadata import distribution
from pathlib import Path

import pytest
import rfc8785

type _Wire = None | bool | int | float | str | list[_Wire] | dict[str, _Wire]

_SOURCE = Path(__file__).resolve().parents[2]
_OBJECTS = Path(__file__).parent / "fixtures/evidence-command-sources/objects"
_CLI_SOURCE = "4d6365dc18f8a55f7b28e25105750d7229f83baf7a8be48c0ed840f8fd7cb0c1"
_METHOD_SOURCE = "6b428b552cbb27a4c17d2bf9429a3996409c91f2f57a4d1c006ce7cb62d81473"
_INITIALIZATION_SOURCE = "102bae120b36fcc5d80c8e5c5a0e59b3e198e6baabdcd5a379b6ed8e2b7a3655"


def _object(value: object) -> dict[str, object]:
    """Retain every original string-keyed source field.

    Parameters
    ----------
    value : object
        Whole original decoded source node.

    Returns
    -------
    dict
        Complete source mapping, without selecting an alternate oracle.
    """
    assert isinstance(value, dict) and all(isinstance(key, str) for key in value)
    return dict(value)


def _text(value: object) -> str:
    """Require an original source string.

    Parameters
    ----------
    value : object
        Original source token.

    Returns
    -------
    str
        Unmodified string; other values are not coerced.
    """
    assert isinstance(value, str)
    return value


def _original(digest: str) -> bytes:
    """Read the entire unchanged original hash-named source object.

    Parameters
    ----------
    digest : str
        Exact original SHA-256, not an artifact locator or execution path.

    Returns
    -------
    bytes
        Complete byte-identity-checked source.
    """
    raw = (_OBJECTS / digest).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    return raw


def _wire(value: object) -> _Wire:
    """Retain every original JSON value for the maintained canonicalization oracle.

    Parameters
    ----------
    value : object
        Entire decoded report, including every nested observation and reason.

    Returns
    -------
    object
        Identical typed JSON population, without coercion or omitted fields.
    """
    if isinstance(value, dict):
        return {key: _wire(member) for key, member in _object(value).items()}
    if isinstance(value, list):
        return [_wire(member) for member in value]
    assert value is None or isinstance(value, (bool, int, float, str))
    return value


def _console_script(original: bytes, root: Path) -> bytes:
    """Return the console script an installer writes into ``root`` for an original one.

    Parameters
    ----------
    original : bytes
        Console script installed into this interpreter's own environment.
    root : Path
        Isolated environment that receives the same script.

    Returns
    -------
    bytes
        The original with its environment prefix moved to ``root``. A ``#!`` line that
        exceeds 127 bytes with its newline, or whose interpreter path holds a space, cannot
        start that interpreter directly, so the installer starts it through ``/bin/sh``
        instead, as uv writes it.
    """
    script = original.replace(str(Path(sys.prefix)).encode(), str(root).encode())
    first, separator, rest = script.partition(b"\n")
    interpreter = first.removeprefix(b"#!")
    if len(first) + 1 <= 127 and b" " not in interpreter:
        return script
    launcher = b"#!/bin/sh\n'''exec' '" + interpreter + b"' \"$0\" \"$@\"\n' '''"
    return launcher + separator + rest


def _without_provider(root: Path, environment: dict[str, str]) -> Path:
    """Install six exact original locked libraries through offline uv hardlinks.

    The repository's own pinned uv installs them from the verified environment inputs
    through the environment's uv cache, as ``make environment`` does; nothing comes
    from the host's uv, its home cache or an index.

    Parameters
    ----------
    root : Path
        Owned Samsung environment directory, separate from every source and global prefix.
    environment : dict
        Original process environment with source-overlay variables removed.

    Returns
    -------
    Path
        Actual isolated Python whose original libraries load normally and Crypto is absent.

    Notes
    -----
    Full original runtime lock hashes are retained, excluding only pycryptodome.
    Source/data/licence bytes and hardlinks are checked. Native installer RECORD
    hashes and the console's actual prefix are checked separately. No import
    interception, network access or product package installation occurs.
    """
    pins = dict(
        re.findall(r"^([\w-]+)==([^\s]+)", (_SOURCE / "requirements-runtime.txt").read_text(), re.M)
    )
    assert set(pins) == {
        "attrs",
        "jsonschema",
        "jsonschema-specifications",
        "referencing",
        "rpds-py",
        "rfc8785",
        "pycryptodome",
    }
    del pins["pycryptodome"]
    uv = str(_SOURCE / ".tool-cache/bootstrap-uv/uv")
    artifacts = Path(
        os.environ.get(
            "EMT_TEST_ENVIRONMENT_ARTIFACTS", str(_SOURCE / ".tool-cache/environment-inputs")
        )
    )
    assert artifacts.is_dir()
    uv_environment = {
        **environment,
        "UV_CONCURRENT_INSTALLS": "1",
        "UV_CONCURRENT_DOWNLOADS": "1",
        "UV_CONCURRENT_BUILDS": "1",
        "RAYON_NUM_THREADS": "1",
        "TOKIO_WORKER_THREADS": "1",
    }
    cache = Path(os.environ.get("EMT_TEST_UV_CACHE", str(_SOURCE / ".tool-cache/uv-cache")))
    assert cache.is_dir()
    requirements = root.parent / (root.name + "-runtime-lock.txt")
    selected: list[str] = []
    current = ""
    for line in (_SOURCE / "requirements-runtime.txt").read_text().splitlines(keepends=True):
        found = re.match(r"^([\w-]+)==", line)
        if found is not None:
            current = found[1]
        if current != "pycryptodome":
            selected.append(
                line.replace(
                    "--find-links vendor/rfc8785", "--find-links " + str(_SOURCE / "vendor/rfc8785")
                )
            )
    requirements.write_text("".join(selected))
    assert dict(re.findall(r"^([\w-]+)==([^\s]+)", requirements.read_text(), re.M)) == pins
    subprocess.run(
        [
            uv,
            "--no-config",
            "venv",
            "--offline",
            "--no-project",
            "--no-python-downloads",
            "--link-mode",
            "hardlink",
            "--cache-dir",
            str(cache),
            "--python",
            sys.executable,
            str(root),
        ],
        env=uv_environment,
        capture_output=True,
        timeout=30,
        check=True,
    )
    python = root / "bin/python"
    synced = subprocess.run(
        [
            uv,
            "--no-config",
            "pip",
            "sync",
            "--offline",
            "--no-index",
            "--find-links",
            str(artifacts),
            "--no-build",
            "--require-hashes",
            "--link-mode",
            "hardlink",
            "--cache-dir",
            str(cache),
            "--python",
            str(python),
            str(requirements),
        ],
        env=uv_environment,
        capture_output=True,
        timeout=30,
        check=True,
    )
    assert b"falling back" not in synced.stderr.lower()
    observed = subprocess.run(
        [str(python), "-B", "-I", "-c", "import sysconfig;print(sysconfig.get_path('purelib'))"],
        env=environment,
        capture_output=True,
        timeout=30,
        check=True,
    )
    assert observed.stderr == b""
    site = Path(observed.stdout.decode().strip())
    assert root in site.parents
    linked = 0
    for name, version in pins.items():
        package = distribution(name)
        assert package.version == version and package.files
        for entry in package.files:
            destination = (site / str(entry)).resolve()
            assert root in destination.parents
            located = package.locate_file(entry)
            assert isinstance(located, Path)
            raw = located.read_bytes()
            actual = destination.read_bytes()
            if entry.name == "RECORD":
                for name, digest, length in csv.reader(actual.decode().splitlines()):
                    recorded = (site / name).resolve()
                    assert root in recorded.parents
                    if digest:
                        assert digest == "sha256=" + base64.urlsafe_b64encode(
                            hashlib.sha256(recorded.read_bytes()).digest()
                        ).decode().rstrip("=")
                        assert str(recorded.stat().st_size) == length
                    else:
                        assert recorded == destination and length == ""
            elif str(entry).startswith("../"):
                assert actual == _console_script(raw, root)
            else:
                assert actual == raw
                if entry.name not in {"INSTALLER", "REQUESTED", "uv_cache.json"}:
                    assert destination.stat().st_nlink > 1
                    linked += 1
    assert linked > 0
    inspected = subprocess.run(
        [
            str(python),
            "-B",
            "-I",
            "-c",
            "import importlib.util,json,sys;from importlib.metadata import distributions;"
            "print(json.dumps({'prefix':sys.prefix,'base_prefix':sys.base_prefix,"
            "'crypto_available':importlib.util.find_spec('Crypto') is not None,"
            "'libraries':{d.metadata['Name'].lower().replace('_','-'):d.version for d in distributions()}}))",
        ],
        env=environment,
        capture_output=True,
        timeout=30,
        check=True,
    )
    assert inspected.stderr == b""
    inventory = _object(json.loads(inspected.stdout))
    assert inventory["prefix"] == str(root) and inventory["base_prefix"] != str(root)
    assert inventory["crypto_available"] is False and inventory["libraries"] == pins
    return python


def _provider_library_copy(python: Path, environment: dict[str, str]) -> dict[Path, bytes]:
    """Copy the entire original maintained provider into the owned isolated prefix.

    Parameters
    ----------
    python : Path
        Existing isolated interpreter with the six original non-provider libraries.
    environment : dict
        Actual process environment without source-overlay variables.

    Returns
    -------
    dict
        Every copied original file and its exact bytes, including metadata and licences.
    """
    observed = subprocess.run(
        [str(python), "-B", "-I", "-c", "import sysconfig;print(sysconfig.get_path('purelib'))"],
        env=environment,
        capture_output=True,
        timeout=30,
        check=True,
    )
    assert observed.stderr == b""
    site = Path(observed.stdout.decode().strip())
    root = python.parent.parent
    assert root in site.parents
    package = distribution("pycryptodome")
    assert package.version == "3.24.0" and package.files
    copied: dict[Path, bytes] = {}
    for entry in package.files:
        destination = (site / str(entry)).resolve()
        assert root in destination.parents
        source = package.locate_file(entry)
        assert isinstance(source, Path)
        raw = source.read_bytes()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        copied[destination] = raw
    assert all(path.read_bytes() == raw for path, raw in copied.items())
    return copied


@pytest.mark.parametrize(
    "case_id",
    ("verify-missing-local-provider", "verify-local-provider-initialization-failure"),
)
def test_original_missing_provider_cli_whole_error_storage_and_report_recovery(
    case_id: str,
    tmp_path: Path,
) -> None:
    """Observe exact original configuration failure, absent output and whole successful recovery.

    Parameters
    ----------
    case_id : str
        Original provider-absence or initialization-failure source and whole error oracle.
    tmp_path : Path
        Owned original caller inputs, object store, isolated libraries and output destinations.

    Notes
    -----
    Actual source-module CLI runs use ordinary interpreter resolution from the
    canonical source directory. A complete original provider copy with its real
    Ed25519 library unreadable supplies initialization failure. Restoring original
    permissions supplies recovery in the same isolated interpreter. Provider
    absence recovers in the healthy canonical environment. These runs do not
    exercise the other two provider conditions, qualified Signer, installed
    console, independent admission or a primary crypto audit.
    """
    cli = _object(json.loads(_original(_CLI_SOURCE)))
    cases = cli["cases"]
    assert isinstance(cases, list)
    selected = next(_object(row) for row in cases if _object(row)["case_id"] == case_id)
    source_digest = (
        _METHOD_SOURCE if case_id == "verify-missing-local-provider" else _INITIALIZATION_SOURCE
    )
    case = _object(json.loads(_original(source_digest)))
    method_pin = _object(selected["complete_method_case"])
    assert len(_original(source_digest)) == method_pin["byte_length"]
    assert method_pin["sha256"] == source_digest
    inputs = tmp_path / "caller"
    inputs.mkdir()
    bindings = _object(selected["exact_input_file_bindings"])
    stores = selected["complete_offline_object_store_bindings"]
    assert isinstance(stores, list) and len(bindings) == 6 and len(stores) == 37
    sources = list(bindings.items()) + [
        (_text(_object(row)["future_relative_path"]), _object(row)["exact_existing_source_bytes"])
        for row in stores
    ]
    before: dict[Path, bytes] = {}
    for name, value in sources:
        record = _object(value)
        raw = _original(_text(record["sha256"]))
        assert len(raw) == record["byte_length"]
        path = inputs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        before[path] = raw
    (inputs / "out").mkdir()
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "MYPYPATH"):
        environment.pop(key, None)
    environment.update(
        PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(tmp_path), TMP=str(tmp_path), TEMP=str(tmp_path)
    )
    absent = _without_provider(tmp_path / "isolated-no-provider", environment)
    copied: dict[Path, bytes] = {}
    backend: Path | None = None
    original_mode = 0
    probe = [
        str(absent),
        "-B",
        "-I",
        "-c",
        "from Crypto.Signature.eddsa import import_public_key;"
        "import_public_key(bytes.fromhex("
        "'d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'));"
        "print('ready')",
    ]
    if case_id == "verify-local-provider-initialization-failure":
        assert os.geteuid() != 0
        copied = _provider_library_copy(absent, environment)
        backend = next(path for path in copied if path.name == "_ed25519.abi3.so")
        original_mode = backend.stat().st_mode & 0o777
        healthy = subprocess.run(
            probe, env=environment, capture_output=True, timeout=30, check=True
        )
        assert (healthy.stdout, healthy.stderr) == (b"ready\n", b"")
        backend.chmod(0)
        with pytest.raises(PermissionError):
            backend.read_bytes()
        failed_probe = subprocess.run(
            probe, env=environment, capture_output=True, timeout=30, check=False
        )
        assert failed_probe.returncode == 1
        assert b"OSError" in failed_probe.stderr and b"_ed25519" in failed_probe.stderr
    argv = selected["full_argv"]
    assert isinstance(argv, list) and argv[0] == "emt"
    arguments = [_text(value) for value in argv[1:]]
    for index, token in enumerate(arguments):
        if token in {
            "--content",
            "--registry",
            "--objects",
            "--limits",
            "--policy",
            "--trust",
            "--report",
            "--signature",
        }:
            arguments[index + 1] = str(inputs / arguments[index + 1])
    try:
        failed = subprocess.run(
            [str(absent), "-B", "-m", "evidence_manifest_toolkit", *arguments],
            cwd=_SOURCE / "src",
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
    finally:
        if backend is not None:
            backend.chmod(original_mode)
    token = _text(selected["exact_expected_stdout_bytes_base64url"])
    expected = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    assert hashlib.sha256(expected).hexdigest() == case["exact_CLI_stdout_sha256"]
    assert (failed.returncode, failed.stdout, failed.stderr) == (4, expected, b"")
    assert json.loads(failed.stdout) == case["expected_entire_ErrorResult"]
    assert not list((inputs / "out").iterdir())
    assert all(path.read_bytes() == raw for path, raw in before.items())
    report_index = arguments.index("--report") + 1
    recovered_path = inputs / "out/recovered-report.json"
    arguments[report_index] = str(recovered_path)
    recovered = subprocess.run(
        [
            str(absent) if backend is not None else sys.executable,
            "-B",
            "-m",
            "evidence_manifest_toolkit",
            *arguments,
        ],
        cwd=_SOURCE / "src",
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert (recovered.returncode, recovered.stderr) == (0, b"")
    expected_report = case["expected_entire_recovery_VerificationReport"]
    assert json.loads(recovered.stdout) == expected_report
    assert recovered.stdout == rfc8785.dumps(_wire(expected_report))
    assert recovered_path.read_bytes() == recovered.stdout
    assert not (inputs / "out/report.json").exists()
    assert all(path.read_bytes() == raw for path, raw in before.items())
    if backend is not None:
        assert backend.stat().st_mode & 0o777 == original_mode
        assert all(path.read_bytes() == raw for path, raw in copied.items())
