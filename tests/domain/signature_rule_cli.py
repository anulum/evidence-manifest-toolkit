# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual command entry with same-process native sources

"""Invoke the real module command while retaining the genuinely captured caller process."""

import runpy
import sys
from pathlib import Path

import pytest
from tests.domain.test_cli_evidence_sources import _transport


def invoke_rule_cli(
    directory: Path,
    *,
    population: dict[str, Path],
    schema_id: str,
    content_raw: bytes,
    registry: object,
    limits: object,
    policy: object,
    trust: object,
    envelopes: tuple[bytes, ...] = (),
) -> tuple[int, Path]:
    """Run the actual module command against complete real files and no substituted sampler.

    Parameters
    ----------
    directory : Path
        Owned command input/output parent.
    population : dict
        Entire real flat resolver input population, retaining genuinely absent targets.
    schema_id : str
        Independently selected whole subject schema.
    content_raw : bytes
        Whole actual original content.
    registry, limits, policy, trust : object
        Entire original command configuration values in their actual wire representation.
    envelopes : tuple of bytes
        Actual explicit ordinary receipts, each supplied through the original signature flag.

    Returns
    -------
    tuple
        Real command exit code and fresh requested report path. Keeping the same process
        is necessary for the selected native PID/start source; a child would be a different
        caller. No private product helper, provider, clock or source observation is replaced.
    """
    arguments, report = prepare_rule_cli(
        directory,
        population=population,
        schema_id=schema_id,
        content_raw=content_raw,
        registry=registry,
        limits=limits,
        policy=policy,
        trust=trust,
        envelopes=envelopes,
    )
    return run_module_command(arguments), report


def prepare_rule_cli(
    directory: Path,
    *,
    population: dict[str, Path],
    schema_id: str,
    content_raw: bytes,
    registry: object,
    limits: object,
    policy: object,
    trust: object,
    envelopes: tuple[bytes, ...] = (),
) -> tuple[list[str], Path]:
    """Write the complete real command files and return the original verify argument vector.

    Parameters
    ----------
    directory : Path
        Owned command input/output parent; ``command-inputs`` below it must not exist yet.
    population : dict
        Entire real flat resolver input population, retaining genuinely absent targets.
    schema_id : str
        Independently selected whole subject schema.
    content_raw : bytes
        Whole actual original content.
    registry, limits, policy, trust : object
        Entire original command configuration values in their actual wire representation.
    envelopes : tuple of bytes
        Actual explicit ordinary receipts, each supplied through the original signature flag.

    Returns
    -------
    tuple
        The whole ``emt verify`` argument vector and the fresh report path it names.
    """
    root = directory / "command-inputs"
    root.mkdir()
    objects = root / "objects"
    objects.mkdir()
    for key, path in population.items():
        if not path.exists():
            continue
        digest, _ = key.split("|")
        destination = objects / digest.removeprefix("sha256:")
        raw = path.read_bytes()
        if destination.exists():
            assert destination.read_bytes() == raw
        else:
            destination.write_bytes(raw)
    content = root / "content.json"
    content.write_bytes(content_raw)
    report = root / "report.json"
    arguments = [
        "emt",
        "verify",
        "--content",
        str(content),
        "--schema-id",
        schema_id,
        "--objects",
        str(objects),
        "--report",
        str(report),
    ]
    for name, value in (
        ("registry", registry),
        ("limits", limits),
        ("policy", policy),
        ("trust", trust),
    ):
        target = root / (name + ".json")
        target.write_bytes(_transport(value))
        arguments.extend(("--" + name, str(target)))
    for index, raw in enumerate(envelopes):
        signature = root / ("signature-" + str(index) + ".json")
        signature.write_bytes(raw)
        arguments.extend(("--signature", str(signature)))
    return arguments, report


def run_module_command(arguments: list[str]) -> int:
    """Run the actual module command in this process with a whole original argument vector.

    Parameters
    ----------
    arguments : list of str
        Entire ``emt`` argument vector, program name first.

    Returns
    -------
    int
        Real command exit code. The same process keeps the selected native PID/start source.
    """
    original_argv = sys.argv
    try:
        sys.argv = arguments
        with pytest.raises(SystemExit) as caught:
            runpy.run_module("evidence_manifest_toolkit", run_name="__main__")
    finally:
        sys.argv = original_argv
    assert isinstance(caught.value.code, int)
    return caught.value.code
