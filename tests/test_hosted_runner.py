# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

"""Keep the hosted automation able to complete on the hosted runner and registry."""

import re
from typing import cast

import yaml

from tests.conftest import SOURCE

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)", re.MULTILINE)
_POLL = re.compile(r"PollInterval(Min|Max)Sec=(\d+)")


def _mapping(value: object) -> dict[str, object]:
    """Return one parsed YAML mapping.

    Parameters
    ----------
    value : object
        Parsed YAML node that must be a mapping.

    Returns
    -------
    dict
        The same mapping, typed for inspection.
    """
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def test_hosted_tests_hold_one_clock_sample_and_use_every_processor() -> None:
    """Provide the clock tests' host sample before the suite, which runs on four workers.

    The whole-workflow Clock tests read the host's live systemd-timesyncd sample and
    fail without one that is not ignored. The hosted tests job installs the daemon,
    keeps its next exchange further away than the job's own bound and waits for such
    a sample before ``make test``, which runs one worker per hosted processor.
    """
    workflow = _mapping(yaml.safe_load((SOURCE / ".github/workflows/pre-commit.yml").read_bytes()))
    job = _mapping(_mapping(workflow["jobs"])["tests"])
    steps = [_mapping(step) for step in cast(list[object], job["steps"])]
    runs = [str(step.get("run", "")) for step in steps]
    clocks = [index for index, run in enumerate(runs) if "systemd-timesyncd" in run]
    assert len(clocks) == 1, "no step provides the host clock sample"
    clock, suite = clocks[0], runs.index("make test")
    assert clock < suite
    poll = dict(_POLL.findall(runs[clock]))
    assert set(poll) == {"Min", "Max"} and poll["Min"] == poll["Max"]
    assert int(poll["Min"]) > 60 * cast(int, job["timeout-minutes"])
    assert '[ "${sample[17]}" = false ]' in runs[clock]
    assert steps[suite].get("env") == {"TEST_WORKERS": "4"}


def test_every_dependabot_lane_can_resolve_its_manifest() -> None:
    """Configure no Dependabot lane over a manifest the public registry cannot resolve.

    The development lock pins the maintained RFC wheel by a local version label that
    the public registry does not serve, so a pip lane would fail every update while
    that pin stands. The GitHub Actions lane keeps every pinned action current.
    """
    config = _mapping(yaml.safe_load((SOURCE / ".github/dependabot.yml").read_bytes()))
    lanes = [_mapping(lane) for lane in cast(list[object], config["updates"])]
    ecosystems = {lane["package-ecosystem"] for lane in lanes}
    requirements = (SOURCE / "requirements-dev.txt").read_text(encoding="utf-8")
    local = sorted(name for name, version in _PIN.findall(requirements) if "+" in version)
    assert "github-actions" in ecosystems
    assert not local or "pip" not in ecosystems, local
