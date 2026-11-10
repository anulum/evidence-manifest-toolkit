# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete maintained Python quality enrollment

"""Keep every required quality hook bound to the whole maintained source population."""

from collections.abc import Mapping
from typing import Final, cast

from .inputs import Json
from .reports import Report

PYTHON_SOURCE_DIRECTORIES: Final = ("src", "tools", "tests")
_ENTRIES = (
    ("ruff-lint", ".venv/bin/python -m ruff check src tools tests"),
    ("ruff-format", ".venv/bin/python -m ruff format --check src tools tests"),
    ("strict-types", ".venv/bin/python -m mypy src tools tests"),
    ("native-documentation", ".venv/bin/python tools/check_documentation.py --root . --json"),
)
_HOOKS = [
    dict(
        id=identifier,
        name=identifier,
        language="system",
        entry=entry,
        pass_filenames=False,
        always_run=True,
    )
    for identifier, entry in _ENTRIES
]
_CONFIGURATION = {
    "default_language_version": {"python": "python3.13"},
    "repos": [{"repo": "local", "hooks": _HOOKS}],
}


def check_quality_configuration(configuration: Mapping[str, Json], report: Report) -> None:
    """Require the complete closed four-hook declaration and strict Boolean control flags.

    Parameters
    ----------
    configuration : Mapping
        Whole bounded parsed hook file; entries are inspected as data and never executed.
    report : Report
        Retains the original hook-drift refusal when a required source or command disappears.

    Notes
    -----
    Exact command and source agreement does not claim that any quality tool ran.
    Numeric zero and one do not substitute for the two native Boolean fields.
    The exact closed configuration comparison establishes all native container
    shapes before static narrowing; the explicit Boolean type checks remain.
    """
    if configuration != _CONFIGURATION:
        report.add("dependency_alignment.hook-drift", ".pre-commit-config.yaml")
        return
    repositories = cast(list[Json], configuration["repos"])
    repository = cast(dict[str, Json], repositories[0])
    hooks = cast(list[Json], repository["hooks"])
    for item in hooks:
        hook = cast(dict[str, Json], item)
        if type(hook["pass_filenames"]) is not bool or type(hook["always_run"]) is not bool:
            report.add("dependency_alignment.hook-drift", ".pre-commit-config.yaml")
            return
