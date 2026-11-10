# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — native seven-line ownership header

"""Validate fixed owner lines and the required project-specific file description."""

from typing import Literal

from .identity import HEADER, REPOSITORY


def has_native_header(text: str, *, style: Literal["comment", "bare", "invisible"]) -> bool:
    """Match the complete original ownership foundation and nonempty seventh description.

    Parameters
    ----------
    text : str
        Entire unchanged decoded source, notice or Markdown/HTML document.
    style : {"comment", "bare", "invisible"}
        Existing native hash comment, bare sidecar or invisible document header syntax.

    Returns
    -------
    bool
        All six fixed owner/license/contact lines match exactly and the seventh names
        this project with a nonempty description; invisible syntax also closes correctly.
    """
    lines = text.splitlines()
    if style == "invisible":
        if len(lines) < 9 or lines[0] != "<!--" or lines[8] != "-->":
            return False
        lines = lines[1:8]
    if len(lines) < 7:
        return False
    prefix = "# " if style == "comment" else ""
    if lines[:6] != [prefix + line for line in HEADER[:6]]:
        return False
    description = lines[6].removeprefix(prefix + REPOSITORY + " — ")
    return lines[6].startswith(prefix + REPOSITORY + " — ") and bool(description.strip())
