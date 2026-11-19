# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the complete unsigned V2 command inputs handed to command cases

"""Hand one complete unsigned V2 verification from the whole workflow to command cases."""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest

from evidence_manifest_toolkit import BlobRef


@dataclass(frozen=True)
class UnsignedCommandInputs:
    """The whole real inputs of the unsigned positive command case and its expected report.

    Attributes
    ----------
    directory : Path
        Owned fixture directory; each command case writes below its own fresh subdirectory.
    population : dict
        Entire real flat resolver input population of the case.
    schema_id : str
        Independently selected whole subject schema.
    content_raw : bytes
        Whole actual original content.
    registry, limits : object
        Original registry and limits values in their wire representation.
    policy : dict
        The successor policy selection (``authority_policy.v2`` reference, claims, purposes).
    legacy_policy : dict
        The original v1 policy selection the fixture started from.
    trust : dict
        The complete unsigned V2 caller trust in its wire representation.
    capfd : pytest.CaptureFixture
        Actual stdout/stderr capture of the same process.
    policy_ref, content_ref : BlobRef
        The selected successor policy and the content references.
    axes : Mapping
        The composed report's expected axes for the current evaluation mode.
    reasons : list
        The composed report's expected reasons, in order.
    """

    directory: Path
    population: dict[str, Path]
    schema_id: str
    content_raw: bytes
    registry: object
    limits: object
    policy: dict[str, object]
    legacy_policy: dict[str, object]
    trust: dict[str, object]
    capfd: pytest.CaptureFixture[str]
    policy_ref: BlobRef
    content_ref: BlobRef
    axes: Mapping[str, object]
    reasons: list[dict[str, object]]
