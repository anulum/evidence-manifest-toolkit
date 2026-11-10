# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — entire declared reproduction history source builder

"""Materialise real whole causal source graphs without claiming an independent execution."""

import json
from copy import deepcopy
from pathlib import Path

from tests.domain.test_verification_report_sources import _array, _object, _text

from evidence_manifest_toolkit import BlobRef, Limits, canonicalize_json, reference_bytes


class HistorySources:
    """Keep whole fixture sources for actual public parent reconstruction controls.

    Parameters
    ----------
    directory : Path
        Actual owned source store before first S0.
    limits : Limits
        Original unchanged public bounds.
    without_metadata : bool
        Omit optional schema assertions only on explicitly built native references;
        document schema IDs and complete source bytes are never omitted.
    """

    def __init__(self, directory: Path, limits: Limits, *, without_metadata: bool) -> None:
        """Retain the exact owned source store, limits and metadata condition."""
        self.directory = directory
        self.limits = limits
        self.without_metadata = without_metadata

    def read(self, reference: BlobRef) -> dict[str, object]:
        """Read the entire actual stored source for the original full reference.

        Parameters
        ----------
        reference : BlobRef
            Complete original stored object reference.

        Returns
        -------
        dict
            Whole parsed source without field projection.
        """
        return _object(json.loads((self.directory / reference.digest[7:]).read_bytes()))

    def child(self, value: dict[str, object], field: str) -> BlobRef:
        """Decode the original complete selected child reference.

        Parameters
        ----------
        value : dict
            Whole parsed parent source.
        field : str
            Actual reference member selected by the fixture's native role.

        Returns
        -------
        BlobRef
            Unchanged complete child argument.
        """
        return BlobRef.from_mapping(_object(value[field]))

    def store(self, value: dict[str, object]) -> BlobRef:
        """Store every actual canonical byte under an original raw identity argument.

        Parameters
        ----------
        value : dict
            Whole source, including its native schema ID when metadata is requested.

        Returns
        -------
        BlobRef
            Actual raw-byte reference to the complete stored canonical source.
        """
        raw = canonicalize_json(json.dumps(value, ensure_ascii=False).encode(), limits=self.limits)
        reference = reference_bytes(
            raw,
            media_type="application/json",
            digest_basis="raw_bytes",
            schema_id=None if self.without_metadata else _text(value["schema_id"]),
            limits=self.limits,
        )
        (self.directory / reference.digest[7:]).write_bytes(raw)
        return reference

    def parent(
        self,
        earlier: dict[str, object],
        index: int,
        record: BlobRef,
        runner: str,
        *,
        change_origin: bool = False,
    ) -> dict[str, object]:
        """Build one whole declared transition with all nonselected fields preserved.

        Parameters
        ----------
        earlier : dict
            Entire earlier source; it is never mutated by this constructor.
        index : int
            Actual selected claim position.
        record : BlobRef
            Exact full later package reference, not a body or projected record.
        runner : str
            Declared actual binding principal, explicitly unqualified identity.
        change_origin : bool
            Deliberate illegal original-origin change for an adverse public case.

        Returns
        -------
        dict
            Whole later manifest. A matching structure supplies no run/class admission.
        """
        result = deepcopy(earlier)
        claims = [_object(item) for item in _array(result["claims"])]
        selected = claims[index]
        if change_origin:
            selected["origin"] = "executed"
        selected.update(
            evidence_maturity="validated",
            verdict="agree",
            validation={
                "status": "independently_reproduced",
                "record_ref": dict(record.to_mapping()),
                "runner_id": runner,
                "independent_of_producer": True,
            },
        )
        result["claims"] = claims
        return result
