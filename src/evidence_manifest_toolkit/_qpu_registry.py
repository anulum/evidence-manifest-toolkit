# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete fixed QPU registry source correspondence

"""Enforce the complete selected QPU cohort without URI aliases or registry mutation."""

import hashlib
from importlib.resources import files
from typing import cast

import rfc8785

from ._budget import ReferenceBudget
from ._errors import InputRefused
from ._json import JsonValue, parse_document
from ._reference_paths import configuration_refusal
from ._registry_types import SchemaRegistry
from ._registry_wire import entry_value
from ._values import BlobRef, Reason

_BINDINGS_LENGTH = 46680
_BINDINGS_DIGEST = "5b6d57696a185eafe9735f5ab0c3e4dec07b10530d2e11d978d499843735624d"
_SUCCESSORS = frozenset(
    {
        "urn:gotm:design:qpu_result_pack.closure.common_trust_context.v7",
        "urn:gotm:design:qpu_result_pack.closure.evaluation_request.v8",
        "urn:gotm:design:qpu_result_pack.closure.evaluation_inputs.v8",
        "urn:gotm:design:qpu_result_pack.closure.evaluation_raw_observation.v8",
        "urn:gotm:design:qpu_result_pack.closure.evaluation_role_manifest.v8",
    }
)


def _bindings(budget: ReferenceBudget) -> list[dict[str, JsonValue]]:
    """Read the complete pinned source correspondence under the actual operation bounds.

    Parameters
    ----------
    budget : ReferenceBudget
        Sole existing source/content/configuration budget, including this whole resource.

    Returns
    -------
    list of dict
        All77 exact independently selected registry/resource/instance identities and
        complete fourteen-field entry digests, not an inferred prefix transformation.

    Raises
    ------
    ConfigurationError
        The installed whole binding resource is missing or corrupted.
    InputRefused
        A shared byte/count/JSON bound prevents loading the complete resource.
    """
    pointer = "/registry/entries"
    reference = BlobRef(
        "sha256:" + _BINDINGS_DIGEST, str(_BINDINGS_LENGTH), "application/json", "raw_bytes"
    )
    raw = budget.cached(reference, subject=reference.digest, pointer=pointer)
    if raw is None:
        maximum = min(
            _BINDINGS_LENGTH,
            budget.limits.max_blob_bytes,
            budget.limits.max_total_reference_bytes - budget.total_bytes,
        )
        if maximum < _BINDINGS_LENGTH:
            raise InputRefused(
                Reason(
                    "limit_exceeded",
                    reference.digest,
                    None,
                    pointer,
                    "Reference acquisition bound exceeded.",
                )
            )
        try:
            with (
                files("evidence_manifest_toolkit")
                .joinpath("_qpu_registry_bindings.json")
                .open("rb") as handle
            ):
                raw = handle.read(maximum + 1)
        except OSError as error:
            raise configuration_refusal(pointer) from error
    if len(raw) != _BINDINGS_LENGTH or hashlib.sha256(raw).hexdigest() != _BINDINGS_DIGEST:
        raise configuration_refusal(pointer)
    budget.charge(reference, raw, subject=reference.digest, pointer=pointer)
    document = cast(dict[str, JsonValue], parse_document(raw, limits=budget.limits))
    return cast(list[dict[str, JsonValue]], document["entries"])


def validate_qpu_registry(registry: SchemaRegistry, *, budget: ReferenceBudget) -> None:
    """Match the complete successor cohort and every whole original source entry.

    Parameters
    ----------
    registry : SchemaRegistry
        Actual independently selected caller catalogue. Selecting a known QPU successor
        requires all77 exact entries; legacy catalogues retain their original law.
    budget : ReferenceBudget
        Existing shared operation budget for the complete pinned correspondence resource.

    Raises
    ------
    ConfigurationError
        The selected cohort, exact raw schema source, URI/body/selector/dependency/role
        or another whole entry field differs from the adopted source selection.
    InputRefused
        The same cumulative acquisition bounds prevent the whole correspondence check.

    Notes
    -----
    This checks structural source correspondence only. It authenticates no snapshot
    and supplies no native, Clock, protected, domain or scientific admission. Registry
    IDs stay exactly as selected; definition URIs never become extra registered IDs.
    """
    if not any(entry.schema_id in _SUCCESSORS for entry in registry.entries):
        return
    expected = _bindings(budget)
    selected = {entry.schema_id: (index, entry) for index, entry in enumerate(registry.entries)}
    if len(selected) != len(expected) or set(selected) != {row["schema_id"] for row in expected}:
        raise configuration_refusal("/registry/entries")
    for row in expected:
        index, entry = selected[cast(str, row["schema_id"])]
        pointer = "/registry/entries/" + str(index)
        if dict(entry.schema_ref.to_mapping()) != row["schema_ref"]:
            raise configuration_refusal(pointer + "/schema_bytes")
        digest = "sha256:" + hashlib.sha256(rfc8785.dumps(entry_value(entry))).hexdigest()
        if digest != row["entry_jcs_digest"]:
            raise configuration_refusal(pointer)
