# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — bounded fixed native method data grammars

"""Load complete fixed native method data without adding a caller format or executing sources."""

import hashlib
from collections.abc import Mapping
from importlib.resources import files
from types import MappingProxyType
from typing import Literal, cast

from referencing.jsonschema import Schema

from ._budget import ReferenceBudget
from ._errors import InputRefused
from ._reference_paths import configuration_refusal
from ._registry_types import ReferencePath
from ._schema_resources import parse_schema
from ._successor_formats import FixedFormat
from ._values import BlobRef, Digest, Reason

type NativeMethodRole = Literal["launcher", "possession", "execution", "comparison"]

_RESOURCE = BlobRef(
    "sha256:79d3c88e8738abaf97a843ecc170a4c994e6f6e17a8038bddd4057b0ef38f96a",
    "41858",
    "application/schema+json",
    "raw_bytes",
)
_COMMON = (
    "implementation_ref",
    "implementation_environment_ref",
    "implementation_qualification_ref",
    "semantic_law_ref",
)
_FIELDS: Mapping[NativeMethodRole, tuple[str, ...]] = MappingProxyType(
    {
        "launcher": _COMMON
        + (
            "record_contract_ref",
            "capture_contract_ref",
            "observer_authority_policy_ref",
            "endpoint_rule_ref",
        ),
        "possession": _COMMON + ("challenge_issuer_rule_ref", "receiver_method_ref"),
        "execution": _COMMON
        + (
            "whole_request_selection_ref",
            "executor_method_ref",
            "output_seal_method_ref",
            "release_method_ref",
        ),
        "comparison": _COMMON
        + ("comparison_algorithm_ref", "whole_comparison_parameters_ref", "outcome_mapping_ref"),
    }
)


def native_method_format(
    role: NativeMethodRole, *, budget: ReferenceBudget, subject: Digest, pointer: str
) -> FixedFormat:
    """Read one fixed owning-role grammar with the entire pinned local resource.

    Parameters
    ----------
    role : {"launcher", "possession", "execution", "comparison"}
        Literal internal callsite selection; no received field selects a file or code.
    budget : ReferenceBudget
        SAME complete invocation budget, charging the whole resource only once.
    subject : str
        Actual independently selected enclosing rule identity.
    pointer : str
        Original rule field for resource acquisition and configuration failures.

    Returns
    -------
    FixedFormat
        Whole installed source, literal definition and complete original Ref selectors.
        Private data shapes add no RegistryEntry, native ID or schema metadata.

    Raises
    ------
    ConfigurationError
        The fixed installed resource is absent, changed or invalid.
    InputRefused
        Whole fixed-source bytes/count/metadata exhaust the original shared bounds.
    """
    raw = budget.cached(_RESOURCE, subject=subject, pointer=pointer)
    if raw is None:
        maximum = min(
            int(_RESOURCE.byte_length),
            budget.limits.max_blob_bytes,
            budget.limits.max_total_reference_bytes - budget.total_bytes,
        )
        if maximum < int(_RESOURCE.byte_length):
            raise InputRefused(
                Reason(
                    "limit_exceeded",
                    subject,
                    None,
                    pointer,
                    "Reference acquisition bound exceeded.",
                )
            )
        try:
            resource = files("evidence_manifest_toolkit").joinpath(
                "_schemas", "native_method_data.json"
            )
            with resource.open("rb") as handle:
                raw = handle.read(maximum + 1)
        except OSError as error:
            raise configuration_refusal(pointer) from error
    if len(raw) != int(_RESOURCE.byte_length) or (
        "sha256:" + hashlib.sha256(raw).hexdigest() != _RESOURCE.digest
    ):
        raise configuration_refusal(pointer)
    budget.charge(_RESOURCE, raw, subject=subject, pointer=pointer)
    root = parse_schema(raw, limits=budget.limits, pointer=pointer)
    definitions = cast(Mapping[str, Schema], cast(Mapping[str, object], root)["$defs"])
    definition: Schema
    if role == "launcher":
        definition = {
            "anyOf": [
                {"$ref": "#/$defs/declared_launch_binding"},
                {"$ref": "#/$defs/observer_binding"},
            ]
        }
    else:
        definition = definitions[
            {
                "possession": "possession_binding",
                "execution": "execution_binding",
                "comparison": "comparison_binding",
            }[role]
        ]
    paths = tuple(
        ReferencePath(
            "native-method-data:" + role + ":" + field,
            ({"kind": "member", "name": field},),
            "schema_optional",
            "schema_optional",
            "when_present",
        )
        for field in _FIELDS[role]
    )
    return FixedFormat(root, definition, paths, None, "native-method-data:" + role)
