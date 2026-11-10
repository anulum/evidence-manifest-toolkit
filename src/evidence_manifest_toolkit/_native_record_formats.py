# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — fixed native run record definitions and reference selectors

"""Select whole installed run-record grammars without adding public format identifiers."""

from collections.abc import Mapping
from typing import Literal, cast

from referencing.jsonschema import Schema

from ._budget import ReferenceBudget
from ._native_method_formats import native_method_format
from ._registry_types import ReferencePath
from ._successor_formats import FixedFormat
from ._values import Digest

type NativeRunRecord = Literal[
    "execution_request",
    "execution_observation",
    "release_observation",
    "comparison_request",
    "comparison_observation",
    "comparison_raw_evidence",
    "access_observation",
]

type NativePossessionRecord = Literal[
    "possession_result",
    "possession_message",
    "challenge",
    "challenge_issuer_rule",
    "issuer_issuance_observation",
    "receiver_commit_payload",
    "receiver_transaction",
    "receiver_completion_payload",
    "challenge_state",
    "receiver_head_observation",
    "receiver_head_value",
    "receiver_storage_binding",
]


def native_record_format(
    kind: NativeRunRecord | NativePossessionRecord,
    *,
    budget: ReferenceBudget,
    subject: Digest,
    pointer: str,
) -> FixedFormat:
    """Bind a literal native record to all Ref positions in its pinned installed grammar.

    Parameters
    ----------
    kind : NativeRunRecord or NativePossessionRecord
        Internal owning callsite, never a value selected from received data.
    budget : ReferenceBudget
        SAME invocation quota for the entire existing native-method resource.
    subject : str
        Actual selecting source identity.
    pointer : str
        Original field selecting this whole record.

    Returns
    -------
    FixedFormat
        Complete closed definition and every direct, array and nested-event Ref edge.
        No caller registry entry, extra private evidence carrier or executable is added.

    Raises
    ------
    ConfigurationError
        The installed whole native-method grammar is missing or changed.
    InputRefused
        Its original shared acquisition bounds are exhausted.
    """
    resource = native_method_format("execution", budget=budget, subject=subject, pointer=pointer)
    root = cast(Mapping[str, object], resource.source_schema)
    definitions = cast(Mapping[str, Schema], root["$defs"])
    definition = definitions[kind]
    properties = cast(Mapping[str, Schema], cast(Mapping[str, object], definition)["properties"])
    paths: list[ReferencePath] = []

    def visit(fields: Mapping[str, Schema], prefix: tuple[dict[str, str], ...]) -> None:
        """Walk only the hash-pinned closed grammar, never received field names."""
        for name, field_definition in fields.items():
            rule = cast(Mapping[str, object], field_definition)
            position = (*prefix, {"kind": "member", "name": name})
            if rule == {"$ref": "#/$defs/ref"} or rule.get("anyOf") == [
                {"$ref": "#/$defs/ref"},
                {"type": "null"},
            ]:
                paths.append(
                    ReferencePath(
                        "native-run-record:" + kind + ":" + str(len(paths)),
                        position,
                        "schema_optional",
                        "schema_optional",
                        "when_present",
                    )
                )
            elif rule.get("type") == "array":
                item = rule.get("items")
                each = (*position, {"kind": "each"})
                if item == {"$ref": "#/$defs/ref"}:
                    paths.append(
                        ReferencePath(
                            "native-run-record:" + kind + ":" + str(len(paths)),
                            each,
                            "schema_optional",
                            "schema_optional",
                            "when_present",
                        )
                    )
                else:
                    event = cast(Mapping[str, object], item)
                    visit(cast(Mapping[str, Schema], event["properties"]), each)

    visit(properties, ())
    return FixedFormat(
        resource.source_schema, definition, tuple(paths), None, "native-run-record:" + kind
    )
