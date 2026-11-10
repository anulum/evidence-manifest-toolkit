# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole typed control closure and root acquisition quotas

"""Construct unadmitted whole control sources with exact metadata and bounded closure."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from tests.domain.test_cli_evidence_sources import _source
from tests.domain.test_verification_report_sources import (
    _array,
    _FileResolver,
    _object,
    _registry,
    _text,
)

from evidence_manifest_toolkit import BlobRef, InputRefused, Limits, Reason, SealResult, seal

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_CONTROL_SCHEMA = "evidence_manifest_toolkit.trust_snapshot.v1"
_GROUP_SCHEMA = "evidence_manifest_toolkit.group_certificate.v1"


def _original_control_source() -> tuple[dict[str, object], bytes]:
    """Read the entire original caller-selected control without asserting approval.

    Returns
    -------
    tuple
        Complete original inputs and byte-identity-checked native snapshot source.
        The object is source data; no signer or controller is created or invoked.
    """
    inputs = _object(_source("verify-current-whole-fixture")["complete_library_inputs"])
    reference = BlobRef.from_mapping(_object(_object(inputs["trust"])["current_snapshot_ref"]))
    population = _object(inputs["resolver_input_population"])
    row = _object(population[reference.digest + "|" + reference.digest_basis])
    raw = (_FIXTURES / "objects" / _text(row["sha256"])).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == reference.digest[7:]
    assert str(len(raw)) == reference.byte_length
    assert _object(json.loads(raw))["schema_id"] == _CONTROL_SCHEMA
    assert json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")).encode("ascii") == raw
    return inputs, raw


@pytest.mark.parametrize("condition", ("matching", "without_metadata", "conflicting", "unknown"))
def test_whole_control_child_schema_context_and_original_recovery(condition: str) -> None:
    """Keep optional metadata separate from the independently known native child type.

    Parameters
    ----------
    condition : str
        Original metadata, its genuine omission, a different known type or an unknown type.

    Notes
    -----
    Entire original TrustSnapshot, GroupCertificate and eight-entry registry are
    retained. Unsigned construction supplies no root, current authority, Clock,
    custody or signature approval and never invokes a signer or native provider.
    """
    inputs, original = _original_control_source()
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    before = {path: path.read_bytes() for path in population.values()}
    baseline = SealResult(
        original,
        BlobRef(
            "sha256:" + hashlib.sha256(original).hexdigest(),
            str(len(original)),
            "application/json",
            "jcs_content",
            _CONTROL_SCHEMA,
        ),
        None,
    )
    assert (
        seal(
            original,
            schema_id=_CONTROL_SCHEMA,
            registry=registry,
            resolver=_FileResolver(population),
            limits=limits,
        )
        == baseline
    )
    document = _object(json.loads(original))
    groups = _array(document["group_certificate_refs"])
    assert len(groups) == 1
    group = _object(groups[0])
    assert group["schema_id"] == _GROUP_SCHEMA
    if condition == "without_metadata":
        del group["schema_id"]
    elif condition == "conflicting":
        group["schema_id"] = "evidence_manifest_toolkit.signed_statement.v1"
    elif condition == "unknown":
        group["schema_id"] = "unregistered.control.source"
    else:
        assert condition == "matching"
    groups[0] = group
    document["group_certificate_refs"] = groups
    content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    reference = BlobRef(
        "sha256:" + hashlib.sha256(content).hexdigest(),
        str(len(content)),
        "application/json",
        "jcs_content",
        _CONTROL_SCHEMA,
    )
    resolver = _FileResolver(population)
    if condition in ("conflicting", "unknown"):
        with pytest.raises(InputRefused) as caught:
            seal(
                content,
                schema_id=_CONTROL_SCHEMA,
                registry=registry,
                resolver=resolver,
                limits=limits,
            )
        assert caught.value.reason == Reason(
            "invalid_schema",
            reference.digest,
            None,
            "/group_certificate_refs/0",
            "Declared schema conflicts with its independently selected native context.",
        )
    else:
        assert seal(
            content,
            schema_id=_CONTROL_SCHEMA,
            registry=registry,
            resolver=resolver,
            limits=limits,
        ) == SealResult(content, reference, None)
    declared = BlobRef.from_mapping(group)
    assert any(actual == declared for actual, _ in resolver.calls)
    assert all(0 < cap <= limits.max_blob_bytes for _, cap in resolver.calls)
    assert (
        seal(
            original,
            schema_id=_CONTROL_SCHEMA,
            registry=registry,
            resolver=_FileResolver(population),
            limits=limits,
        )
        == baseline
    )
    assert all(path.read_bytes() == raw for path, raw in before.items())


@pytest.mark.parametrize("condition", ("reference_count", "root_bytes_before", "root_bytes_exact"))
def test_whole_control_root_quota_precedes_reference_lookup_and_recovers(condition: str) -> None:
    """Enforce whole-root charging after the actual complete static schema population.

    Parameters
    ----------
    condition : str
        No root identity slot, one byte below the entire root, or exactly that root.

    Notes
    -----
    Actual schema identities and byte counts determine each boundary. No selected
    file is read without remaining byte allowance. A fresh complete operation
    recovers the original unsigned source, without shared mutable cache or state.
    """
    inputs, content = _original_control_source()
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    before = {path: path.read_bytes() for path in population.values()}
    reference = BlobRef(
        "sha256:" + hashlib.sha256(content).hexdigest(),
        str(len(content)),
        "application/json",
        "jcs_content",
        _CONTROL_SCHEMA,
    )
    expected = SealResult(content, reference, None)
    assert (
        seal(
            content,
            schema_id=_CONTROL_SCHEMA,
            registry=registry,
            resolver=_FileResolver(population),
            limits=limits,
        )
        == expected
    )
    schemas = {
        (entry.schema_ref.digest, entry.schema_ref.digest_basis, entry.schema_ref.byte_length): (
            entry.schema_bytes
        )
        for entry in registry.entries
    }
    schema_bytes = sum(len(raw) for raw in schemas.values())
    if condition == "reference_count":
        bounded = replace(limits, max_reference_count=len(schemas))
    else:
        bounded = replace(
            limits,
            max_total_reference_bytes=schema_bytes
            + len(content)
            - (1 if condition == "root_bytes_before" else 0),
        )
    resolver = _FileResolver(population)
    with pytest.raises(InputRefused) as caught:
        seal(
            content,
            schema_id=_CONTROL_SCHEMA,
            registry=registry,
            resolver=resolver,
            limits=bounded,
        )
    assert caught.value.reason == Reason(
        "limit_exceeded",
        reference.digest,
        None,
        "/group_certificate_refs/0" if condition == "root_bytes_exact" else "",
        "Reference count bound exceeded."
        if condition == "reference_count"
        else "Reference acquisition bound exceeded.",
    )
    assert not resolver.calls
    assert (
        seal(
            content,
            schema_id=_CONTROL_SCHEMA,
            registry=registry,
            resolver=_FileResolver(population),
            limits=limits,
        )
        == expected
    )
    assert all(path.read_bytes() == raw for path, raw in before.items())
