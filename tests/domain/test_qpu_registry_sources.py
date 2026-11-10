# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete fixed QPU registry source correspondence

"""Exercise the entire selected QPU registry through real unsigned construction."""

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Literal

import pytest
from tests.domain.test_verification_report_sources import (
    _FileResolver,
    _mapping,
    _object,
    _registry,
)

from evidence_manifest_toolkit import (
    ConfigurationError,
    InputRefused,
    Limits,
    SchemaRegistry,
    reference_bytes,
    seal,
)

_FIXTURES = Path(__file__).parent / "fixtures"
_REGISTRY_SHA = "757fe0dcdf59a8ef2859218eee9cc3f2e5f425d484e47f9637c4118b66b7c6d8"
_CERTIFICATE_SHA = "10edf1af6835947532bcaef3b8c99c7958ef5106ce46b14ab595643ecd68e338"


def _construction_sources() -> tuple[SchemaRegistry, Limits, bytes]:
    """Retain all original source values for independent public construction attempts.

    Returns
    -------
    tuple
        Complete unqualified77-entry declaration, all six operation bounds and the
        original certificate content. These sources supply no snapshot admission.
    """
    raw = (_FIXTURES / "qpu-registry-source.json").read_bytes()
    assert len(raw) == 2173128 and hashlib.sha256(raw).hexdigest() == _REGISTRY_SHA
    limits = Limits(4194304, 4194304, 67108864, 2048, 32, 96)
    reference = reference_bytes(
        raw, media_type="application/json", digest_basis="raw_bytes", schema_id=None, limits=limits
    )
    registry = _registry(
        {
            "snapshot_ref": dict(reference.to_mapping()),
            "entries": _object(json.loads(raw))["entries"],
        }
    )
    content = (_FIXTURES / "evidence-command-sources/objects" / _CERTIFICATE_SHA).read_bytes()
    assert len(registry.entries) == 77 and hashlib.sha256(content).hexdigest() == _CERTIFICATE_SHA
    return registry, limits, content


@pytest.mark.parametrize("condition", ("cohort", "owner", "domain", "quota"))
def test_complete_qpu_cohort_domain_and_shared_quota_refusal_then_recovery(
    condition: Literal["cohort", "owner", "domain", "quota"],
) -> None:
    """Refuse incomplete source selection, changed ownership/domain requirements and exhausted bytes.

    Parameters
    ----------
    condition : {"cohort", "owner", "domain", "quota"}
        Actual caller catalogue or acquisition limit that conflicts with the complete
        selected source. Every original schema byte and fixture stays unchanged.
    """
    registry, limits, content = _construction_sources()
    original = _mapping(registry)
    schema_id = "evidence_manifest_toolkit.group_certificate.v1"
    baseline = seal(
        content, schema_id=schema_id, registry=registry, resolver=_FileResolver({}), limits=limits
    )
    supplied = registry
    selected_limits = limits
    if condition == "cohort":
        supplied = replace(registry, entries=registry.entries[:-1])
    elif condition in ("owner", "domain"):
        entry = registry.entries[8]
        assert entry.schema_id == "qpu_result_pack.bundle.v2"
        assert entry.domain_support == "required_unqualified"
        supplied = replace(
            registry,
            entries=registry.entries[:8]
            + (
                replace(entry, owner="EXPERIMENT-LEDGER")
                if condition == "owner"
                else replace(entry, domain_support="not_required"),
            )
            + registry.entries[9:],
        )
    else:
        unique = {entry.schema_ref.digest: entry.schema_bytes for entry in registry.entries}
        selected_limits = replace(limits, max_total_reference_bytes=sum(map(len, unique.values())))
    exception = InputRefused if condition == "quota" else ConfigurationError
    resolver = _FileResolver({})
    with pytest.raises(exception) as caught:
        seal(
            content,
            schema_id=schema_id,
            registry=supplied,
            resolver=resolver,
            limits=selected_limits,
        )
    assert asdict(caught.value.reason) == {
        "code": "limit_exceeded" if condition == "quota" else "configuration_error",
        "subject_digest": "sha256:5b6d57696a185eafe9735f5ab0c3e4dec07b10530d2e11d978d499843735624d"
        if condition == "quota"
        else None,
        "claim_id": None,
        "pointer": "/registry/entries/8"
        if condition in ("owner", "domain")
        else "/registry/entries",
        "detail": "Reference acquisition bound exceeded."
        if condition == "quota"
        else "Invalid local configuration.",
    }
    recovered = seal(
        content, schema_id=schema_id, registry=registry, resolver=resolver, limits=limits
    )
    assert baseline == recovered and baseline.canonical_content == content
    assert baseline.envelope_json is None and not resolver.calls
    assert _mapping(registry) == original
    assert _construction_sources() == (registry, limits, content)


def test_complete_qpu_registry_preserves_source_pairs_and_refuses_schema_substitution() -> None:
    """Keep all77 actual source entries and recover after a different existing schema is refused.

    Notes
    -----
    The original complete source declaration supplies this construction's unqualified
    registry identity. It is not asserted to be an authenticated C5 snapshot. The actual
    original public certificate bytes supply construction content only; no signature,
    root, Clock, domain result, native registry admission or current trust is asserted.
    """
    path = _FIXTURES / "qpu-registry-source.json"
    raw = path.read_bytes()
    assert len(raw) == 2173128 and hashlib.sha256(raw).hexdigest() == _REGISTRY_SHA
    source = _object(json.loads(raw))
    limits = Limits(4194304, 4194304, 67108864, 2048, 32, 96)
    identity = reference_bytes(
        raw, media_type="application/json", digest_basis="raw_bytes", schema_id=None, limits=limits
    )
    value = {"snapshot_ref": dict(identity.to_mapping()), "entries": source["entries"]}
    registry = _registry(value)
    assert len(registry.entries) == 77 and _mapping(registry) == value
    assert sum(not entry.schema_id.startswith("urn:") for entry in registry.entries) == 23
    for entry in registry.entries:
        assert entry.schema_ref.digest == "sha256:" + hashlib.sha256(entry.schema_bytes).hexdigest()
        assert entry.schema_ref.byte_length == str(len(entry.schema_bytes))
    certificate_path = _FIXTURES / "evidence-command-sources/objects" / _CERTIFICATE_SHA
    certificate = certificate_path.read_bytes()
    assert hashlib.sha256(certificate).hexdigest() == _CERTIFICATE_SHA
    schema_id = "evidence_manifest_toolkit.group_certificate.v1"
    resolver = _FileResolver({})
    baseline = seal(
        certificate, schema_id=schema_id, registry=registry, resolver=resolver, limits=limits
    )
    assert baseline.canonical_content == certificate and baseline.envelope_json is None
    assert asdict(baseline.content_ref) == {
        "digest": "sha256:" + _CERTIFICATE_SHA,
        "byte_length": str(len(certificate)),
        "media_type": "application/json",
        "digest_basis": "jcs_content",
        "schema_id": schema_id,
    }
    selected = registry.entries[0]
    assert selected.schema_id == schema_id
    packaged_path = (
        Path(__file__).resolve().parents[2]
        / "src/evidence_manifest_toolkit/_schemas/group_certificate.json"
    )
    packaged = packaged_path.read_bytes()
    assert len(packaged) == len(selected.schema_bytes) == 1913 and packaged != selected.schema_bytes
    assert json.loads(selected.schema_bytes)["$id"] == "urn:gotm:design:" + schema_id
    assert json.loads(packaged)["$id"] == "urn:gotm:schema:" + schema_id
    altered = replace(
        selected,
        schema_bytes=packaged,
        schema_ref=reference_bytes(
            packaged,
            media_type="application/schema+json",
            digest_basis="raw_bytes",
            schema_id=None,
            limits=limits,
        ),
    )
    supplied = replace(registry, entries=(altered,) + registry.entries[1:])
    with pytest.raises(ConfigurationError) as caught:
        seal(certificate, schema_id=schema_id, registry=supplied, resolver=resolver, limits=limits)
    assert asdict(caught.value.reason) == {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": "/registry/entries/0/schema_bytes",
        "detail": "Invalid local configuration.",
    }
    recovered = seal(
        certificate, schema_id=schema_id, registry=registry, resolver=resolver, limits=limits
    )
    assert recovered == baseline and not resolver.calls
    assert path.read_bytes() == raw and certificate_path.read_bytes() == certificate
    assert packaged_path.read_bytes() == packaged and _mapping(registry) == value
