# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — actual public software table/current/history source boundaries

"""Exercise complete software source initialization before Clock through public verify."""

import base64
import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest
from tests.domain.method_rule_inputs import method_rule_inputs
from tests.domain.test_cli_evidence_sources import _source, _transport
from tests.domain.test_policy_selection_sources import _successor_policy
from tests.domain.test_successor_trust import _callers, _sources
from tests.domain.test_verification_report_sources import (
    _array,
    _bytes,
    _FileResolver,
    _object,
    _registry,
    _text,
)

from evidence_manifest_toolkit import (
    BlobRef,
    InputRefused,
    Limits,
    ReferenceUnavailable,
    VerificationPolicy,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


def _stored_source(value: object, directory: Path, *, schema_id: str | None = None) -> BlobRef:
    """Store the complete independently prepared carrier under its actual raw identity.

    Parameters
    ----------
    value : object
        Entire declared source, without claiming native authorization or Clock acceptance.
    directory : Path
        Owned flat content-addressed input store.
    schema_id : str or None
        Explicit registered assertion only for the enclosing authority policy.

    Returns
    -------
    BlobRef
        Full actual raw reference, retaining absent optional schema metadata.
    """
    raw = _transport(value)
    digest = hashlib.sha256(raw).hexdigest()
    (directory / digest).write_bytes(raw)
    return BlobRef("sha256:" + digest, str(len(raw)), "application/json", "raw_bytes", schema_id)


def _software_table(
    reference: BlobRef,
    directory: Path,
    *,
    sequence: str,
    previous: BlobRef | None = None,
    changes: dict[str, object] | None = None,
) -> BlobRef:
    """Prepare a complete unprotected table with a real published RFC8032 public key.

    Parameters
    ----------
    reference : BlobRef
        Whole explicit scope and unqualified provenance declaration for these source tests.
    directory : Path
        Owned actual source store. No production private helper or fake provider is used.
    sequence : str
        Original exact stream counter, including values beyond interoperable JSON integers.
    previous : BlobRef or None
        Whole earlier table or explicit initial absence.
    changes : dict or None
        Whole deliberate source changes; they supply no signed/physical/authority acceptance.

    Returns
    -------
    BlobRef
        Exact full source-r4 table reference, with every original field retained.
    """
    provenance = dict(reference.to_mapping())
    value: dict[str, object] = {
        "format_version": "emt-software-authorization-source-r4",
        "installation_id": "explicit-software-source-test-stream",
        "sequence": sequence,
        "whole_scope_and_signature_rule_ref": provenance,
        "local_controller_identity_ref": provenance,
        "authorized_keys": [
            {
                "key_id": "ed25519:" + hashlib.sha256(_KEY).hexdigest(),
                "raw_public_key_base64url": base64.urlsafe_b64encode(_KEY)
                .rstrip(b"=")
                .decode("ascii"),
                "group": "SC-NEUROMORPHIC-COMPUTING-SYSTEMS",
                "principal": "published-test-key-only",
                "role": "author_input",
                "segment": "evidence_manifest_toolkit",
                "purposes": ["evidence"],
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "identity_binding_ref": provenance,
                "possession_and_software_custody_ref": provenance,
            }
        ],
        "revocations": [],
        "previous_authorization_ref": None if previous is None else dict(previous.to_mapping()),
        "issued_at": "2026-01-01T00:00:00Z",
        "limitations_ref": provenance,
    }
    if changes is not None:
        value.update(changes)
    return _stored_source(value, directory)


@pytest.mark.parametrize(
    "condition",
    (
        "current",
        "historical",
        "large_counter",
        "missing_current",
        "missing_previous",
        "missing_archive",
        "malformed",
        "key_id",
        "key_encoding",
        "duplicate",
        "distinct_scope",
        "window",
        "floor",
        "history_sequence",
        "installation",
        "history_time",
        "scope",
        "archive_branch",
        "archive_stream",
        "archive_future",
        "archive_time",
        "historical_floor",
        "depth",
    ),
)
def test_public_software_source_history_precedes_clock_without_protected_state(
    condition: str,
    tmp_path: Path,
) -> None:
    """Check actual source failures and original references before unrelated Clock dispatch.

    Parameters
    ----------
    condition : str
        Real valid current/historical/large streams or one whole original source conflict.
    tmp_path : Path
        Owned full source files; original common fixtures remain byte-identical.

    Notes
    -----
    Positive source initialization reaches the deliberately unknown Clock entry method.
    It proves no possession of a key, no qualification of curve or signature, and no accepted
    Clock or authority.
    No protected root is supplied and no cryptographic provider is needed for source reads.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    declared = _object(inputs["policy"])
    original_ref = BlobRef.from_mapping(_object(declared["policy_ref"]))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    originals = {path: path.read_bytes() for path in population.values()}
    ordinary = _object(json.loads(population[original_ref.digest + "|raw_bytes"].read_bytes()))
    for name in ("actual_accepted_configuration", "source_chain_ref"):
        ordinary.pop(name)
    ordinary.update(
        namespace="OWNER_LOCAL_VERIFICATION_POLICY_V1",
        time_rule="Explicit caller UTC under original half-open snapshot/certificate windows; "
        "independently qualified evaluation-time source required.",
        root_and_key_rule="Existing independently owner-approved local bootstrap/current "
        "configuration; no artifact approval or root provisioning.",
        required_evaluation_time_qualification={
            "requirement": "independent previously accepted clock/time-selection method and full "
            "source/capture/controller identity",
            "clock_qualification_ref": None,
            "actual_qualification": "unavailable",
            "caller_utc_string_is_qualification": False,
            "source_contract": "Existing selected common8 UTC/time qualification boundary; this "
            "explicit prospective policy extension needs affected selection and adds no "
            "TrustContext field.",
        },
    )
    ordinary_ref = _stored_source(ordinary, tmp_path)
    counter = "9007199254740993" if condition == "large_counter" else "2"
    parent = _software_table(ordinary_ref, tmp_path, sequence=str(int(counter) - 1))
    if condition in {"history_sequence", "installation", "history_time"}:
        parent = _software_table(
            ordinary_ref,
            tmp_path,
            sequence=counter if condition == "history_sequence" else str(int(counter) - 1),
            changes={"installation_id": "different-stream"}
            if condition == "installation"
            else {"issued_at": "2026-02-01T00:00:00Z"}
            if condition == "history_time"
            else None,
        )
    current = _software_table(ordinary_ref, tmp_path, sequence=counter, previous=parent)
    depth_subject = current
    if condition == "depth":
        initial = _software_table(ordinary_ref, tmp_path, sequence="0")
        depth_subject = _software_table(ordinary_ref, tmp_path, sequence="1", previous=initial)
        parent = _software_table(ordinary_ref, tmp_path, sequence="2", previous=depth_subject)
        counter = "3"
        current = _software_table(ordinary_ref, tmp_path, sequence=counter, previous=parent)
        limits = replace(limits, max_graph_depth=3)
    value = _object(json.loads((tmp_path / current.digest[7:]).read_bytes()))
    if condition in {"key_id", "key_encoding", "duplicate", "distinct_scope", "window"}:
        keys = _array(value["authorized_keys"])
        entry = _object(keys[0])
        if condition == "key_id":
            entry["key_id"] = "ed25519:" + "0" * 64
        if condition == "key_encoding":
            entry["raw_public_key_base64url"] = _text(entry["raw_public_key_base64url"])[:-1] + "B"
        if condition == "window":
            entry["valid_until"] = entry["valid_from"]
        keys[0] = entry
        if condition == "duplicate":
            keys.append(dict(entry))
        if condition == "distinct_scope":
            keys.append({**entry, "role": "second_explicit_role"})
        value["authorized_keys"] = keys
        current = _stored_source(value, tmp_path)
    if condition == "scope":
        current = _software_table(
            ordinary_ref,
            tmp_path,
            sequence=counter,
            previous=parent,
            changes={"whole_scope_and_signature_rule_ref": dict(original_ref.to_mapping())},
        )
    if condition == "malformed":
        raw = b"{"
        digest = hashlib.sha256(raw).hexdigest()
        (tmp_path / digest).write_bytes(raw)
        current = BlobRef("sha256:" + digest, "1", "application/json", "raw_bytes")
    historical = condition in {
        "historical",
        "missing_archive",
        "archive_branch",
        "archive_stream",
        "archive_future",
        "archive_time",
        "historical_floor",
    }
    archive = parent
    if condition in {
        "missing_archive",
        "archive_branch",
        "archive_stream",
        "archive_future",
        "archive_time",
    }:
        archive = _software_table(
            ordinary_ref,
            tmp_path,
            sequence="3" if condition == "archive_future" else "1",
            changes={
                "issued_at": "2026-02-01T00:00:00Z"
                if condition == "archive_time"
                else "2025-12-31T23:59:59Z",
                "installation_id": "different-stream"
                if condition == "archive_stream"
                else "explicit-software-source-test-stream",
            },
        )
    binding, references, carrier_originals = _sources()
    caller = _callers(binding, references, "historical" if historical else "current")[1]
    caller = replace(
        caller,
        software_authorization_ref=current,
        accepted_authorization_sequence_floor=str(int(counter) + 1)
        if condition in {"floor", "historical_floor"}
        else counter,
        archived_software_authorization_ref=archive if historical else None,
    )
    policy_value = _successor_policy(ordinary_ref)
    policy_value.update(
        profile_class=caller.profile_class, authority_rule_ref=dict(ordinary_ref.to_mapping())
    )
    rule_fields, _ = method_rule_inputs(ordinary_ref, tmp_path, profile_class=caller.profile_class)
    policy_value.update(rule_fields)
    policy_ref = _stored_source(
        policy_value, tmp_path, schema_id="evidence_manifest_toolkit.authority_policy.v2"
    )
    population.update(
        {
            "sha256:" + path.name + "|raw_bytes": path
            for path in tmp_path.iterdir()
            if path.is_file()
        }
    )
    missing = {
        "missing_current": current,
        "missing_previous": parent,
        "missing_archive": archive,
    }.get(condition)
    if missing is not None:
        (tmp_path / missing.digest[7:]).unlink()
    resolver = _FileResolver(population)
    with pytest.raises(ReferenceUnavailable if missing is not None else InputRefused) as caught:
        verify(
            _bytes(inputs["content_json"]),
            schema_id=_text(inputs["schema_id"]),
            envelopes=(),
            registry=registry,
            resolver=resolver,
            limits=limits,
            policy=VerificationPolicy(
                policy_ref,
                tuple(_text(x) for x in _array(declared["required_claim_ids"])),
                ("evidence",),
            ),
            trust=caller,
        )
    if missing is not None:
        assert isinstance(caught.value, ReferenceUnavailable) and caught.value.reference == missing
        assert resolver.calls[-1][0] == missing
    else:
        code, subject, pointer, detail = (
            "policy_unavailable",
            policy_ref.digest,
            "/required_evaluation_time_qualification/clock_qualification_ref",
            "The required evaluation-time qualification is unavailable.",
        )
        if condition in {"key_id", "key_encoding", "duplicate", "window"}:
            code, subject, detail = (
                "invalid_schema",
                current.digest,
                "Software authorization source refused.",
            )
            pointer = (
                "/authorized_keys/"
                + ("1" if condition == "duplicate" else "0")
                + "/"
                + (
                    "raw_public_key_base64url"
                    if condition == "key_encoding"
                    else "valid_until"
                    if condition == "window"
                    else "key_id"
                )
            )
        if condition == "malformed":
            code, subject, pointer, detail = (
                "invalid_json",
                current.digest,
                "",
                "Input is not valid strict JSON.",
            )
        if condition in {
            "floor",
            "scope",
            "archive_stream",
            "archive_future",
            "archive_time",
            "historical_floor",
            "history_sequence",
            "installation",
            "history_time",
        }:
            detail = "Software authorization source refused."
            pointer = {
                "floor": "/trust/accepted_authorization_sequence_floor",
                "scope": "/authority_rule_ref",
                "archive_stream": "/trust/archived_software_authorization_ref",
                "archive_future": "/trust/archived_software_authorization_ref",
                "archive_time": "/trust/archived_software_authorization_ref",
                "historical_floor": "/trust/accepted_authorization_sequence_floor",
                "history_sequence": "/sequence",
                "installation": "/installation_id",
                "history_time": "/issued_at",
            }[condition]
            if condition in {"history_sequence", "installation", "history_time"}:
                subject = parent.digest
        if condition == "depth":
            code, subject, pointer, detail = (
                "limit_exceeded",
                depth_subject.digest,
                "/previous_authorization_ref",
                "Software authorization source refused.",
            )
        assert asdict(caught.value.reason) == dict(
            code=code, subject_digest=subject, claim_id=None, pointer=pointer, detail=detail
        )
    assert resolver.calls[0][0] == policy_ref and resolver.calls[1][0] == ordinary_ref
    assert resolver.calls[2][0] == current
    assert all(path.read_bytes() == raw for path, raw in (originals | carrier_originals).items())
