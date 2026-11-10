# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole deliberately unqualified protected state sources

"""Keep full native source declarations separate from actual root and machine admission."""

import hashlib
from pathlib import Path
from typing import cast

import rfc8785

from evidence_manifest_toolkit import BlobRef

type _SourceJson = None | bool | int | float | str | list[_SourceJson] | dict[str, _SourceJson]


def protected_state_inputs(
    base: BlobRef,
    rule: BlobRef,
    root: BlobRef,
    directory: Path,
    *,
    sequence: str = "1",
) -> tuple[BlobRef, BlobRef, dict[str, Path]]:
    """Materialise complete immutable declarations before the actual first sample/context freeze.

    Parameters
    ----------
    base : BlobRef
        Whole actual earlier source used for explicitly unqualified procedure declarations.
    rule : BlobRef
        Entire independently selected r6 control rule.
    root : BlobRef
        Actual earlier root-selection source argument, without an enrolment assertion.
    directory : Path
        Owned flat actual source store.
    sequence : str
        Exact original counter token, including counters larger than machine integers.

    Returns
    -------
    tuple
        Whole native grant/current references and actual immutable source population.
        Published RFC8032 public key is unprotected, unenrolled and never eligible here.
    """
    population: dict[str, Path] = {}

    def store(raw: bytes, schema: str | None, media: str = "application/json") -> BlobRef:
        """Keep exact source bytes and their actual complete reference metadata."""
        digest = hashlib.sha256(raw).hexdigest()
        path = directory / digest
        path.write_bytes(raw)
        reference = BlobRef(
            "sha256:" + digest,
            str(len(raw)),
            media,
            "raw_bytes" if schema is None else "jcs_content",
            schema,
        )
        population[reference.digest + "|" + reference.digest_basis] = path
        return reference

    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    key_reference = store(public, None, "application/octet-stream")
    identifier = "ed25519:" + hashlib.sha256(public).hexdigest()
    ref = dict(base.to_mapping())
    grant_schema = "evidence_manifest_toolkit.authority_grant.v2"
    grant_value: dict[str, object] = {
        "schema_id": grant_schema,
        "authority_id": "unqualified-source-authority",
        "root_key_id": identifier,
        "initial_issuer_key_id": identifier,
        "initial_issuer_public_key_ref": dict(key_reference.to_mapping()),
        "automation_policy_ref": dict(rule.to_mapping()),
        "protected_controller_custody_ref": ref,
        "scope": {
            "group_ids": ["unqualified-source-group"],
            "principal_ids": ["unqualified-source-principal"],
            "roles": ["source-correspondence-only"],
            "tool_segments": ["source-correspondence-only"],
            "permitted_operations": [
                "evidence",
                "issue_certificate",
                "issue_snapshot",
                "rotate_authority",
                "revoke_descendants",
            ],
        },
        "remaining_path_length": "1",
        "lifetime": {
            "kind": "finite",
            "not_before": "2020-01-01T00:00:00Z",
            "not_after": "2030-01-01T00:00:00Z",
        },
        "rotation_rule_ref": ref,
        "root_selection_source_ref": dict(root.to_mapping()),
        "serial": "1",
        "owner_revocation_only_path_ref": ref,
    }
    grant = store(rfc8785.dumps(cast(dict[str, _SourceJson], grant_value)), grant_schema)
    schema = "evidence_manifest_toolkit.authority_snapshot.v2"
    snapshot: dict[str, object] = {
        "schema_id": schema,
        "authority_id": "unqualified-source-authority",
        "root_grant_ref": dict(grant.to_mapping()),
        "current_issuer_key_id": identifier,
        "current_rotation_ref": None,
        "sequence": sequence,
        "issued_at": "2020-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "certificate_refs": [],
        "identity_rule_refs": [],
        "registry_ref": ref,
        "revocations": [],
        "previous_snapshot_ref": None,
    }
    current = store(rfc8785.dumps(cast(dict[str, _SourceJson], snapshot)), schema)
    return grant, current, population
