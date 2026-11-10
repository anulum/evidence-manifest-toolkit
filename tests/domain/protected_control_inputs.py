# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole deliberately unqualified protected control inputs

"""Retain actual complete control declarations without inventing protected key or state facts."""

import base64
import hashlib
import json
from pathlib import Path
from typing import cast

import rfc8785
from tests.domain.test_cli_evidence_sources import _source
from tests.domain.test_software_sources import _stored_source
from tests.domain.test_verification_report_sources import _object, _text

from evidence_manifest_toolkit import BlobRef

type _ControlJson = None | bool | int | float | str | list[_ControlJson] | dict[str, _ControlJson]


def protected_control_inputs(
    base: BlobRef,
    directory: Path,
    *,
    root: BlobRef | None = None,
    conditions: BlobRef | None = None,
    operations: tuple[str, ...] = (),
) -> tuple[BlobRef, BlobRef, tuple[bytes, ...], dict[str, Path]]:
    """Materialise whole r6 sources and actual public-test-key receipts before context freeze.

    Parameters
    ----------
    base : BlobRef
        Actual entire earlier ordinary B, never a future witness or final policy.
    directory : Path
        Owned flat source store for this actual invocation input.
    root, conditions : BlobRef or None
        Entire declared source selections; defaults name the actual earlier B bytes.
        Neither source is asserted to be accepted root, custody or limitation evidence.
    operations : tuple of str
        Whole independently selected operation order. Published RFC8032 test key signs
        the real V2 messages for nonempty inputs; it is unprotected and unenrolled.

    Returns
    -------
    tuple
        Whole rule/selection references, original receipt bytes and complete file population.
        All procedure/controller/bootstrap/state qualifications remain explicitly absent.
    """
    population: dict[str, Path] = {}
    root = base if root is None else root
    conditions = base if conditions is None else conditions
    ref = dict(base.to_mapping())

    def store(value: dict[str, object], schema: str | None = None) -> BlobRef:
        """Keep complete raw private or canonical native bodies with their actual identities."""
        raw = (
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if schema is None
            else rfc8785.dumps(cast(dict[str, _ControlJson], value))
        )
        digest = hashlib.sha256(raw).hexdigest()
        path = directory / digest
        path.write_bytes(raw)
        result = BlobRef(
            "sha256:" + digest,
            str(len(raw)),
            "application/json",
            "raw_bytes" if schema is None else "jcs_content",
            schema,
        )
        population[result.digest + "|" + result.digest_basis] = path
        return result

    rule = store(
        {
            "format_version": "emt-protected-control-rule-source-r6",
            "independent_root_selection_ref": dict(root.to_mapping()),
            "whole_legacy_base_policy_ref": ref,
            "scope_source_ref": ref,
            "controller_identity_rule_ref": ref,
            "protected_custody_rule_ref": ref,
            "bootstrap_rule_ref": ref,
            "certificate_rule_ref": ref,
            "snapshot_rule_ref": ref,
            "revocation_rule_ref": ref,
            "rotation_rule_ref": ref,
            "whole_conditions_and_limitations_ref": dict(conditions.to_mapping()),
            "implementation_method_ref": ref,
            "implementation_environment_ref": ref,
        }
    )
    entries: list[dict[str, object]] = []
    envelopes: list[bytes] = []
    for operation in operations:
        from Crypto.Signature import eddsa

        # Published RFC8032 section7.1 vector, never an operational/protected key.
        key = eddsa.import_private_key(
            bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        )
        public_key = key.public_key().export_key(format="raw")
        assert isinstance(public_key, bytes)
        signer = "ed25519:" + hashlib.sha256(public_key).hexdigest()
        scope: dict[str, object] = {
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
        }
        target: dict[str, object]
        if operation == "authority_grant":
            target = {
                "schema_id": "evidence_manifest_toolkit.authority_grant.v2",
                "authority_id": "unqualified-source-authority",
                "root_key_id": signer,
                "initial_issuer_key_id": signer,
                "initial_issuer_public_key_ref": ref,
                "automation_policy_ref": dict(rule.to_mapping()),
                "protected_controller_custody_ref": ref,
                "scope": scope,
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
        elif operation == "issue_certificate":
            target = {
                "schema_id": "evidence_manifest_toolkit.delegated_certificate.v2",
                "authority_id": "unqualified-source-authority",
                "parent_authorization_ref": ref,
                "issuer_key_id": signer,
                "subject_key_id": signer,
                "subject_public_key_ref": ref,
                "identity_custody_source_ref": ref,
                "scope": scope,
                "remaining_path_length": "0",
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": "2030-01-01T00:00:00Z",
                "serial": "1",
            }
        elif operation == "rotate_authority":
            target = {
                "schema_id": "evidence_manifest_toolkit.authority_rotation.v2",
                "authority_id": "unqualified-source-authority",
                "root_grant_ref": ref,
                "previous_rotation_ref": None,
                "old_key_id": signer,
                "new_key_id": signer,
                "new_public_key_ref": ref,
                "actual_generation_custody_ref": ref,
                "controller_ref": ref,
                "effective_at": "2026-10-03T12:00:00Z",
                "rotation_sequence": "1",
                "unchanged_scope_ref": ref,
            }
        else:
            assert operation in {"issue_snapshot", "revoke_descendants"}
            target = {
                "schema_id": "evidence_manifest_toolkit.authority_snapshot.v2",
                "authority_id": "unqualified-source-authority",
                "root_grant_ref": ref,
                "current_issuer_key_id": signer,
                "current_rotation_ref": None,
                "sequence": "1",
                "issued_at": "2020-01-01T00:00:00Z",
                "expires_at": "2030-01-01T00:00:00Z",
                "certificate_refs": [],
                "identity_rule_refs": [],
                "registry_ref": ref,
                "revocations": [],
                "previous_snapshot_ref": None,
            }
        target_ref = store(target, str(target["schema_id"]))
        statement: dict[str, object] = {
            "schema_id": "evidence_manifest_toolkit.signed_statement.v2",
            "profile_id": "evidence_manifest_toolkit.jcs_sha256_ed25519.authority_v2",
            "canonical_profile": "rfc8785-jcs-v1",
            "digest_algorithm": "sha256",
            "content_schema_id": target_ref.schema_id,
            "content_digest": target_ref.digest,
            "content_byte_length": target_ref.byte_length,
            "signer_key_id": signer,
            "purpose": operation,
            "signature_context": "authority_control",
            "authorizing_state_ref": ref,
            "authorization_ref": ref,
            "scope_ref": ref,
            "snapshot_ref": None,
            "claim_ids": [],
            "claimed_signed_at": "2026-10-03T12:00:00Z",
        }
        statement_ref = store(statement, "evidence_manifest_toolkit.signed_statement.v2")
        message = b"GOTM-EMT-AUTHORITY-V2\x00" + rfc8785.dumps(
            cast(dict[str, _ControlJson], statement)
        )
        signature = eddsa.new(key, "rfc8032").sign(message)
        eddsa.new(key.public_key(), "rfc8032").verify(message, signature)
        raw = rfc8785.dumps(
            cast(
                dict[str, _ControlJson],
                {
                    "statement": statement,
                    "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
                },
            )
        )
        envelopes.append(raw)
        entries.append(
            {
                "operation": operation,
                "target_ref": dict(target_ref.to_mapping()),
                "statement_ref": dict(statement_ref.to_mapping()),
                "envelope_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "authorizing_state_ref": ref,
                "authorization_ref": ref,
                "scope_ref": ref,
                "signer_key_id": signer,
            }
        )
    selection = store(
        {
            "format_version": "emt-protected-control-selection-source-r6",
            "control_rule_ref": dict(rule.to_mapping()),
            "entries": entries,
        }
    )
    return rule, selection, tuple(envelopes), population


def prepare_control_base(
    directory: Path,
) -> tuple[dict[str, object], dict[str, object], BlobRef, dict[str, Path], dict[Path, bytes]]:
    """Retain the entire original input corpus and materialise its unqualified operational B.

    Parameters
    ----------
    directory : Path
        Owned flat source store, before caller/context/Clock-source freezing.

    Returns
    -------
    tuple
        Full original public inputs, whole policy argument, complete B reference,
        actual resolver population and immutable original source-byte inventory.
        Changing the namespace supplies no independent operational qualification.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    declared = _object(inputs["policy"])
    original_ref = BlobRef.from_mapping(_object(declared["policy_ref"]))
    fixtures = Path(__file__).parent / "fixtures/evidence-command-sources"
    population = {
        key: fixtures / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    originals = {path: path.read_bytes() for path in population.values()}
    base = _object(json.loads(population[original_ref.digest + "|raw_bytes"].read_bytes()))
    for field in ("actual_accepted_configuration", "source_chain_ref"):
        base.pop(field)
    base.update(
        namespace="OWNER_LOCAL_VERIFICATION_POLICY_V1",
        time_rule="Explicit caller UTC under original half-open snapshot/certificate windows; independently qualified evaluation-time source required.",
        root_and_key_rule="Existing independently owner-approved local bootstrap/current configuration; no artifact approval or root provisioning.",
        required_evaluation_time_qualification={
            "requirement": "independent previously accepted clock/time-selection method and full source/capture/controller identity",
            "clock_qualification_ref": None,
            "actual_qualification": "unavailable",
            "caller_utc_string_is_qualification": False,
            "source_contract": "Existing selected common8 UTC/time qualification boundary; this explicit prospective policy extension needs affected selection and adds no TrustContext field.",
        },
    )
    base_ref = _stored_source(base, directory)
    population[base_ref.digest + "|raw_bytes"] = directory / base_ref.digest[7:]
    return inputs, declared, base_ref, population, originals
