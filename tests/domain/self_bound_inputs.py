# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — a launcher's static store and declaration for a self-bound launch

"""Prepare what an unsigned launcher holds before it starts a self-bound child.

The static inputs are the whole-workflow fixture's own: its content, registry and limits, its
base policy, its method rules and the signature rule of its ``sig_exception`` case. The
launcher's Clock declarations are the fixture's unqualified test numbers; they are
declarations for conditional arithmetic, never physical proof.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import cast

from tests.domain.method_rule_inputs import method_rule_inputs
from tests.domain.signature_rule_inputs import signature_rule_input
from tests.domain.test_cli_evidence_sources import _source
from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _bytes, _object, _registry, _text

from evidence_manifest_toolkit import BlobRef, Limits, VerificationReport, reference_bytes
from evidence_manifest_toolkit._clock_verdict import CHECK_IDS
from evidence_manifest_toolkit._self_bound_launch import SelfBoundRequest, verify_self_bound

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"


@dataclass(frozen=True, slots=True)
class SelfBoundInputs:
    """Everything a self-bound child is started with, as files in one directory.

    Attributes
    ----------
    directory : Path
        The launcher's directory.
    declaration_path, content, registry, limits, objects, request : Path
        The files and directories ``verify_self_bound`` takes; ``request`` does not exist yet.
    schema_id : str
        The content's schema identifier.
    declaration : dict
        The declaration as written.
    launcher_ref : BlobRef
        The launcher's static declaration object, used as every declared rule reference.
    """

    directory: Path
    declaration_path: Path
    content: Path
    schema_id: str
    registry: Path
    limits: Path
    objects: Path
    request: Path
    declaration: dict[str, object]
    launcher_ref: BlobRef

    def launch(self) -> tuple[VerificationReport, SelfBoundRequest]:
        """Run the self-bound launch in this process on these inputs."""
        return verify_self_bound(
            declaration=self.declaration_path,
            content=self.content,
            schema_id=self.schema_id,
            registry=self.registry,
            limits=self.limits,
            objects=self.objects,
            request=self.request,
        )


def _write(path: Path, value: object) -> Path:
    """Write one JSON file and return its path."""
    path.write_text(json.dumps(value, sort_keys=True), encoding="ascii")
    return path


def declaration_value(
    *,
    rate: Fraction,
    base_ref: BlobRef,
    launcher_ref: BlobRef,
    rule_fields: Mapping[str, object],
    signature_ref: BlobRef,
    claim_ids: list[str],
    purposes: list[str],
    declared_checks: Mapping[str, str],
    evidence: Mapping[str, list[dict[str, object]]],
    sample_bounds: Mapping[str, str],
) -> dict[str, object]:
    """Return a whole declaration of the fixture's unsigned caller.

    Parameters
    ----------
    rate : Fraction
        The declared drift rate.
    base_ref, launcher_ref, signature_ref : BlobRef
        The base policy, the launcher's static declaration object and the signature rule.
    rule_fields : Mapping
        The method rules' four policy fields.
    claim_ids, purposes : list of str
        The verification policy's scope.
    declared_checks : Mapping
        Each check's declared result.
    evidence : Mapping
        Each check's evidence items; a check absent here names the launcher object.
    sample_bounds : Mapping
        Per-sample bounds that replace the fixture's.

    Returns
    -------
    dict
        The declaration.
    """
    launcher = dict(launcher_ref.to_mapping())
    return {
        "schema_id": "evidence_manifest_toolkit.self_bound_declaration.v1",
        "required_claim_ids": claim_ids,
        "required_purposes": purposes,
        "base_policy_ref": dict(base_ref.to_mapping()),
        "policy_rules": {
            **rule_fields,
            "whole_conditions_and_limitations_ref": launcher,
            "signature_obligation_rule_ref": dict(signature_ref.to_mapping()),
            "minimum_identity_class": "declared_by_launcher_under_the_seat_account",
            "allowed_nonuse_classes": ["procedural_nonuse"],
        },
        "clock": {
            "time_source": "workstation_system_clock_ntp",
            "drift_rate": {"numerator": str(rate.numerator), "denominator": str(rate.denominator)},
            "maximum_uncertainty_ns": "5000000000",
            "model_valid_from": "2020-01-01T00:00:00Z",
            "model_valid_until": "2030-01-01T00:00:00Z",
            "sample_bounds": {
                "accuracy_radius_ns": "1000000000",
                "mapping_ns": "1000",
                "quantization_ns": "1000",
                "source_encoding_ns": "6000",
                "post_exchange_adjustment_ns": "1000",
                "use_adjustment_ns": "1000",
            }
            | dict(sample_bounds),
            "entry_bounds": {
                "acquisition_ns": "100000000",
                "mapping_ns": "1000",
                "quantization_ns": "1000",
                "adjustment_ns": "1000",
            },
            "rule_refs": {
                name: launcher
                for name in (
                    "accepted_ntp_configuration_ref",
                    "acquisition_rule_ref",
                    "monotonic_mapping_rule_ref",
                    "independence_rule_ref",
                    "daemon_field_mapping_rule_ref",
                    "ntp_resolution_and_rotation_rule_ref",
                    "automatic_reacceptance_rule_ref",
                    "sample_mapping_and_quantization_rule_ref",
                    "rate_source_ref",
                    "calibration_source_ref",
                    "adjustment_rule_ref",
                    "rule_implementation_ref",
                    "complete_authorization_obligations_ref",
                    "assumptions_and_limitations_ref",
                    "term_source_ref",
                )
            },
            "provenance_refs": [launcher],
            "checks": [
                {
                    "check_id": name,
                    "result": declared_checks.get(name, "unavailable"),
                    "evidence": list(evidence.get(name, [{"ref": launcher}])),
                }
                for name in CHECK_IDS
            ],
        },
    }


def self_bound_inputs(
    directory: Path,
    *,
    rate: Fraction,
    declared_checks: Mapping[str, str] | None = None,
    evidence: Mapping[str, list[dict[str, object]]] | None = None,
    sample_bounds: Mapping[str, str] | None = None,
) -> SelfBoundInputs:
    """Write the launcher's store, configurations and declaration into ``directory``.

    Parameters
    ----------
    directory : Path
        An empty directory owned by the test.
    rate : Fraction
        The declared drift rate.
    declared_checks : Mapping or None
        Each check's declared result; every other check is ``unavailable``.
    evidence : Mapping or None
        Each check's evidence items; every other check names the launcher object.
    sample_bounds : Mapping or None
        Per-sample bounds that replace the fixture's.

    Returns
    -------
    SelfBoundInputs
        The files and the arguments of one launch.
    """
    objects = directory / "objects"
    objects.mkdir()
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    for key, row in _object(inputs["resolver_input_population"]).items():
        data = (_FIXTURES / "objects" / _text(_object(row)["sha256"])).read_bytes()
        target = objects / key.split("|")[0][7:]
        assert not target.exists() or target.read_bytes() == data
        target.write_bytes(data)
    for entry in registry.entries:
        (objects / entry.schema_ref.digest[7:]).write_bytes(entry.schema_bytes)
    original_policy = _object(inputs["policy"])
    original_ref = BlobRef.from_mapping(_object(original_policy["policy_ref"]))
    base = _object(json.loads((objects / original_ref.digest[7:]).read_bytes()))
    for name in ("actual_accepted_configuration", "source_chain_ref"):
        base.pop(name)
    base.update(
        required_claim_ids=original_policy["required_claim_ids"],
        required_purposes=original_policy["required_purposes"],
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
    base_ref = _stored(base, objects)
    rule_fields, _ = method_rule_inputs(base_ref, objects, profile_class="unsigned_declared")
    launcher_ref = _stored(
        {
            "provenance": "declared_by_launcher_under_the_seat_account",
            "qualified_rule": False,
            "statement": "Unqualified launcher declaration for conditional arithmetic only.",
        },
        objects,
    )
    content_raw = _bytes(inputs["content_json"])
    schema_id = _text(inputs["schema_id"])
    content_ref = reference_bytes(
        content_raw,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=schema_id,
        limits=limits,
    )
    claim_ids = [_text(item) for item in cast(list[object], original_policy["required_claim_ids"])]
    purposes = [_text(item) for item in cast(list[object], original_policy["required_purposes"])]
    signature_ref, kind, _ = signature_rule_input(
        "sig_exception",
        objects,
        base_ref=base_ref,
        conditions_ref=launcher_ref,
        content_ref=content_ref,
        content_raw=content_raw,
        required_claim_ids=claim_ids,
        required_purposes=purposes,
        profile_class="unsigned_declared",
        limits=limits,
    )
    assert kind != "unavailable"
    declaration = declaration_value(
        rate=rate,
        base_ref=base_ref,
        launcher_ref=launcher_ref,
        rule_fields=rule_fields,
        signature_ref=signature_ref,
        claim_ids=claim_ids,
        purposes=purposes,
        declared_checks=declared_checks or {},
        evidence=evidence or {},
        sample_bounds=sample_bounds or {},
    )
    content_path = directory / "content.json"
    content_path.write_bytes(content_raw)
    return SelfBoundInputs(
        directory,
        _write(directory / "declaration.json", declaration),
        content_path,
        schema_id,
        _write(directory / "registry.json", inputs["registry"]),
        _write(directory / "limits.json", inputs["limits"]),
        objects,
        directory / "request",
        declaration,
        launcher_ref,
    )
