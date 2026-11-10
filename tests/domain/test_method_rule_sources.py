# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole private method rules through public verify

"""Exercise actual complete rule selection before unrelated native Clock admission."""

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest
from tests.domain.method_rule_inputs import method_rule_inputs
from tests.domain.protected_control_inputs import protected_control_inputs
from tests.domain.protected_state_inputs import protected_state_inputs
from tests.domain.test_cli_evidence_sources import _source
from tests.domain.test_policy_selection_sources import _successor_policy
from tests.domain.test_software_sources import _software_table, _stored_source
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
    DelegatedTrustContextV2,
    InputRefused,
    Limits,
    ReferenceUnavailable,
    SoftwareTrustContextV2,
    VerificationPolicy,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"


@pytest.mark.parametrize(
    "condition",
    (
        "unsigned",
        "software",
        "delegated",
        "foreign",
        "missing_identity",
        "missing_validation",
        "missing_foreign",
        "identity_format",
        "validation_format",
        "foreign_format",
        "identity_class",
        "minimum_class",
        "validation_class",
        "validation_identity",
        "nonuse",
        "foreign_without_trust",
        "trust_without_foreign",
        "native_method_depth",
        "native_method_within_depth",
    ),
)
def test_public_whole_method_rule_sources_and_class_joins(condition: str, tmp_path: Path) -> None:
    """Retain original missing arguments, exact rule failures and later Clock refusal.

    Parameters
    ----------
    condition : str
        Actual complete class/foreign selection or one whole original source conflict.
    tmp_path : Path
        Owned real input files; all original corpus and carrier sources remain unchanged.

    Notes
    -----
    Valid rule initialization reaches the deliberately unqualified native Clock method.
    Opaque earlier source refs are not claimed as qualified launcher, key, comparison or
    foreign trust evidence. No helper/network/provider or protected state is fabricated.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    declared = _object(inputs["policy"])
    legacy = BlobRef.from_mapping(_object(declared["policy_ref"]))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    original = {path: path.read_bytes() for path in population.values()}
    base = _object(json.loads(population[legacy.digest + "|raw_bytes"].read_bytes()))
    for field in ("actual_accepted_configuration", "source_chain_ref"):
        base.pop(field)
    base.update(
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
    base_ref = _stored_source(base, tmp_path)
    population[base_ref.digest + "|raw_bytes"] = tmp_path / base_ref.digest[7:]
    binding, references, carriers = _sources()
    original.update(carriers)
    for reference in references:
        path = next(
            path
            for path, raw in carriers.items()
            if "sha256:" + hashlib.sha256(raw).hexdigest() == reference.digest
        )
        population[reference.digest + "|raw_bytes"] = path
    caller = _callers(binding, references, "current")[
        1 if condition == "software" else 2 if condition == "delegated" else 0
    ]
    if isinstance(caller, SoftwareTrustContextV2):
        table = _software_table(base_ref, tmp_path, sequence="1")
        population[table.digest + "|raw_bytes"] = tmp_path / table.digest[7:]
        caller = replace(
            caller, software_authorization_ref=table, accepted_authorization_sequence_floor="1"
        )
    value = _successor_policy(base_ref)
    value["profile_class"] = caller.profile_class
    if caller.profile_class != "unsigned_declared":
        value["authority_rule_ref"] = dict(base_ref.to_mapping())
    if isinstance(caller, DelegatedTrustContextV2):
        value["root_grant_ref"] = dict(caller.root_grant_ref.to_mapping())
        rule, selection, controls, control_objects = protected_control_inputs(base_ref, tmp_path)
        caller = replace(
            caller,
            independent_root_selection_ref=base_ref,
            authority_control_selection_ref=selection,
            control_envelopes=controls,
        )
        grant, snapshot, state_objects = protected_state_inputs(
            base_ref, rule, base_ref, tmp_path, sequence=caller.accepted_authority_sequence_floor
        )
        caller = replace(
            caller,
            root_grant_ref=grant,
            current_authority_snapshot_ref=snapshot,
            archived_authority_snapshot_ref=snapshot
            if caller.evaluation_mode == "historical"
            else None,
        )
        value["root_grant_ref"] = dict(grant.to_mapping())
        population.update(state_objects)
        value["authority_rule_ref"] = dict(rule.to_mapping())
        population.update(control_objects)
    fields, objects = method_rule_inputs(
        base_ref,
        tmp_path,
        profile_class=caller.profile_class,
        foreign=condition
        in {"foreign", "missing_foreign", "foreign_format", "foreign_without_trust"},
    )
    affected = {
        "missing_identity": "identity_rule_ref",
        "identity_format": "identity_rule_ref",
        "identity_class": "identity_rule_ref",
        "missing_validation": "validation_rule_ref",
        "validation_format": "validation_rule_ref",
        "validation_class": "validation_rule_ref",
        "validation_identity": "validation_rule_ref",
        "nonuse": "validation_rule_ref",
        "missing_foreign": "foreign_rule_ref",
        "foreign_format": "foreign_rule_ref",
    }.get(condition)
    target = None if affected is None else BlobRef.from_mapping(_object(fields[affected]))
    if target is not None and not condition.startswith("missing"):
        body = _object(json.loads((tmp_path / target.digest[7:]).read_bytes()))
        if condition.endswith("_format"):
            body["format_version"] = "different-independent-format"
        if condition == "identity_class":
            body["custody_class"] = "software_local_unprotected"
        if condition == "validation_class":
            body["profile_class"] = "software_local_unprotected"
        if condition == "validation_identity":
            body["independent_identity_policy_ref"] = dict(base_ref.to_mapping())
        if condition == "nonuse":
            body["required_nonuse_classes"] = ["enforced_isolation"]
        target = _stored_source(body, tmp_path)
        fields[cast(str, affected)] = dict(target.to_mapping())
        objects[target.digest + "|raw_bytes"] = tmp_path / target.digest[7:]
    if condition == "minimum_class":
        value["minimum_identity_class"] = "endpoint_observed"
    if condition == "foreign_without_trust":
        fields["independent_foreign_trust_ref"] = None
    if condition == "trust_without_foreign":
        fields["independent_foreign_trust_ref"] = dict(base_ref.to_mapping())
    depth_frontier: BlobRef | None = None
    if condition in {"native_method_depth", "native_method_within_depth"}:
        limits = replace(limits, max_graph_depth=3 if condition == "native_method_depth" else 6)
        identity = _object(
            json.loads(
                (
                    tmp_path / BlobRef.from_mapping(_object(fields["identity_rule_ref"])).digest[7:]
                ).read_bytes()
            )
        )
        validation = _object(
            json.loads(
                (
                    tmp_path
                    / BlobRef.from_mapping(_object(fields["validation_rule_ref"])).digest[7:]
                ).read_bytes()
            )
        )
        child: BlobRef | None = None
        for parent, field, join in (
            (validation, "comparison_rule_ref", "whole_comparison_parameters_ref"),
            (validation, "run_and_seal_before_comparison_procedure_ref", "executor_method_ref"),
            (identity, "actual_key_possession_rule_ref", "receiver_method_ref"),
            (identity, "launcher_or_observer_procedure_ref", "record_contract_ref"),
        ):
            selected_binding = BlobRef.from_mapping(_object(parent[field]))
            body = _object(json.loads((tmp_path / selected_binding.digest[7:]).read_bytes()))
            if child is not None:
                body[join] = dict(child.to_mapping())
            child = _stored_source(body, tmp_path)
            if field == "run_and_seal_before_comparison_procedure_ref":
                depth_frontier = BlobRef.from_mapping(_object(body["implementation_ref"]))
            parent[field] = dict(child.to_mapping())
            objects[child.digest + "|raw_bytes"] = tmp_path / child.digest[7:]
        identity_ref = _stored_source(identity, tmp_path)
        validation["independent_identity_policy_ref"] = dict(identity_ref.to_mapping())
        validation_ref = _stored_source(validation, tmp_path)
        fields.update(
            identity_rule_ref=dict(identity_ref.to_mapping()),
            validation_rule_ref=dict(validation_ref.to_mapping()),
        )
        for original_ref in (identity_ref, validation_ref):
            objects[original_ref.digest + "|raw_bytes"] = tmp_path / original_ref.digest[7:]
    value.update(fields)
    selected = _stored_source(
        value, tmp_path, schema_id="evidence_manifest_toolkit.authority_policy.v2"
    )
    population.update(objects)
    population[selected.digest + "|raw_bytes"] = tmp_path / selected.digest[7:]
    if condition.startswith("missing"):
        assert target is not None
        (tmp_path / target.digest[7:]).unlink()
    resolver = _FileResolver(population)
    with pytest.raises(
        ReferenceUnavailable if condition.startswith("missing") else InputRefused
    ) as caught:
        verify(
            _bytes(inputs["content_json"]),
            schema_id=_text(inputs["schema_id"]),
            envelopes=(),
            registry=registry,
            resolver=resolver,
            limits=limits,
            policy=VerificationPolicy(
                selected,
                tuple(_text(v) for v in _array(declared["required_claim_ids"])),
                ("evidence",),
            ),
            trust=caller,
        )
    if condition.startswith("missing"):
        assert isinstance(caught.value, ReferenceUnavailable) and caught.value.reference == target
        assert resolver.calls[-1][0] == target
    else:
        assert isinstance(caught.value, InputRefused)
        expected = {
            "code": "policy_unavailable",
            "subject_digest": selected.digest,
            "claim_id": None,
            "pointer": "/required_evaluation_time_qualification/clock_qualification_ref",
            "detail": "The required evaluation-time qualification is unavailable.",
        }
        if condition.endswith("_format"):
            assert target is not None
            expected.update(
                code="invalid_schema",
                subject_digest=target.digest,
                pointer="/format_version",
                detail="Input violates its selected schema.",
            )
        if condition in {
            "identity_class",
            "minimum_class",
            "validation_class",
            "validation_identity",
            "nonuse",
            "foreign_without_trust",
            "trust_without_foreign",
        }:
            expected.update(
                pointer="/"
                + (
                    {
                        "identity_class": "identity_rule_ref",
                        "minimum_class": "minimum_identity_class",
                        "validation_class": "validation_rule_ref",
                        "validation_identity": "validation_rule_ref",
                        "nonuse": "allowed_nonuse_classes",
                    }.get(condition, "independent_foreign_trust_ref")
                ),
                detail="Selected method rule sources conflict.",
            )
        if condition == "native_method_depth":
            assert depth_frontier is not None
            expected.update(
                code="limit_exceeded",
                subject_digest=depth_frontier.digest,
                pointer=None,
                detail="Reference graph depth bound exceeded.",
            )
        assert asdict(caught.value.reason) == expected
    assert all(path.read_bytes() == raw for path, raw in original.items())
