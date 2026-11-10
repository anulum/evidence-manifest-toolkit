# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole selected native method source fault inputs

"""Materialise exact whole implementation and environment failures for public verification."""

import json
from pathlib import Path
from typing import TYPE_CHECKING

from tests.domain.test_successor_provider_boundary import _stored
from tests.domain.test_verification_report_sources import _object

from evidence_manifest_toolkit import BlobRef, Limits, reference_bytes

if TYPE_CHECKING:
    from tests.domain.reproduction_record_inputs import ReproductionOutcome

ENVIRONMENT_FACTS = (
    "python_implementation",
    "python_version",
    "python_cache_tag",
    "python_executable",
    "python_soabi",
    "libc_reported_version",
    "uname",
    "byte_order",
    "long_bits",
    "pointer_bits",
)
NATIVE_METHOD_CASES = (
    tuple(
        "native_binding_" + case
        for case in (
            "implementation_stale",
            "implementation_unknown",
            "implementation_media",
            "implementation_basis",
            "implementation_missing",
            "implementation_identity",
            "qualification_identity",
            "environment_missing",
            "qualification_missing",
            "environment_extra",
            "environment_omitted",
            "environment_primitive",
            "environment_invalid_json",
        )
    )
    + tuple("native_binding_environment_fact_" + name for name in ENVIRONMENT_FACTS)
    + tuple(
        "cli_native_binding_" + case
        for case in (
            "implementation_stale",
            "implementation_missing",
            "environment_extra",
            "qualification_missing",
        )
    )
)


def native_method_input(
    condition: str, rules: dict[str, object], directory: Path
) -> "ReproductionOutcome":
    """Change one complete independent method source before the original caller freeze.

    Parameters
    ----------
    condition : str
        Whole known implementation/source or actual environment contradiction.
    rules : dict
        Entire original identity/validation selections, replaced with their new full refs.
    directory : Path
        Real source population owned by this one public test.

    Returns
    -------
    tuple
        Independently specified complete public diagnostic and original missing argument.
        Test declarations remain explicitly unqualified even when all facts match.
    """
    case = condition.removeprefix("cli_").removeprefix("native_binding_")
    identity_ref = BlobRef.from_mapping(_object(rules["identity_rule_ref"]))
    identity = _object(json.loads((directory / identity_ref.digest[7:]).read_bytes()))
    launcher_ref = BlobRef.from_mapping(_object(identity["launcher_or_observer_procedure_ref"]))
    launcher = _object(json.loads((directory / launcher_ref.digest[7:]).read_bytes()))
    field = (
        "implementation_environment_ref"
        if case.startswith("environment_")
        else "implementation_qualification_ref"
        if case.startswith("qualification_")
        else "implementation_ref"
    )
    source_ref = BlobRef.from_mapping(_object(launcher[field]))
    original = (directory / source_ref.digest[7:]).read_bytes()
    missing = None
    if case in {"implementation_identity", "qualification_identity"}:
        (directory / source_ref.digest[7:]).write_bytes(original + b" ")
    elif case.endswith("_missing"):
        raw = b"An original explicitly selected native source is genuinely unavailable."
        missing = reference_bytes(
            raw,
            media_type="text/plain",
            digest_basis="raw_bytes",
            schema_id=None,
            limits=Limits(
                max_json_bytes=1048576,
                max_blob_bytes=1048576,
                max_total_reference_bytes=16777216,
                max_reference_count=1024,
                max_graph_depth=32,
                max_json_depth=64,
            ),
        )
        source_ref = missing
        assert not (directory / missing.digest[7:]).exists()
    else:
        raw = original
        media = source_ref.media_type
        basis = source_ref.digest_basis
        if case == "implementation_stale":
            possession_ref = BlobRef.from_mapping(
                _object(identity["actual_key_possession_rule_ref"])
            )
            possession = _object(json.loads((directory / possession_ref.digest[7:]).read_bytes()))
            previous_implementation = BlobRef.from_mapping(
                _object(possession["implementation_ref"])
            )
            raw = (directory / previous_implementation.digest[7:]).read_bytes()
            media = "text/x-python"
        elif case == "implementation_unknown":
            raw = b"{}"
        elif case == "implementation_media":
            media = "text/plain"
        elif case == "implementation_basis":
            basis = "jcs_content"
        elif case == "environment_invalid_json":
            raw = b"{"
        elif case == "environment_primitive":
            raw = b"[]"
        else:
            environment = _object(json.loads(original))
            if case == "environment_extra":
                environment["unobserved_fact"] = "not part of the actual captured environment"
            elif case == "environment_omitted":
                del environment["python_soabi"]
            else:
                fact = case.removeprefix("environment_fact_")
                assert fact in ENVIRONMENT_FACTS
                environment[fact] = {"different_type_and_value": True}
            raw = json.dumps(environment).encode()
        source_ref = reference_bytes(
            raw,
            media_type=media,
            digest_basis=basis,
            schema_id=None,
            limits=Limits(
                max_json_bytes=1048576,
                max_blob_bytes=1048576,
                max_total_reference_bytes=16777216,
                max_reference_count=1024,
                max_graph_depth=32,
                max_json_depth=64,
            ),
        )
        (directory / source_ref.digest[7:]).write_bytes(raw)
    launcher[field] = dict(source_ref.to_mapping())
    launcher_ref = _stored(launcher, directory)
    identity["launcher_or_observer_procedure_ref"] = dict(launcher_ref.to_mapping())
    rules["identity_rule_ref"] = dict(_stored(identity, directory).to_mapping())
    validation_ref = BlobRef.from_mapping(_object(rules["validation_rule_ref"]))
    validation = _object(json.loads((directory / validation_ref.digest[7:]).read_bytes()))
    validation["independent_identity_policy_ref"] = rules["identity_rule_ref"]
    rules["validation_rule_ref"] = dict(_stored(validation, directory).to_mapping())
    reason: dict[str, object] = {
        "code": "policy_unavailable",
        "subject_digest": launcher_ref.digest,
        "claim_id": None,
        "pointer": "/" + field,
        "detail": "Native method execution environment conflicts."
        if field == "implementation_environment_ref"
        else "Native method implementation sources conflict.",
    }
    if missing is not None:
        reason.update(
            code="reference_unavailable",
            subject_digest=None,
            pointer=None,
            detail="Required reference unavailable.",
        )
        return "unavailable", reason, missing
    if case in {"implementation_identity", "qualification_identity"}:
        reason.update(code="reference_mismatch", detail="Reference byte identity does not match.")
    if case in {"environment_invalid_json", "environment_primitive"}:
        reason.update(
            code="invalid_json" if case.endswith("invalid_json") else "invalid_schema",
            subject_digest=source_ref.digest,
            pointer="",
            detail="Input is not valid strict JSON."
            if case.endswith("invalid_json")
            else "Complete context object is required.",
        )
    return "refused", reason, None
