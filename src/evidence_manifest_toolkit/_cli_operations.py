# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole offline evidence command integration

"""Connect original caller files and closed configurations to genuine seal and verify."""

import base64
from pathlib import Path

import rfc8785

from ._caller_config import validate_trust_argument
from ._configuration_wire import (
    decode_policy,
    decode_registry,
    decode_signer_config,
    decode_signing_request,
    decode_trust,
)
from ._directory_publication import publish_directory
from ._errors import InputRefused
from ._file_io import read_file
from ._json import JsonValue, acquire_document
from ._offline_store import OfflineStore
from ._publication import publish_report
from ._reference_paths import configuration_refusal
from ._references import reference_bytes
from ._sealing import seal
from ._serialization import reference_mapping, report_bytes
from ._signer_installation import installed_signer
from ._signing_request import validate_signing_request
from ._values import Limits
from ._verification import execute_verification


def _configuration(path: Path, limits: Limits, pointer: str) -> JsonValue:
    """Acquire one entire bounded configuration and preserve outer caller failure scope."""
    data = read_file(path, max_bytes=limits.max_json_bytes)
    try:
        return acquire_document(data, limits=limits).value
    except InputRefused:
        raise configuration_refusal(pointer) from None


def seal_command(
    *,
    content: Path,
    schema_id: str,
    registry: Path,
    objects: Path,
    limits: Limits,
    output: Path,
    signing_request: Path | None,
    signer_config: Path | None,
    trust: Path | None,
) -> bytes:
    """Acquire the selected signer and exclusively publish the complete original seal transport.

    Parameters
    ----------
    content, registry, objects : Path
        Explicit complete source, caller-selected complete registry and read-only digest store.
    schema_id : str
        Independently selected known schema, without content-selected code.
    limits : Limits
        Original six validated operation bounds.
    output : Path
        Caller-selected fresh directory; no ancestors or existing entries are replaced.
    signing_request, signer_config, trust : Path or None
        Original all-three local signing selections. An unenrolled adapter never falls back
        to unsigned construction or manufactures a software signer.

    Returns
    -------
    bytes
        All three original stdout fields as no-LF JCS; content.json and refs.json are complete,
        with exact envelope bytes when an existing eligible installed signer succeeds.

    Raises
    ------
    EmtError
        Configuration, required input, native semantics or exclusive publication refuses.
    SignerUnavailable
        This installation has no enrolled qualified CLI signing adapter. The public library
        accepts actual caller-owned Signer instances independently of this installation state.
    """
    selected_registry = decode_registry(
        _configuration(registry, limits, "/registry"), limits=limits
    )
    selected_signing = None
    selected_signer = None
    selected_trust = None
    if signing_request is not None and signer_config is not None and trust is not None:
        selected_signing = decode_signing_request(
            _configuration(signing_request, limits, "/signing")
        )
        selected_configuration = decode_signer_config(
            _configuration(signer_config, limits, "/signer")
        )
        selected_trust = decode_trust(_configuration(trust, limits, "/trust"))
        validate_signing_request(selected_signing, limits=limits)
        validate_trust_argument(selected_trust, signed_construction=True)
        selected_signer = installed_signer(selected_configuration)
    data = read_file(content, max_bytes=limits.max_json_bytes)
    with OfflineStore(objects) as resolver:
        result = seal(
            data,
            schema_id=schema_id,
            registry=selected_registry,
            resolver=resolver,
            limits=limits,
            signing=selected_signing,
            signer=selected_signer,
            trust=selected_trust,
        )
    reference = reference_mapping(result.content_ref)
    references: dict[str, JsonValue] = {"content_ref": reference}
    files = {"content.json": result.canonical_content}
    envelope: str | None = None
    if result.envelope_json is not None:
        files["envelope.json"] = result.envelope_json
        references["envelope_ref"] = reference_mapping(
            reference_bytes(
                result.envelope_json,
                digest_basis="jcs_content",
                media_type="application/json",
                schema_id=None,
                limits=limits,
            )
        )
        envelope = base64.urlsafe_b64encode(result.envelope_json).rstrip(b"=").decode("ascii")
    files["refs.json"] = rfc8785.dumps(references)
    stdout = rfc8785.dumps(
        {
            "canonical_content": {
                "content_ref": reference,
                "output_file": str(output / "content.json"),
            },
            "content_ref": reference,
            "envelope_json": envelope,
        }
    )
    publish_directory(output, files)
    return stdout


def verify_command(
    *,
    content: Path,
    schema_id: str,
    registry: Path,
    objects: Path,
    limits: Limits,
    policy: Path,
    trust: Path,
    signatures: list[Path],
    report: Path,
) -> tuple[bytes, int]:
    """Verify actual original evidence and publish all fifteen report fields without qualification loss.

    Parameters
    ----------
    content, registry, objects, policy, trust : Path
        Explicit complete source, independently selected closed configurations and offline store.
    schema_id : str
        Caller-selected exact known schema identifier.
    limits : Limits
        Whole original validated byte/count/depth bounds.
    signatures : list of Path
        All explicit detached envelopes in caller order; no store discovery occurs.
    report : Path
        Explicit fresh file receiving exactly the same complete bytes as stdout.

    Returns
    -------
    tuple of bytes and int
        Complete no-LF JCS report and common-mode exit0/2/3/4. Domain/current results retain
        their separate report meaning, and successful file storage clears no refusal.

    Raises
    ------
    EmtError
        Input/configuration/acquisition or output publication fails; no success file is created
        for thrown failures and no interpreter diagnostic is exposed.
    """
    selected_registry = decode_registry(
        _configuration(registry, limits, "/registry"), limits=limits
    )
    selected_policy = decode_policy(_configuration(policy, limits, "/policy"))
    selected_trust = decode_trust(_configuration(trust, limits, "/trust"))
    data = read_file(content, max_bytes=limits.max_json_bytes)
    envelopes = tuple(read_file(path, max_bytes=limits.max_json_bytes) for path in signatures)
    with OfflineStore(objects) as resolver:
        execution = execute_verification(
            data,
            schema_id=schema_id,
            envelopes=envelopes,
            registry=selected_registry,
            resolver=resolver,
            limits=limits,
            policy=selected_policy,
            trust=selected_trust,
        )
        result = execution.report
        output = report_bytes(result)
    status = (
        4
        if any(reason.code == "configuration_error" for reason in result.reasons)
        else 3
        if any(
            reason.code in {"reference_unavailable", "signer_unavailable", "storage_error"}
            for reason in result.reasons
        )
        else 0
        if result.common_eligibility == "eligible"
        else 2
    )
    publish_report(report, output)
    return output, status
