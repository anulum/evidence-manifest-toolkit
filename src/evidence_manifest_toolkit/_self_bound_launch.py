# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — build an unsigned V2 request in the process that verifies it

"""Bind, build and verify one unsigned V2 request inside the process that verifies it.

A verification binds the process that runs it: the entry binding names this process's start
identity and boot, and a request built in another process refuses here. A launcher therefore
starts a child that calls :func:`verify_self_bound`. The child captures its own identity with
the toolkit's native entry method, captures this launch's Clock acceptance, builds every record
of the request from those captures and the launcher's declaration, and verifies in the same
process. Every capture happens before verification starts; verification's own entry
observation and monotonic handoff stay its own.

Nothing is written while the request is built or verified. The records are held by digest and
served to verification over the caller's store; only after verification returns are the new
records written to the store and the request directory published under a fresh name. A refusal
anywhere leaves both untouched.
"""

import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType
from typing import cast

import rfc8785

from ._caller_config import validate_reference_argument
from ._codecs import DIGEST_PATTERN
from ._configuration_wire import decode_registry
from ._directory_publication import publish_directory
from ._entry_observation import (
    NativeEntryObservation,
    NativeEntryUnavailable,
    capture_verifier_entry,
)
from ._errors import ConfigurationError, InputRefused, ReferenceUnavailable, StorageError
from ._file_io import read_file, read_limits
from ._json import JsonValue, acquire_document
from ._offline_store import OfflineStore
from ._reference_paths import configuration_refusal
from ._references import reference_bytes
from ._results import VerificationReport
from ._self_bound_declaration import EvidenceSelection, SelfBoundDeclaration, decode_declaration
from ._self_bound_records import (
    IDENTITY_CLASS,
    POLICY_SCHEMA_ID,
    UNSIGNED_CLASS,
    AnnualAcceptance,
    IdentitySources,
    StagedObjects,
    Wire,
    capture_exchange,
    capture_sample,
    policy_record,
    stage_annual_acceptance,
    use_method_record,
    utc_lexeme,
    wire,
    witness_record,
)
from ._successor_configuration import decode_successor_trust
from ._successor_trust import UnsignedTrustContextV2
from ._trust_types import Purpose, VerificationPolicy
from ._values import BlobRef, Digest, Limits, Reason
from ._verification import verify

REQUEST_SCHEMA_ID = "evidence_manifest_toolkit.self_bound_request.v1"
"""The schema identifier of a published request's ``request.json``."""


@dataclass(frozen=True, slots=True)
class SelfBoundRequest:
    """What one self-bound launch built and verified.

    Attributes
    ----------
    request_id : str
        The request's fresh identifier.
    policy : VerificationPolicy
        The verification policy the request was verified under.
    trust : UnsignedTrustContextV2
        The unsigned caller trust binding this process.
    records : Mapping of str to BlobRef
        Every record the launch stored, by name.
    """

    request_id: str
    policy: VerificationPolicy
    trust: UnsignedTrustContextV2
    records: Mapping[str, BlobRef]


class _StagedResolver:
    """Serve the staged records first and the caller's store for everything else.

    Parameters
    ----------
    staged : Mapping of str to bytes
        Staged record bytes by 64-hex-digit digest.
    store : OfflineStore
        The caller's open store.
    """

    def __init__(self, staged: Mapping[str, bytes], store: OfflineStore) -> None:
        """Keep the staged records and the open store this resolver reads from."""
        self._staged = staged
        self._store = store

    def _staged_bytes(self, digest: Digest, max_bytes: int) -> bytes | None:
        """Return a staged record within the caller's bound, or ``None`` when none is staged.

        Parameters
        ----------
        digest : str
            The validated digest.
        max_bytes : int
            The caller's positive read bound.

        Returns
        -------
        bytes or None
            The staged bytes.

        Raises
        ------
        ConfigurationError
            The bound is not a positive integer.
        InputRefused
            The staged record exceeds the bound.
        """
        if type(max_bytes) is not int or max_bytes <= 0:
            raise configuration_refusal("/resolver/max_bytes")
        data = self._staged.get(digest[7:])
        if data is not None and len(data) > max_bytes:
            raise InputRefused(
                Reason(
                    "limit_exceeded", digest, None, None, "Reference acquisition bound exceeded."
                )
            )
        return data

    def resolve(self, reference: BlobRef, *, max_bytes: int) -> bytes:
        """Read one reference's bytes, staged or stored.

        Parameters
        ----------
        reference : BlobRef
            The complete reference.
        max_bytes : int
            The caller's positive read bound.

        Returns
        -------
        bytes
            The bytes.
        """
        validate_reference_argument(reference, pointer="/resolver/reference")
        data = self._staged_bytes(reference.digest, max_bytes)
        return self._store.resolve(reference, max_bytes=max_bytes) if data is None else data

    def resolve_digest(self, digest: Digest, *, max_bytes: int) -> bytes:
        """Read one digest's bytes, staged or stored.

        Parameters
        ----------
        digest : str
            The lowercase sha256 identity.
        max_bytes : int
            The caller's positive read bound.

        Returns
        -------
        bytes
            The bytes.
        """
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            raise configuration_refusal("/resolver/digest")
        data = self._staged_bytes(digest, max_bytes)
        return self._store.resolve_digest(digest, max_bytes=max_bytes) if data is None else data


def _configuration(path: Path, limits: Limits, pointer: str) -> JsonValue:
    """Acquire one whole bounded configuration file, refused at its own pointer.

    Parameters
    ----------
    path : Path
        The file.
    limits : Limits
        The operation's bounds.
    pointer : str
        The configuration's position.

    Returns
    -------
    object
        The decoded JSON value.

    Raises
    ------
    ConfigurationError
        The file is not strict JSON within the bounds.
    """
    data = read_file(path, max_bytes=limits.max_json_bytes)
    try:
        return acquire_document(data, limits=limits).value
    except InputRefused:
        raise configuration_refusal(pointer) from None


def _base_policy(store: OfflineStore, reference: BlobRef, limits: Limits) -> Wire:
    """Read the declared base policy and require its Clock qualification to be unfilled.

    Parameters
    ----------
    store : OfflineStore
        The caller's store.
    reference : BlobRef
        The declared base policy.
    limits : Limits
        The operation's bounds.

    Returns
    -------
    dict
        The base policy body.

    Raises
    ------
    ConfigurationError
        It is not a JSON object whose evaluation-time qualification has a null
        ``clock_qualification_ref``.
    """
    try:
        value = acquire_document(
            store.resolve(reference, max_bytes=limits.max_json_bytes), limits=limits
        ).value
    except InputRefused:
        raise configuration_refusal("/declaration/base_policy_ref") from None
    qualification = (
        value.get("required_evaluation_time_qualification") if isinstance(value, dict) else None
    )
    if (
        not isinstance(qualification, dict)
        or qualification.get("clock_qualification_ref", 0) is not None
    ):
        raise configuration_refusal("/declaration/base_policy_ref")
    return cast(Wire, value)


def identity_sources(
    store: StagedObjects, observation: NativeEntryObservation | NativeEntryUnavailable
) -> IdentitySources:
    """Stage this process's identity as the toolkit's native entry method observed it.

    Parameters
    ----------
    store : StagedObjects
        The request's staged records.
    observation : NativeEntryObservation or NativeEntryUnavailable
        This process's own entry observation.

    Returns
    -------
    IdentitySources
        The staged sources.

    Raises
    ------
    ConfigurationError
        The native entry method is unavailable on this host.
    """
    if not isinstance(observation, NativeEntryObservation):
        raise ConfigurationError(
            Reason(
                "configuration_error",
                None,
                None,
                "/clock/identity_capture",
                "The native entry identity of this process is unavailable.",
            )
        )
    method = files("evidence_manifest_toolkit").joinpath("_native_entry_method.json").read_bytes()
    return IdentitySources(
        store.raw(observation.environment_json, "application/json"),
        store.raw(observation.boot_bytes, "text/plain"),
        store.raw(observation.process_bytes, "text/plain"),
        store.raw(method, "application/json"),
        store.json(
            {
                "pid": str(observation.process_id),
                "provenance": IDENTITY_CLASS,
                "qualified_rule": False,
            }
        ),
    )


def _checks(declaration: SelfBoundDeclaration, roles: Mapping[str, BlobRef]) -> list[JsonValue]:
    """Return the declared checks in wire form, each role replaced by the record it names.

    Parameters
    ----------
    declaration : SelfBoundDeclaration
        The launcher's declared checks.
    roles : Mapping of str to BlobRef
        The records stored before the acceptance body, by role.

    Returns
    -------
    list
        The checks as the acceptance body carries them.
    """

    def evidence(item: EvidenceSelection) -> Wire:
        """Return one evidence item's reference in wire form."""
        if item.reference is not None:
            return wire(item.reference)
        return wire(roles[cast(str, item.role)])

    return [
        {
            "check_id": check.check_id,
            "result": check.result,
            "evidence_refs": [evidence(item) for item in check.evidence],
        }
        for check in declaration.checks
    ]


def _storage_refusal(pointer: str, detail: str) -> StorageError:
    """Return a refusal of the caller's object store.

    Parameters
    ----------
    pointer : str
        The store's position.
    detail : str
        What failed.

    Returns
    -------
    StorageError
        The refusal.
    """
    return StorageError(Reason("storage_error", None, None, pointer, detail))


def _absent_objects(store: OfflineStore, staged: Mapping[str, bytes]) -> dict[str, bytes]:
    """Return the staged records the store does not hold yet, refusing any conflicting one.

    Parameters
    ----------
    store : OfflineStore
        The caller's open store.
    staged : Mapping of str to bytes
        The staged records by digest.

    Returns
    -------
    dict of str to bytes
        The records still to be written.

    Raises
    ------
    StorageError
        The store holds different bytes under a staged digest, or cannot be read.
    """
    absent: dict[str, bytes] = {}
    for name, data in staged.items():
        try:
            held = store.resolve_digest("sha256:" + name, max_bytes=len(data) + 1)
        except ReferenceUnavailable:
            absent[name] = data
            continue
        except InputRefused:
            held = None
        if held != data:
            raise _storage_refusal(
                "/objects/" + name,
                "The object store holds different bytes under a staged record's digest.",
            )
    return absent


def _write_objects(objects: Path, records: Mapping[str, bytes]) -> None:
    """Publish each record into the store under its digest, never replacing a file.

    Each record is written whole to a private name, synchronised, and linked to its digest
    name, which fails if that name exists; the private name is then removed.

    Parameters
    ----------
    objects : Path
        The caller's store directory.
    records : Mapping of str to bytes
        The records to write, by digest.

    Raises
    ------
    StorageError
        A write or link fails.
    """
    try:
        directory = os.open(objects, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for name, data in records.items():
                private = ".emt-object-" + secrets.token_hex(8)
                descriptor = os.open(
                    private,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o644,
                    dir_fd=directory,
                )
                try:
                    try:
                        view = memoryview(data)
                        while view:
                            view = view[os.write(descriptor, view) :]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    os.link(private, name, src_dir_fd=directory, dst_dir_fd=directory)
                finally:
                    os.unlink(private, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        raise _storage_refusal("/objects", "The object store could not be written.") from None


def verify_self_bound(
    *,
    declaration: Path,
    content: Path,
    schema_id: str,
    registry: Path,
    limits: Path,
    objects: Path,
    request: Path,
) -> tuple[VerificationReport, SelfBoundRequest]:
    """Build the whole unsigned V2 request in this process and verify it here.

    Parameters
    ----------
    declaration : Path
        The launcher's declaration (``evidence_manifest_toolkit.self_bound_declaration.v1``).
    content : Path
        The content to verify.
    schema_id : str
        The content's known schema identifier.
    registry, limits : Path
        The schema registry and the operation's limits, as ``emt verify`` takes them.
    objects : Path
        The caller's object store, holding the declared static objects. The request's new
        records are added to it after verification returns.
    request : Path
        A fresh directory name. After verification returns it holds ``policy.json`` and
        ``trust.json``, exactly as ``emt verify`` takes them, and ``request.json``.

    Returns
    -------
    tuple
        The verification report and what the launch built.

    Raises
    ------
    ConfigurationError
        A configuration or the declaration is invalid, ``request`` exists, or this host lacks
        the native entry method.
    StorageError
        A capture is unavailable, or the store conflicts with a staged record.
    EmtError
        Verification refuses. Nothing is then written.
    """
    selected_limits = read_limits(limits)
    limits_value = _configuration(limits, selected_limits, "/limits")
    registry_value = _configuration(registry, selected_limits, "/registry")
    selected_registry = decode_registry(registry_value, limits=selected_limits)
    declared = decode_declaration(_configuration(declaration, selected_limits, "/declaration"))
    content_json = read_file(content, max_bytes=selected_limits.max_json_bytes)
    content_ref = reference_bytes(
        content_json,
        media_type="application/json",
        digest_basis="jcs_content",
        schema_id=schema_id,
        limits=selected_limits,
    )
    if request.exists() or request.is_symlink():
        raise configuration_refusal("/request")
    staged = StagedObjects()
    with OfflineStore(objects) as store:
        base = _base_policy(store, declared.base_policy_ref, selected_limits)
        sources = identity_sources(staged, capture_verifier_entry())
        annual: AnnualAcceptance = stage_annual_acceptance(
            staged, sources, declared, lambda roles: _checks(declared, roles)
        )
        request_id = "emt-self-bound:" + secrets.token_hex(16)
        exchange = capture_exchange(staged)
        before = capture_sample(staged)
        identity = wire(sources.identity)
        first = staged.json(
            {
                "format_version": "autonomous-evaluation-clock-first-sample-source-r4",
                "request_id": request_id,
                "utc_lexeme": utc_lexeme(before.utc_ns),
                "utc_epoch_ns": str(before.utc_ns),
                "monotonic_ticks": str(before.raw_after),
                "boot_domain_ref": wire(sources.boot),
                "verification_controller_identity_ref": identity,
                "process_start_identity_ref": wire(sources.process),
                "source_profile_ref": wire(annual.profile),
                "raw_sample_ref": wire(before.raw_ref),
            }
        )
        context: Wire = {
            "namespace": "EMT_CALLER_TRUST_UNSIGNED_V2",
            "profile_class": UNSIGNED_CLASS,
            "evaluation_mode": "current",
            "evaluation_time": utc_lexeme(before.utc_ns),
            "clock_entry_binding": {
                "format_version": "emt-clock-entry-binding-source-r4",
                "request_id": request_id,
                "first_sample_source_ref": wire(first),
                "source_profile_ref": wire(annual.profile),
                "boot_domain_ref": wire(sources.boot),
                "verification_controller_identity_ref": identity,
                "process_start_identity_ref": wire(sources.process),
                "entry_observation_method_ref": wire(sources.method),
                "implementation_environment_ref": wire(sources.environment),
            },
        }
        trust = cast(UnsignedTrustContextV2, decode_successor_trust(context))
        context_ref = staged.json(context)
        subject = staged.json(
            {
                "format_version": "autonomous-evaluation-clock-subject-source-r4",
                "request_id": request_id,
                "content_ref": wire(content_ref),
                "ordered_receipt_refs": [],
                "schema_registry_ref": wire(staged.json(cast(Wire, registry_value))),
                "whole_trust_context_ref": wire(context_ref),
                "whole_limits_ref": wire(staged.json(cast(Wire, limits_value))),
                "whole_base_policy_ref": wire(declared.base_policy_ref),
                "verification_controller_identity_ref": identity,
                "custody_class": UNSIGNED_CLASS,
                "first_sample_source_ref": wire(first),
            }
        )
        after = capture_sample(staged)
        use = capture_sample(staged)
        samples = (before, after, use)
        use_method = staged.json(
            use_method_record(
                sources=sources,
                declaration=declared,
                annual=annual,
                subject=subject,
                first=first,
                request_id=request_id,
                exchange=exchange,
                samples=samples,
            )
        )
        witness = staged.json(
            witness_record(
                sources=sources,
                declaration=declared,
                annual=annual,
                subject=subject,
                first=first,
                request_id=request_id,
                exchange=exchange,
                samples=samples,
                use_method=use_method,
            )
        )
        qualification = cast(Wire, base["required_evaluation_time_qualification"])
        final = staged.json(
            {
                **base,
                "required_evaluation_time_qualification": {
                    **qualification,
                    "clock_qualification_ref": wire(witness),
                },
            }
        )
        policy_ref = staged.json(policy_record(declared, final), schema_id=POLICY_SCHEMA_ID)
        policy = VerificationPolicy(
            policy_ref,
            declared.required_claim_ids,
            cast(tuple[Purpose, ...], declared.required_purposes),
        )
        absent = _absent_objects(store, staged.objects)
        report = verify(
            content_json,
            schema_id=schema_id,
            envelopes=(),
            registry=selected_registry,
            resolver=_StagedResolver(staged.objects, store),
            limits=selected_limits,
            policy=policy,
            trust=trust,
        )
    records = {
        "environment": sources.environment,
        "boot_domain": sources.boot,
        "process_start": sources.process,
        "entry_method": sources.method,
        "identity_declaration": sources.identity,
        "drift_method": annual.drift,
        "annual_derivation": annual.annual_derivation,
        "uncertainty_method": annual.uncertainty,
        "profile": annual.profile,
        "acceptance": annual.acceptance,
        "first_sample": first,
        "trust_context": context_ref,
        "subject": subject,
        "use_method": use_method,
        "witness": witness,
        "final_policy": final,
        "policy": policy_ref,
    }
    _write_objects(objects, absent)
    publish_directory(
        request,
        {
            "policy.json": rfc8785.dumps(
                {
                    "policy_ref": wire(policy_ref),
                    "required_claim_ids": list(declared.required_claim_ids),
                    "required_purposes": list(declared.required_purposes),
                }
            ),
            "trust.json": rfc8785.dumps(context),
            "request.json": rfc8785.dumps(
                {
                    "schema_id": REQUEST_SCHEMA_ID,
                    "request_id": request_id,
                    "acceptance": {
                        "captured": "at_this_launch",
                        "holds_for": "this_boot_only",
                        "boot_domain_ref": wire(sources.boot),
                    },
                    "records": {name: wire(reference) for name, reference in records.items()},
                }
            ),
        },
    )
    return report, SelfBoundRequest(request_id, policy, trust, MappingProxyType(records))
