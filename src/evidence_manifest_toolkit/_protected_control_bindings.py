# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exact independently selected control receipt correspondence

"""Match complete control inputs without authenticating a protected transition or key."""

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import cast

from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._errors import InputRefused, ReferenceUnavailable
from ._format_sources import FixedSource, acquire_fixed_source
from ._immutable import FrozenJson, freeze_json, thaw_json
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._subject_formats import SubjectFormat
from ._successor_envelopes import SuccessorEnvelope, parse_successor_envelope
from ._values import BlobRef, Digest, Reason

_TARGETS = {
    "authority_grant": "evidence_manifest_toolkit.authority_grant.v2",
    "issue_certificate": "evidence_manifest_toolkit.delegated_certificate.v2",
    "rotate_authority": "evidence_manifest_toolkit.authority_rotation.v2",
    "issue_snapshot": "evidence_manifest_toolkit.authority_snapshot.v2",
    "revoke_descendants": "evidence_manifest_toolkit.authority_snapshot.v2",
}


@dataclass(frozen=True, slots=True)
class ProtectedControlBinding:
    """Keep an entire selected operation and the actual corresponding source bodies.

    Attributes
    ----------
    entry : Mapping
        All original independently selected fields, detached without a scope projection.
    target, statement : FixedSource
        Entire actual native target and separately acquired whole statement source.
    envelope : SuccessorEnvelope
        Complete parsed native receipt and message, without a verified signature verdict.
    raw_envelope_digest : str
        SHA256 of the actual original supplied receipt bytes, not their JCS spelling.
    """

    entry: Mapping[str, FrozenJson]
    target: FixedSource
    statement: FixedSource
    envelope: SuccessorEnvelope
    raw_envelope_digest: Digest


def bind_protected_controls(
    selection: FixedSource,
    *,
    envelopes: tuple[bytes, ...],
    formats: Mapping[str, SubjectFormat],
    resolver: Resolver,
    budget: ReferenceBudget,
) -> tuple[ProtectedControlBinding, ...]:
    """Match the entire independently frozen population against actual ordered receipts.

    Parameters
    ----------
    selection : FixedSource
        Whole valid r6 selection; received receipt purposes never choose its operations.
    envelopes : tuple of bytes
        Complete explicitly supplied original control population, never store discovery.
    formats : Mapping
        Original structural lookup plus the fixed installed native definitions.
    resolver : Resolver
        Sole bounded original source for whole selected target and statement arguments.
    budget : ReferenceBudget
        SAME invocation quota, including all earlier policy and source acquisitions.

    Returns
    -------
    tuple of ProtectedControlBinding
        Actual whole source correspondences in original order. Empty means no supplied
        controls, not admitted bootstrap, protected state, signer or current authority.

    Raises
    ------
    InputRefused
        Original source/schema/metadata/quota or exact population/context/reference fails.
    ReferenceUnavailable
        An exact required original target or statement argument is unavailable.
    """
    subject = selection.source.reference.digest
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, selection.source.document).value)
    entries = cast(list[dict[str, JsonValue]], value["entries"])

    def refuse(pointer: str) -> InputRefused:
        """Locate an actual selected correspondence conflict without echoing source text."""
        return InputRefused(
            Reason(
                "scope_missing", subject, None, pointer, "Protected control selection conflicts."
            )
        )

    def fixed(reference: BlobRef, name: str, pointer: str) -> FixedSource:
        """Retain one entire known native source and its original typed failure."""
        source = acquire_fixed_source(
            reference,
            format_name=name,
            formats=formats,
            resolver=resolver,
            budget=budget,
            subject=subject,
            pointer=pointer,
        )
        if source.source.raw_bytes is None:
            raise ReferenceUnavailable(reference)
        if source.source.document is None:
            raise InputRefused(source.source.reasons[0])
        return source

    if len(entries) != len(envelopes):
        raise refuse("/entries")
    results: list[ProtectedControlBinding] = []
    seen: set[BlobRef] = set()
    for index, (entry, raw) in enumerate(zip(entries, envelopes, strict=True)):
        pointer = "/entries/" + str(index)
        envelope = parse_successor_envelope(raw, context="authority_control", budget=budget)
        raw_digest: Digest = "sha256:" + sha256(raw).hexdigest()
        if raw_digest != entry["envelope_digest"]:
            raise refuse(pointer + "/envelope_digest")
        if envelope.reference in seen:
            raise refuse(pointer + "/envelope_digest")
        seen.add(envelope.reference)
        declared = envelope.statement.value
        for field, actual, expected in (
            ("operation", declared["purpose"], entry["operation"]),
            ("signer_key_id", declared["signer_key_id"], entry["signer_key_id"]),
            *(
                (field, thaw_json(declared[field]), entry[field])
                for field in ("authorizing_state_ref", "authorization_ref", "scope_ref")
            ),
        ):
            if actual != expected:
                raise refuse(pointer + "/" + field)
        reference = decode_reference(
            entry["statement_ref"], subject=subject, pointer=pointer + "/statement_ref"
        )
        if reference != envelope.statement.reference:
            raise refuse(pointer + "/statement_ref")
        statement = fixed(
            reference, "evidence_manifest_toolkit.signed_statement.v2", pointer + "/statement_ref"
        )
        target_reference = decode_reference(
            entry["target_ref"], subject=subject, pointer=pointer + "/target_ref"
        )
        if (
            declared["content_schema_id"] != target_reference.schema_id
            or declared["content_digest"] != target_reference.digest
            or declared["content_byte_length"] != target_reference.byte_length
        ):
            raise refuse(pointer + "/target_ref")
        target = fixed(
            target_reference, _TARGETS[cast(str, entry["operation"])], pointer + "/target_ref"
        )
        results.append(
            ProtectedControlBinding(
                cast(Mapping[str, FrozenJson], freeze_json(entry)),
                target,
                statement,
                envelope,
                raw_digest,
            )
        )
    return tuple(results)
