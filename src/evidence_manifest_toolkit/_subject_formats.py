# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit structural format and metadata selection

"""Keep independently selected private formats separate from reference schema assertions."""

from collections.abc import Mapping

from ._json import AcquiredDocument
from ._schema_resources import StaticSchema
from ._successor_formats import FixedFormat
from ._values import BlobRef, Digest, Reason

type SubjectFormat = StaticSchema | FixedFormat


def select_subject_format(
    name: str, *, formats: Mapping[str, SubjectFormat], explicit_format: bool
) -> SubjectFormat | None:
    """Select known structural data without interpreting a private token as a public ID.

    Parameters
    ----------
    name : str
        Exact already selected format or actual reference schema assertion.
    formats : Mapping
        Independently supplied caller schemas and installed fixed formats, without
        modifying the caller registry or inferring URI-prefix aliases.
    explicit_format : bool
        True only when the owning method independently selects a fixed format.

    Returns
    -------
    StaticSchema or FixedFormat or None
        Actual selected structural binding. Private formats require explicit context;
        a received schema_id alone cannot select their source interpretation.
    """
    selected = formats.get(name)
    if isinstance(selected, FixedFormat) and selected.name != name:
        return None
    if explicit_format:
        return selected if isinstance(selected, FixedFormat) else None
    if isinstance(selected, FixedFormat) and selected.schema_id is None:
        return None
    return selected


def subject_format_reasons(
    selected: SubjectFormat,
    document: AcquiredDocument,
    reference: BlobRef,
    *,
    formats: Mapping[str, SubjectFormat],
    subject: Digest,
    pointer: str,
    expected_schema_id: str | None = None,
) -> tuple[Reason, ...]:
    """Check complete format shape and every actual independently meaningful schema assertion.

    Parameters
    ----------
    selected : StaticSchema or FixedFormat
        Exact independent structural binding, never an artifact-selected executable.
    document : AcquiredDocument
        Whole identity-matching strict source with original numeric custody.
    reference : BlobRef
        Original complete argument; omitted metadata remains omitted.
    formats : Mapping
        Known caller schemas and fixed native/private bindings.
    subject : str
        Containing reference identity for metadata diagnostics; body errors retain
        their actual target reference digest.
    pointer : str
        Actual containing reference position.
    expected_schema_id : str or None
        Independently selected public native context, separate from a private format.

    Returns
    -------
    tuple of Reason
        Whole shape and metadata refusals. Structural validity supplies no authority,
        Clock, identity, validation, domain or current-use qualification.
    """
    failures = selected.reasons(document.value, subject=reference.digest)
    if failures or isinstance(selected, StaticSchema):
        return failures
    expected = expected_schema_id or selected.schema_id
    if (expected_schema_id is not None and expected_schema_id != selected.schema_id) or (
        expected is not None and reference.schema_id not in (None, expected)
    ):
        return (
            Reason(
                "invalid_schema",
                subject,
                None,
                pointer,
                "Declared schema conflicts with its independently selected native context.",
            ),
        )
    if selected.schema_id is None and reference.schema_id is not None:
        advertised = formats.get(reference.schema_id)
        if not isinstance(advertised, StaticSchema):
            return (
                Reason("unknown_schema", subject, None, pointer, "Selected schema is not known."),
            )
        return advertised.reasons(document.value, subject=reference.digest)
    return ()
