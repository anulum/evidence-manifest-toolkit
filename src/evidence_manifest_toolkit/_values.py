# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — immutable common boundary values

"""Represent immutable byte identities, limits and located common refusals."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, cast

type DigestBasis = Literal["raw_bytes", "jcs_content"]
type Digest = str


class Utc(str):
    """Retain a parsed exact UTC token without clock, source or approval state.

    Parameters
    ----------
    raw : object
        Original string content; no coercion, repair, normalization or precision loss.

    Notes
    -----
    The constructor checks the entire Common-owned Gregorian/leap/full-fraction predicate.
    Clock source/controller/capture qualification remains an independent caller precondition.
    Inherited string equality preserves exact wire spelling; use compare for instant order.
    """

    __slots__ = ()

    def __new__(cls, raw: object) -> "Utc":
        """Validate original underlying string content before creating the immutable value.

        Parameters
        ----------
        raw : object
            Entire original string, including every fractional digit and T/t distinction.

        Returns
        -------
        Utc
            Exact unchanged validated token with no extra instance fields.

        Raises
        ------
        InputRefused
            Nonstring input or the original Common grammar/calendar/leap predicate refuses
            at the scalar root; no interpreter text or clock qualification is supplied.
        """
        from ._errors import InputRefused
        from ._utc import utc_key

        if not isinstance(raw, str):
            raise InputRefused(
                Reason("invalid_schema", None, None, "", "UTC value must be a string.")
            )
        token = str.__str__(raw)
        utc_key(token, pointer="")
        return str.__new__(cls, token)

    def compare(self, other: "Utc | str") -> Literal[-1, 0, 1]:
        """Compare two actual complete UTC instants without inherited lexical ordering.

        Parameters
        ----------
        other : Utc or str
            Entire original other token, independently revalidated at the scalar root.

        Returns
        -------
        {-1, 0, 1}
            Exact less/equal/greater order using Gregorian fields, full fractions and pinned
            leap history. Original spellings and string equality remain unchanged.

        Raises
        ------
        InputRefused
            Either actual operand is malformed, including a manually forged string subtype.
        """
        from ._utc import utc_key

        left = utc_key(Utc(self), pointer="")
        right = utc_key(Utc(other), pointer="")
        return -1 if left < right else 1 if left > right else 0


@dataclass(frozen=True, slots=True)
class BlobRef:
    """Describe the exact bytes identified by a content reference.

    Attributes
    ----------
    digest : str
        SHA-256 identity with its explicit algorithm prefix.
    byte_length : str
        Canonical nonnegative decimal length of the identified bytes.
    media_type : str
        Declared media type, retained without guessing from filenames.
    digest_basis : {"raw_bytes", "jcs_content"}
        Whether identity binds original bytes or admitted canonical content.
    schema_id : str or None
        Optional declared schema; omitted from the wire form when absent.
    """

    digest: Digest
    byte_length: str
    media_type: str
    digest_basis: DigestBasis
    schema_id: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "BlobRef":
        """Acquire a complete closed wire declaration without resolving or accepting it.

        Parameters
        ----------
        value : Mapping
            Entire stable four-field declaration with optional nonempty schema_id.
            A received explicit null schema_id is invalid; strings are never coerced.

        Returns
        -------
        BlobRef
            Independent immutable base value retaining exact strings and original basis.
            The declared identity, schema and media remain unverified.

        Raises
        ------
        InputRefused
            An ordinary malformed mapping/field yields the fixed invalid_schema reason
            with null subject/claim and the declaration's empty root pointer.
        """
        from ._codecs import decode_reference

        return decode_reference(value, subject=None, pointer="")

    def to_mapping(self) -> Mapping[str, str]:
        """Validate all stored fields and return a detached read-only wire declaration.

        Returns
        -------
        Mapping
            Four required exact strings plus schema_id only when stored nonnull.
            Every call returns a fresh read-only mapping without changing this value.

        Raises
        ------
        InputRefused
            An ordinary invalid manually constructed declaration fails the same full
            public field predicate; the constructor itself supplies no validation.
        """
        from ._codecs import decode_reference, reference_value

        checked = decode_reference(reference_value(self), subject=None, pointer="")
        return MappingProxyType(cast(dict[str, str], reference_value(checked)))


@dataclass(frozen=True, slots=True)
class Limits:
    """Carry all six explicit positive integer operation bounds.

    Attributes
    ----------
    max_json_bytes : int
        Maximum original JSON document byte length before decoding.
    max_blob_bytes : int
        Maximum size of an individual resolver read.
    max_total_reference_bytes : int
        Shared bound on bytes of unique referenced objects.
    max_reference_count : int
        Shared bound on distinct referenced object identities.
    max_graph_depth : int
        Maximum reference graph depth across all selected roots.
    max_json_depth : int
        Maximum container depth; a root container has depth one.
    """

    max_json_bytes: int
    max_blob_bytes: int
    max_total_reference_bytes: int
    max_reference_count: int
    max_graph_depth: int
    max_json_depth: int

    def validate(self) -> None:
        """Check all six declared bounds before a caller performs a source read.

        Returns
        -------
        None
            Every field is an exact positive Python integer. No bytes are allocated or read,
            no upper bound is inferred and the unvalidated constructor value is unchanged.
            Engine entrypoints independently perform the same checks.

        Raises
        ------
        ConfigurationError
            The first invalid field in the declared six-field order yields its exact
            /limits/name pointer and fixed positive-integer refusal. An untyped unbound
            call with a non-Limits object yields the same reason at /limits.
        """
        from ._json import validate_limits

        validate_limits(self)


@dataclass(frozen=True, slots=True)
class Reason:
    """Locate an actual common refusal without fabricating missing identity.

    Attributes
    ----------
    code : str
        Stable common refusal code.
    subject_digest : str or None
        Actual failed subject identity, if known.
    claim_id : str or None
        Actual affected claim, if applicable.
    pointer : str or None
        Literal JSON Pointer into the actual supplied subject or configuration.
    detail : str
        Fixed explanation without filenames, secrets or backend exceptions.
    """

    code: str
    subject_digest: Digest | None
    claim_id: str | None
    pointer: str | None
    detail: str
