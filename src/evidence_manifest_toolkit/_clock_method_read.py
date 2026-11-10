# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — bounded fixed Clock method source reader

"""Acquire complete method and provenance bytes under the original invocation budget."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import cast

from ._acquisition import acquire_reference, identity_reason
from ._budget import ReferenceBudget
from ._clock_method_types import ClockBoundDatum, ClockMethodRecord, ClockMethodSource
from ._clock_method_values import (
    CLOCK_POINTER,
    COMMON_FIELDS,
    check_method_header,
    method_configuration_refusal,
    method_integer,
    method_object,
)
from ._clock_values import clock_unavailable
from ._closure import ClosureRoot, traverse_closure
from ._codecs import decode_reference
from ._errors import InputRefused, ReferenceUnavailable
from ._immutable import FrozenJson, freeze_json
from ._interfaces import Resolver
from ._json import JsonValue, acquire_document
from ._subject_formats import SubjectFormat
from ._values import BlobRef, Digest, Reason


@dataclass(frozen=True, slots=True)
class ClockMethodReader:
    """Hold only the original explicit source dependencies for one invocation.

    Attributes
    ----------
    resolver : Resolver
        Original caller-owned source, with no discovery or fallback.
    budget : ReferenceBudget
        SAME already charged invocation budget for every model/source/dependency read.
    formats : Mapping
        Whole independently known public/fixed structural dispatch, without new formats.
    policy_subject : str
        Original policy identity for the prescribed Clock-unavailable diagnostic.
    """

    resolver: Resolver
    budget: ReferenceBudget
    formats: Mapping[str, SubjectFormat]
    policy_subject: Digest

    def read(self, reference: BlobRef, *, subject: Digest, pointer: str) -> ClockMethodSource:
        """Retain an entire actual source and any declared known-schema dependency graph.

        Parameters
        ----------
        reference : BlobRef
            Whole original declaration, including its actual basis and schema assertion.
        subject : str
            Actual containing source identity.
        pointer : str
            Actual field selecting these bytes.

        Returns
        -------
        ClockMethodSource
            Complete matching raw bytes and full declared structural graph when present.
            Matching supplies no independent calibration or physical support verdict.

        Raises
        ------
        ReferenceUnavailable
            An exact original root or required declared descendant is unavailable.
        InputRefused
            Original identity, metadata, schema, graph or cumulative bound fails.
        ConfigurationError
            The original resolver or independently known dispatch is invalid.
        """
        raw = acquire_reference(
            reference, resolver=self.resolver, budget=self.budget, subject=subject, pointer=pointer
        )
        failure = identity_reason(
            reference, raw, budget=self.budget, subject=subject, pointer=pointer
        )
        if failure is not None:
            raise InputRefused(failure)
        closure = None
        if reference.schema_id is not None:
            closure = traverse_closure(
                (ClosureRoot(reference, raw),),
                schemas=self.formats,
                resolver=self.resolver,
                budget=self.budget,
                requirements=(),
            )
            if closure.missing_references:
                raise ReferenceUnavailable(closure.missing_references[0])
            if closure.reasons:
                raise InputRefused(closure.reasons[0])
        return ClockMethodSource(reference, raw, closure)

    def field_source(self, value: JsonValue, *, subject: Digest, pointer: str) -> ClockMethodSource:
        """Decode and acquire one whole original source without repairing its declaration.

        Parameters
        ----------
        value : object
            Complete original reference value.
        subject : str
            Actual containing method identity.
        pointer : str
            Actual concrete field position.

        Returns
        -------
        ClockMethodSource
            Whole acquired identity/graph-checked source, with original typed failures.
        """
        return self.read(
            decode_reference(value, subject=subject, pointer=pointer),
            subject=subject,
            pointer=pointer,
        )

    def record(
        self,
        reference: BlobRef,
        *,
        parent_subject: Digest,
        pointer: str,
        method: str,
        units: str,
        fields: frozenset[str],
        expected: Mapping[str, JsonValue],
    ) -> ClockMethodRecord:
        """Read one complete known raw method and bind its entire common source context.

        Parameters
        ----------
        reference : BlobRef
            Original independently selected model or later use record.
        parent_subject : str
            Actual containing profile/witness identity for unsupported raw metadata.
        pointer : str
            Actual field in that containing source.
        method, units : str
            Fixed installed interpretation and dimensional units.
        fields : frozenset of str
            All specific mandatory fields, in addition to the common full population.
        expected : Mapping
            Whole actual class/host/controller/environment/boot/limitations source values.

        Returns
        -------
        ClockMethodRecord
            Full raw record and complete ordered common/provenance source edges.

        Raises
        ------
        ConfigurationError
            Raw method metadata or complete closed local grammar is invalid.
        InputRefused
            Original source/UTC/quota fails, or known method/common context is unsupported.
        ReferenceUnavailable
            Any actual required whole original source is absent.
        """
        if (
            reference.media_type != "application/json"
            or reference.digest_basis != "raw_bytes"
            or reference.schema_id is not None
        ):
            raise method_configuration_refusal(parent_subject, pointer)
        source = self.read(reference, subject=parent_subject, pointer=pointer)
        try:
            document = acquire_document(source.raw_bytes, limits=self.budget.limits)
        except InputRefused as error:
            original = error.reason
            raise InputRefused(
                Reason(
                    original.code,
                    reference.digest,
                    original.claim_id,
                    original.pointer,
                    original.detail,
                )
            ) from error
        value = method_object(
            document.value, COMMON_FIELDS | fields, subject=reference.digest, pointer=""
        )
        check_method_header(
            value,
            method=method,
            units=units,
            subject=reference.digest,
            policy_subject=self.policy_subject,
        )
        if any(value[name] != actual for name, actual in expected.items()):
            raise clock_unavailable(self.policy_subject, CLOCK_POINTER)
        evidence: list[tuple[str, ClockMethodSource]] = []
        for name in (
            "host_identity_ref",
            "controller_identity_ref",
            "implementation_environment_ref",
            "boot_domain_ref",
            "assumptions_and_limitations_ref",
        ):
            location = "/" + name
            evidence.append(
                (
                    location,
                    self.field_source(value[name], subject=reference.digest, pointer=location),
                )
            )
        refs = value["provenance_refs"]
        if not isinstance(refs, list) or not refs:
            raise method_configuration_refusal(reference.digest, "/provenance_refs")
        selected = tuple(
            decode_reference(
                item, subject=reference.digest, pointer="/provenance_refs/" + str(index)
            )
            for index, item in enumerate(refs)
        )
        if len(set(selected)) != len(selected):
            raise method_configuration_refusal(reference.digest, "/provenance_refs")
        evidence.extend(
            (
                "/provenance_refs/" + str(index),
                self.read(ref, subject=reference.digest, pointer="/provenance_refs/" + str(index)),
            )
            for index, ref in enumerate(selected)
        )
        return ClockMethodRecord(
            source, document, cast(Mapping[str, FrozenJson], freeze_json(value)), tuple(evidence)
        )

    def bounds(
        self, value: JsonValue, fields: frozenset[str], *, subject: Digest, pointer: str
    ) -> Mapping[str, ClockBoundDatum]:
        """Read every required explicit numerical term and its whole original source.

        Parameters
        ----------
        value : object
            Entire selected terms object, without missing-value defaults.
        fields : frozenset of str
            Complete fixed term population for this source context.
        subject : str
            Actual containing use-record identity.
        pointer : str
            Actual terms position in that record.

        Returns
        -------
        Mapping
            All immutable exact terms and full source bytes, without physical promotion.

        Raises
        ------
        ConfigurationError
            Complete object or bound field type is invalid.
        InputRefused
            Numeric mapping, original reference/schema/identity or cumulative quota fails.
        ReferenceUnavailable
            An exact original bound source is unavailable.
        """
        values = method_object(value, fields, subject=subject, pointer=pointer)
        result: dict[str, ClockBoundDatum] = {}
        for name, raw in values.items():
            location = pointer + "/" + name
            term = method_object(
                raw, frozenset({"bound_ns", "source_ref"}), subject=subject, pointer=location
            )
            number = method_integer(
                term["bound_ns"],
                subject=subject,
                policy_subject=self.policy_subject,
                pointer=location + "/bound_ns",
            )
            result[name] = ClockBoundDatum(
                number,
                self.field_source(
                    term["source_ref"], subject=subject, pointer=location + "/source_ref"
                ),
            )
        return MappingProxyType(result)
