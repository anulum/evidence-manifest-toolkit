# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole conditional Clock method data

"""Keep declared numerical inputs, actual source bytes and physical qualification distinct."""

from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction

from ._closure import ClosureResult
from ._immutable import FrozenJson
from ._json import AcquiredDocument
from ._values import BlobRef


@dataclass(frozen=True, slots=True)
class ClockMethodSource:
    """Retain a whole original source without interpreting its presence as model support.

    Attributes
    ----------
    reference : BlobRef
        Entire selected original declaration, without repaired metadata or basis.
    raw_bytes : bytes
        Complete matching bounded bytes, not a projection of a calibration or model.
    closure : ClosureResult or None
        Complete independently known public-schema graph when a schema was declared;
        None only for a raw source with no such assertion, not a successful verdict.
    """

    reference: BlobRef
    raw_bytes: bytes
    closure: ClosureResult | None


@dataclass(frozen=True, slots=True)
class ClockBoundDatum:
    """Retain an explicit nonnegative numerical declaration and its actual whole source.

    Attributes
    ----------
    nanoseconds : int
        Exact canonical supplied integer, with no missing-value or zero default.
        Numerical consistency does not establish an independently supported bound.
    source : ClockMethodSource
        Entire original provenance source, still requiring actual method/model admission.
    """

    nanoseconds: int
    source: ClockMethodSource


@dataclass(frozen=True, slots=True)
class ClockMethodRecord:
    """Keep the entire fixed raw record and every selected evidence edge in source order.

    Attributes
    ----------
    source : ClockMethodSource
        Whole original raw method record; it has no public evidence schema.
    document : AcquiredDocument
        Entire strict parsed body and original numeric tokens.
    declaration : Mapping
        Full immutable closed record, without a producer acceptance Boolean.
    evidence : tuple
        Every concrete field pointer and actual selected source, including repeated
        targets under distinct fields. Cached reads do not erase those edges.
    """

    source: ClockMethodSource
    document: AcquiredDocument
    declaration: Mapping[str, FrozenJson]
    evidence: tuple[tuple[str, ClockMethodSource], ...]


@dataclass(frozen=True, slots=True)
class ClockAcceptanceInputs:
    """Retain the complete original annual derivation separately from invocation inputs.

    Attributes
    ----------
    record : ClockMethodRecord
        Entire selected raw annual method with its actual original source edges.
        It has no backward acceptance/profile/future invocation reference.
    raw_samples, ntp_sources : tuple of ClockMethodSource
        Explicitly associated original before/after captures and packet observations.
        Repeated byte targets retain both actual selecting field edges.
    before_bounds, after_bounds : Mapping
        All six terms for each ORIGINAL annual sample, never later invocation bounds.
    measured_offset_source : ClockMethodSource
        Exact selected original exchange associated with measured_ntp_offset_ns.
        Its source selection never waives either complete sample calculation.
    """

    record: ClockMethodRecord
    raw_samples: tuple[ClockMethodSource, ClockMethodSource]
    ntp_sources: tuple[ClockMethodSource, ClockMethodSource]
    before_bounds: Mapping[str, ClockBoundDatum]
    after_bounds: Mapping[str, ClockBoundDatum]
    measured_offset_source: ClockMethodSource


@dataclass(frozen=True, slots=True)
class ClockMethodInputs:
    """Retain all three whole method records and complete conditional arithmetic inputs.

    Attributes
    ----------
    uncertainty, drift, use : ClockMethodRecord
        Entire independently selected earlier models and later invocation derivation.
        The later record contains no future witness, final policy or native E.
    maximum_error_rate : Fraction
        Exact finite nonnegative declared nanosecond error per elapsed nanosecond.
        Source/model/calibration qualification remains a separate owning predicate.
    before_bounds, after_bounds : Mapping
        All six source-encoding/holdover/adjustment/acquisition/mapping/quantization terms.
    use_terms, entry_terms : Mapping
        All four acquisition/mapping/quantization/adjustment terms, without defaults.
    acceptance : ClockAcceptanceInputs
        Whole original annual associations, six-term derivations and all raw sources.
        This remains distinct from the later request-bound before/after/use records.
    """

    uncertainty: ClockMethodRecord
    drift: ClockMethodRecord
    use: ClockMethodRecord
    maximum_error_rate: Fraction
    before_bounds: Mapping[str, ClockBoundDatum]
    after_bounds: Mapping[str, ClockBoundDatum]
    use_terms: Mapping[str, ClockBoundDatum]
    entry_terms: Mapping[str, ClockBoundDatum]
    acceptance: ClockAcceptanceInputs
