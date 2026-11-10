# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — entire earlier and final Clock policy reconstruction

"""Bind complete operational policies while changing only the actual Clock witness slot."""

from typing import cast

from ._clock_values import clock_unavailable
from ._codecs import reference_value
from ._immutable import thaw_json
from ._json import AcquiredDocument, JsonValue
from ._policy_literals import CLOCK_FIELD
from ._policy_source import PolicyDeclaration, parse_policy_source
from ._values import BlobRef, Digest


def bind_clock_policies(
    base: AcquiredDocument,
    final: AcquiredDocument,
    *,
    witness_reference: BlobRef,
    subject: Digest,
) -> PolicyDeclaration:
    """Reconstruct the whole final policy from the earlier explicit-null base.

    Parameters
    ----------
    base, final : AcquiredDocument
        Entire independently acquired identity-matching original policies, retaining
        every field, string, array order and source token. The base precedes the witness.
    witness_reference : BlobRef
        Complete actual selected witness; absent schema metadata is not manufactured.
    subject : str
        Whole enclosing invocation policy identity for the original Clock refusal.

    Returns
    -------
    PolicyDeclaration
        Entire earlier parsed operational declaration. Equality establishes only this
        acyclic policy relation, not Clock/source/authority/current admission.

    Raises
    ------
    ConfigurationError
        Either full source violates the original closed policy contract.
    InputRefused
        The earlier slot is absent/non-null, a fixture replaces the operational policy,
        the selected witness differs, or any other whole final field changes.
    """
    earlier = parse_policy_source(base)
    later = parse_policy_source(final)
    pointer = "/" + CLOCK_FIELD + "/clock_qualification_ref"
    if (
        earlier.namespace != "operational"
        or later.namespace != "operational"
        or not earlier.requires_clock
        or earlier.clock_reference is not None
        or later.clock_reference != witness_reference
    ):
        raise clock_unavailable(subject, pointer)
    reconstructed = cast(dict[str, JsonValue], thaw_json(earlier.declaration))
    clock = cast(dict[str, JsonValue], reconstructed[CLOCK_FIELD])
    clock["clock_qualification_ref"] = reference_value(witness_reference)
    if reconstructed != thaw_json(later.declaration):
        raise clock_unavailable(subject, pointer)
    return earlier
