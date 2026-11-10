# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — definitive whole policy-bound successor content

"""Retain complete current typed content with its original independently selected scope."""

from collections.abc import Mapping

from ._budget import ReferenceBudget
from ._content import CompleteContent, prepare_content
from ._format_sources import native_format_lookup
from ._interfaces import Resolver
from ._reproduction_history import ReproductionHistory
from ._schema_resources import StaticSchema
from ._trust_types import VerificationPolicy


def prepare_successor_content(
    content_json: bytes,
    *,
    schema_id: str,
    schemas: Mapping[str, StaticSchema],
    history: ReproductionHistory | None,
    resolver: Resolver,
    budget: ReferenceBudget,
    policy: VerificationPolicy,
) -> CompleteContent:
    """Check the whole current source with actual native roots and original policy paths.

    Parameters
    ----------
    content_json : bytes
        Entire original invocation bytes, preserving original numeric source custody.
    schema_id : str
        Original independent caller selection.
    schemas : Mapping
        Complete original compiled caller catalogue, without added registry entries.
    history : ReproductionHistory or None
        Whole actually selected earlier source graph; None selects no history roots.
    resolver : Resolver
        Sole original bounded source without discovery or fallback.
    budget : ReferenceBudget
        SAME invocation allowance and cache, including every earlier source acquisition.
    policy : VerificationPolicy
        Entire original required reference-path population; no projected scope substitute.

    Returns
    -------
    CompleteContent
        Definitive entire typed closure/common observations and actual reasons. This
        data alone supplies no authority, Clock, independent execution or class admission.

    Raises
    ------
    InputRefused
        Original whole content, source or operation bounds cannot be represented.
    ConfigurationError
        Original independently selected static/native configuration is unavailable.
    """
    return prepare_content(
        content_json,
        schema_id=schema_id,
        schemas=schemas,
        resolver=resolver,
        budget=budget,
        requirements=policy.required_reference_paths,
        formats=native_format_lookup(schemas, budget=budget),
        additional_roots=() if history is None else history.roots,
    )
