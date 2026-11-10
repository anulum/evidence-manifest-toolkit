# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — whole independently selected native launch grammar

"""Select the exact known launch-record data source without adding a public schema."""

from typing import cast

from ._acquisition import acquire_reference
from ._budget import ReferenceBudget
from ._codecs import decode_reference
from ._format_sources import FixedSource
from ._interfaces import Resolver
from ._json import AcquiredDocument, JsonValue
from ._reference_paths import configuration_refusal
from ._schema_resources import parse_schema
from ._successor_formats import FixedFormat
from ._values import BlobRef

_RESOURCE = BlobRef(
    "sha256:f4dc21580f6961e84835dbf9dac3f0d5328a06e05a23ea73970d60130cc2fbee",
    "3619",
    "application/schema+json",
    "raw_bytes",
)


def native_launch_format(
    method: FixedSource, *, resolver: Resolver, budget: ReferenceBudget
) -> FixedFormat:
    """Read the whole fixed raw record grammar through the original source graph.

    Parameters
    ----------
    method : FixedSource
        Complete independently selected launcher/observer declaration after its original
        full graph checks. Presence establishes no method qualification or identity.
    resolver : Resolver
        Sole original bounded source; contract data never selects code or a filesystem path.
    budget : ReferenceBudget
        SAME cumulative invocation budget, reusing the actual earlier source bytes.

    Returns
    -------
    FixedFormat
        Whole exact known raw-launch grammar and no reference selectors. Native file
        SHA/size fields and pathnames are data, never invented full BlobRefs.

    Raises
    ------
    ConfigurationError
        The selected declaration supplies no known launcher contract or selects a
        different complete grammar. An observer requires its separate actual method.
    ReferenceUnavailable
        The original selected exact grammar source cannot be acquired.
    InputRefused
        Original metadata or cumulative source limits fail.
    """
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, method.source.document).value)
    if "record_contract_ref" not in value:
        raise configuration_refusal("/launcher_or_observer_procedure_ref")
    reference = decode_reference(
        value["record_contract_ref"],
        subject=method.source.reference.digest,
        pointer="/record_contract_ref",
    )
    if reference != _RESOURCE:
        raise configuration_refusal("/record_contract_ref")
    raw = acquire_reference(
        reference,
        resolver=resolver,
        budget=budget,
        subject=method.source.reference.digest,
        pointer="/record_contract_ref",
    )
    schema = parse_schema(raw, limits=budget.limits, pointer="/record_contract_ref")
    return FixedFormat(schema, schema, (), None, "native-launch-record-source")
