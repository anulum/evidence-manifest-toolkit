# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete explicitly declared static dependency closure

"""Follow selected schema dependency declarations without making unused sources available."""

from ._budget import ReferenceBudget
from ._errors import InputRefused
from ._reference_paths import configuration_refusal
from ._registry_types import RegistryEntry, SchemaDependency
from ._values import Reason


def schema_dependency_closure(
    entry: RegistryEntry,
    *,
    entries: tuple[RegistryEntry, ...],
    budget: ReferenceBudget,
    pointer: str,
) -> tuple[SchemaDependency, ...]:
    """Retain exact reachable direct/transitive pins in their first-seen declaration order.

    Parameters
    ----------
    entry : RegistryEntry
        Actual root schema and its original declared direct pins.
    entries : tuple of RegistryEntry
        Whole independently validated source catalogue; its unused bodies are not
        implicit dependencies. A reached resource may use its own explicit declarations.
    budget : ReferenceBudget
        SAME operation bounds; physical resources and every declaration's metadata
        have already been acquired/checked by the caller's complete catalogue pass.
    pointer : str
        Actual root entry position for ambiguous resource/depth diagnostics.

    Returns
    -------
    tuple of SchemaDependency
        Complete finite offline resource set. Original caller entries/declared edges
        are unchanged; only repeated identical resource URI bindings deduplicate.

    Raises
    ------
    ConfigurationError
        A reachable URI has contradictory pins or a reached source has ambiguous
        selected dependency declarations. No global URI alias or fallback is inferred.
    InputRefused
        Actual distinct dependency nesting exceeds the existing graph-depth bound.
    """
    owners: dict[str, list[RegistryEntry]] = {}
    for candidate in entries:
        owners.setdefault(candidate.schema_ref.digest, []).append(candidate)
    selected: dict[str, SchemaDependency] = {}
    pending = [(dependency, 1) for dependency in reversed(entry.schema_dependencies)]
    while pending:
        dependency, depth = pending.pop()
        previous = selected.get(dependency.uri)
        if previous is not None:
            before, after = previous.schema_ref, dependency.schema_ref
            if (before.digest, before.digest_basis, before.byte_length, before.media_type) != (
                after.digest,
                after.digest_basis,
                after.byte_length,
                after.media_type,
            ):
                raise configuration_refusal(pointer + "/schema_dependencies")
            continue
        if depth > budget.limits.max_graph_depth:
            raise InputRefused(
                Reason(
                    "limit_exceeded",
                    entry.schema_ref.digest,
                    None,
                    pointer + "/schema_dependencies",
                    "Reference graph depth bound exceeded.",
                )
            )
        selected[dependency.uri] = dependency
        candidates = owners.get(dependency.schema_ref.digest, [])
        if candidates:
            children = candidates[0].schema_dependencies
            if any(candidate.schema_dependencies != children for candidate in candidates[1:]):
                raise configuration_refusal(pointer + "/schema_dependencies")
            pending.extend((child, depth + 1) for child in reversed(children))
    return tuple(selected.values())
