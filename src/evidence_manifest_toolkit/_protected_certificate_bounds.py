# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete native certificate source bounds

"""Check whole declared parent bounds without admitting a native certificate or issuer."""

from typing import cast

from ._codecs import decode_reference
from ._format_sources import FixedSource
from ._json import AcquiredDocument, JsonValue
from ._protected_state_history import protected_source_conflict
from ._values import Utc

_GRANT = "evidence_manifest_toolkit.authority_grant.v2"
_CERTIFICATE = "evidence_manifest_toolkit.delegated_certificate.v2"
_SCOPE_FIELDS = ("group_ids", "principal_ids", "roles", "tool_segments", "permitted_operations")
_ORDINARY_OPERATIONS = frozenset(("evidence", "deployment", "human_review"))


def check_certificate_source_parent_bounds(child: FixedSource, *, parent: FixedSource) -> None:
    """Compare complete native declarations against the entire exact selected parent.

    Parameters
    ----------
    child : FixedSource
        Whole already acquired, identity-matching and structurally validated native
        delegated certificate. Its original bytes and every field remain retained.
    parent : FixedSource
        Whole independently resolved parent grant or certificate under its exact native
        format. Acquisition, schema, quotas and source-history checks precede this call.

    Returns
    -------
    None
        Necessary whole reference, stream, depth, scope and finite-window consistency.
        This does not admit root, parent, subject, issuer, key, custody or positive state.

    Raises
    ------
    InputRefused
        Exact native class, parent reference, stream, depth, scope or window conflicts.
        Original source bodies remain intact and received text is not echoed.

    Notes
    -----
    Complete chain traversal must call this check for every actual parent edge while
    preserving the independently selected grant and original graph bounds. A grant's
    until_withdrawal upper bound is explicitly absent here, not accepted infinity:
    actual owner approval, current withdrawal and the full Clock/native law still apply.
    Issuer eligibility is selected from the earlier admitted authorizing state, including
    actual rotations. Grant.initial_issuer_key_id is not a permanent issuer shortcut.
    """
    subject = child.source.reference.digest
    if child.format.name != _CERTIFICATE or parent.format.name not in (_GRANT, _CERTIFICATE):
        raise protected_source_conflict(subject, "/parent_authorization_ref")
    value = cast(dict[str, JsonValue], cast(AcquiredDocument, child.source.document).value)
    ancestor = cast(dict[str, JsonValue], cast(AcquiredDocument, parent.source.document).value)
    reference = decode_reference(
        value["parent_authorization_ref"], subject=subject, pointer="/parent_authorization_ref"
    )
    if reference != parent.source.reference:
        raise protected_source_conflict(subject, "/parent_authorization_ref")
    if value["authority_id"] != ancestor["authority_id"]:
        raise protected_source_conflict(subject, "/authority_id")
    depth = int(cast(str, value["remaining_path_length"]))
    parent_depth = int(cast(str, ancestor["remaining_path_length"]))
    if depth >= parent_depth:
        raise protected_source_conflict(subject, "/remaining_path_length")
    scope = cast(dict[str, JsonValue], value["scope"])
    parent_scope = cast(dict[str, JsonValue], ancestor["scope"])
    if "issue_certificate" not in cast(list[str], parent_scope["permitted_operations"]):
        raise protected_source_conflict(subject, "/parent_authorization_ref")
    for name in _SCOPE_FIELDS:
        if not set(cast(list[str], scope[name])) <= set(cast(list[str], parent_scope[name])):
            raise protected_source_conflict(subject, "/scope/" + name)
    if (
        depth == 0
        and not set(cast(list[str], scope["permitted_operations"])) <= _ORDINARY_OPERATIONS
    ):
        raise protected_source_conflict(subject, "/scope/permitted_operations")
    lower, upper = Utc(value["not_before"]), Utc(value["not_after"])
    if lower.compare(upper) >= 0:
        raise protected_source_conflict(subject, "/not_after")
    if parent.format.name == _GRANT:
        lifetime = cast(dict[str, JsonValue], ancestor["lifetime"])
        parent_lower = Utc(lifetime["not_before"])
        parent_upper = Utc(lifetime["not_after"]) if lifetime["kind"] == "finite" else None
        parent_pointer = "/lifetime/not_after"
    else:
        parent_lower = Utc(ancestor["not_before"])
        parent_upper = Utc(ancestor["not_after"])
        parent_pointer = "/not_after"
    if parent_upper is not None and parent_lower.compare(parent_upper) >= 0:
        raise protected_source_conflict(parent.source.reference.digest, parent_pointer)
    if lower.compare(parent_lower) < 0:
        raise protected_source_conflict(subject, "/not_before")
    if parent_upper is not None and upper.compare(parent_upper) > 0:
        raise protected_source_conflict(subject, "/not_after")
