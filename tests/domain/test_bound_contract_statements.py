# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the three bound behaviours the public operation contract states

"""Pin what the contract states about bounds: their order, a registry outside them, an exhausted count.

The public operation contract states three rules and leaves two forms unstated. These cases pin
the rules only: an invalid bound is named before any other invalid argument; a registry schema
that a document bound refuses is a configuration error under ``/registry/entries``; an exhausted
reference count is a ``limit_exceeded`` refusal and never a success. Whether that refusal is
raised or reported, and how deep the configuration pointer reaches, are deliberately not pinned.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, replace
from typing import cast

import pytest
from tests.domain.test_public_operation_surface import (
    _DOCUMENT,
    _OPERATIONS,
    _VALID,
    _sealing_arguments,
    _verification_arguments,
)
from tests.domain.test_verification_report_sources import _FileResolver

import evidence_manifest_toolkit as toolkit
from evidence_manifest_toolkit import (
    ConfigurationError,
    EmtError,
    InputRefused,
    Limits,
    SchemaRegistry,
    VerificationReport,
)

_NOT_JSON = b"{"
_UNKNOWN_SCHEMA = "urn:emt:not-in-the-registry"
# The count the whole verification fixture needs: its eight registry schemas, the nine objects
# an unbounded run reads and the content itself; the bounds unit derives and pins the same 18.
_NEEDED_COUNT = 18
_COUNT_DETAIL = "Reference count bound exceeded."


def _with_another_invalid_argument(
    operation: str,
) -> tuple[Callable[[Limits], object], _FileResolver | None]:
    """Return one operation bound to arguments of which exactly one, other than the bounds, is invalid.

    Parameters
    ----------
    operation : str
        One of the six exported operation names.

    Returns
    -------
    tuple
        A callable taking the bounds, and the resolver whose calls it records, for the two
        operations that read references.
    """
    function = cast(Callable[..., object], getattr(toolkit, operation))
    if operation in ("canonicalize_json", "inspect"):
        return lambda limits: function(_NOT_JSON, limits=limits), None
    if operation == "diff":
        return lambda limits: function(_NOT_JSON, _NOT_JSON, limits=limits), None
    if operation == "reference_bytes":
        return (
            lambda limits: function(
                _DOCUMENT,
                media_type="application/json",
                digest_basis="not_a_basis",
                schema_id=None,
                limits=limits,
            ),
            None,
        )
    content, keywords, resolver = (
        _sealing_arguments() if operation == "seal" else _verification_arguments()
    )
    keywords = {**keywords, "schema_id": _UNKNOWN_SCHEMA}
    return lambda limits: function(content, **keywords, limits=limits), resolver


@pytest.mark.parametrize("operation", _OPERATIONS)
def test_an_invalid_bound_is_named_before_another_invalid_argument(operation: str) -> None:
    """Content that is not JSON, an unknown basis or schema yields to an invalid bound, and nothing is read.

    Parameters
    ----------
    operation : str
        One of the six exported operation names.

    Notes
    -----
    With valid bounds the same call is refused for its other argument (raised, or for verify
    returned as a refused report), so that argument is really invalid; with the first bound at
    zero the refusal names that bound instead.
    """
    call, _ = _with_another_invalid_argument(operation)
    try:
        result = call(_VALID)
    except EmtError as other:
        pointer = other.reason.pointer
        assert pointer is None or not pointer.startswith("/limits")
    else:
        assert isinstance(result, VerificationReport)
        assert result.common_eligibility == "refused"
    call, resolver = _with_another_invalid_argument(operation)
    with pytest.raises(ConfigurationError) as caught:
        call(replace(_VALID, max_json_bytes=0))
    assert asdict(caught.value.reason) == {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": "/limits/max_json_bytes",
        "detail": "Limits require positive integers.",
    }
    assert resolver is None or resolver.calls == []


def _largest_schema(registry: SchemaRegistry) -> int:
    """Return the length in bytes of the registry's largest schema.

    Parameters
    ----------
    registry : SchemaRegistry
        The fixture's registry.

    Returns
    -------
    int
        The largest schema's byte length.
    """
    return max(len(entry.schema_bytes) for entry in registry.entries)


@pytest.mark.parametrize("bound", ("max_json_bytes", "max_json_depth"))
@pytest.mark.parametrize("operation", ("seal", "verify"))
def test_a_registry_schema_outside_a_document_bound_is_a_configuration_error(
    operation: str, bound: str
) -> None:
    """The caller's bounds and registry disagree: configuration, not a limit on evidence.

    Parameters
    ----------
    operation : str
        Construction or verification; both validate the registry under the caller's bounds.
    bound : str
        A document bound set one below what a schema the registry validation parses needs.

    Notes
    -----
    The size bound is set one byte below the largest entry schema, which still admits the
    content; the depth bound one level below 14, the depth of the toolkit's own registry schema,
    which is met first. Only the code and the ``/registry/entries`` prefix are pinned; how far
    the pointer reaches is not stated.
    """
    content, keywords, _ = (
        _sealing_arguments() if operation == "seal" else _verification_arguments()
    )
    registry = keywords["registry"]
    assert isinstance(registry, SchemaRegistry)
    value = _largest_schema(registry) - 1 if bound == "max_json_bytes" else 13
    if bound == "max_json_bytes":
        assert len(content) <= value
    call = cast(Callable[..., object], getattr(toolkit, operation))
    with pytest.raises(ConfigurationError) as caught:
        call(content, **keywords, limits=replace(_VALID, **{bound: value}))
    reason = caught.value.reason
    assert reason.code == "configuration_error"
    assert reason.pointer is not None and reason.pointer.startswith("/registry/entries")
    assert reason.detail == "Invalid local configuration."


@pytest.mark.parametrize("short", (1, 2, 3, 4))
def test_an_exhausted_reference_count_is_refused_and_never_succeeds(short: int) -> None:
    """Below the count the fixture needs, verification refuses with the count's own reason.

    Parameters
    ----------
    short : int
        How many identities below the needed count the bound is set.

    Notes
    -----
    Raised or reported, the refusal is ``limit_exceeded`` with the count's detail; a report
    carries it among its reasons and is refused. Which form a given shortfall takes depends on
    the acquisition that meets the bound, and is not pinned.
    """
    content, keywords, _ = _verification_arguments()
    verify = cast(Callable[..., VerificationReport], toolkit.verify)
    limits = replace(_VALID, max_reference_count=_NEEDED_COUNT - short)
    try:
        report = verify(content, **keywords, limits=limits)
    except InputRefused as refused:
        assert refused.reason.code == "limit_exceeded"
        assert refused.reason.detail == _COUNT_DETAIL
    else:
        assert report.common_eligibility == "refused"
        assert any(
            reason.code == "limit_exceeded" and reason.detail == _COUNT_DETAIL
            for reason in report.reasons
        )
