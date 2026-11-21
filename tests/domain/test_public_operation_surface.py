# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — exported names, six operations and their explicit bounds

"""Pin the public surface: its names, its six operations and their required bounds."""

import ast
import hashlib
import inspect as signatures
import json
from collections.abc import Callable
from dataclasses import asdict, replace
from pathlib import Path
from types import ModuleType
from typing import Literal, cast

import pytest
from tests.domain.test_cli_evidence_sources import _source
from tests.domain.test_verification_report_sources import (
    _array,
    _bytes,
    _FileResolver,
    _mapping,
    _object,
    _optional_reference,
    _registry,
    _text,
)

import evidence_manifest_toolkit as toolkit
from evidence_manifest_toolkit import (
    BlobRef,
    ConfigurationError,
    Difference,
    Inspection,
    Limits,
    TrustContext,
    Utc,
    VerificationPolicy,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"

_EXPORTED = (
    "BlobRef",
    "ConfigurationError",
    "DelegatedTrustContextV2",
    "Difference",
    "Digest",
    "DigestBasis",
    "EmtError",
    "Envelope",
    "InputRefused",
    "Inspection",
    "Limits",
    "PathStep",
    "Reason",
    "ReferenceObservation",
    "ReferencePath",
    "ReferenceRequirement",
    "ReferenceUnavailable",
    "RegistryEntry",
    "Resolver",
    "SchemaDependency",
    "SchemaRegistry",
    "SealResult",
    "Signer",
    "SignerConfig",
    "SignerUnavailable",
    "SigningRequest",
    "SoftwareTrustContextV2",
    "StorageError",
    "TrustContext",
    "UnsignedTrustContextV2",
    "Utc",
    "VerificationPolicy",
    "VerificationReport",
    "canonicalize_json",
    "diff",
    "inspect",
    "reference_bytes",
    "seal",
    "verify",
)
_OPERATIONS = ("canonicalize_json", "diff", "inspect", "reference_bytes", "seal", "verify")
_OWNERS = {
    "canonicalize_json": "_json",
    "diff": "_difference",
    "inspect": "_inspection",
    "reference_bytes": "_references",
    "seal": "_sealing",
    "verify": "_verification",
}
_FIELDS = (
    "max_json_bytes",
    "max_blob_bytes",
    "max_total_reference_bytes",
    "max_reference_count",
    "max_graph_depth",
    "max_json_depth",
)
_VALID = Limits(1048576, 1048576, 16777216, 1024, 32, 64)
_DOCUMENT = b'{"a":[1,2]}'


def _sealing_arguments() -> tuple[bytes, dict[str, object], _FileResolver]:
    """Return the whole unsigned sealing fixture as the arguments of the public operation.

    Returns
    -------
    tuple
        Original content bytes, every keyword argument except the bounds, and the real
        file resolver over the fixture's complete object population.
    """
    packet = _object(json.loads((_FIXTURES / "seal-unsigned-whole-fixture.json").read_bytes()))
    inputs = _object(packet["complete_library_inputs"])
    resolver = _FileResolver(
        {
            key: _FIXTURES / "objects" / _text(_object(member)["sha256"])
            for key, member in _object(inputs["resolver_input_population"]).items()
        }
    )
    keywords: dict[str, object] = {
        "schema_id": _text(inputs["schema_id"]),
        "registry": _registry(inputs["registry"]),
        "resolver": resolver,
    }
    return _bytes(inputs["content_json"]), keywords, resolver


def _verification_arguments() -> tuple[bytes, dict[str, object], _FileResolver]:
    """Return the whole current verification fixture as the arguments of the public operation.

    Returns
    -------
    tuple
        Original content bytes, every keyword argument except the bounds, and the real
        file resolver over the fixture's complete object population.
    """
    inputs = _object(_source("verify-current-whole-fixture")["complete_library_inputs"])
    declared = _object(inputs["policy"])
    local = _object(inputs["trust"])
    resolver = _FileResolver(
        {
            key: _FIXTURES / "objects" / _text(_object(member)["sha256"])
            for key, member in _object(inputs["resolver_input_population"]).items()
        }
    )
    keywords: dict[str, object] = {
        "schema_id": _text(inputs["schema_id"]),
        "envelopes": tuple(_bytes(value) for value in _array(inputs["envelopes"])),
        "registry": _registry(inputs["registry"]),
        "resolver": resolver,
        "policy": VerificationPolicy(
            BlobRef.from_mapping(_object(declared["policy_ref"])),
            tuple(_text(value) for value in _array(declared["required_claim_ids"])),
            ("evidence",),
        ),
        "trust": TrustContext(
            BlobRef.from_mapping(_object(local["bootstrap_policy_ref"])),
            BlobRef.from_mapping(_object(local["current_snapshot_ref"])),
            _text(local["accepted_sequence_floor"]),
            cast(Literal["current", "historical"], _text(local["evaluation_mode"])),
            Utc(local["evaluation_time"]),
            tuple(_bytes(value) for value in _array(local["control_envelopes"])),
            _optional_reference(local.get("archived_snapshot_ref")),
        ),
    }
    return _bytes(inputs["content_json"]), keywords, resolver


def _call(operation: str) -> tuple[Callable[..., object], _FileResolver | None]:
    """Return one public operation bound to valid arguments, lacking only its bounds.

    Parameters
    ----------
    operation : str
        One of the six exported operation names.

    Returns
    -------
    tuple
        A callable that takes the bounds as keyword arguments (or none at all), and the
        resolver whose calls it records, for the two operations that read references.
    """
    function = cast(Callable[..., object], getattr(toolkit, operation))
    if operation in ("canonicalize_json", "inspect"):
        return lambda **bounds: function(_DOCUMENT, **bounds), None
    if operation == "diff":
        return lambda **bounds: function(_DOCUMENT, _DOCUMENT, **bounds), None
    if operation == "reference_bytes":
        return (
            lambda **bounds: function(
                _DOCUMENT,
                media_type="application/json",
                digest_basis="raw_bytes",
                schema_id=None,
                **bounds,
            ),
            None,
        )
    content, keywords, resolver = (
        _sealing_arguments() if operation == "seal" else _verification_arguments()
    )
    return lambda **bounds: function(content, **keywords, **bounds), resolver


def test_the_exported_names_are_the_pinned_thirty_nine() -> None:
    """A name added to or removed from the package is a visible change of this list.

    Notes
    -----
    An imported submodule becomes an attribute of the package; it is not an export. The only
    public submodule is ``self_bound``, whose own surface ``test_self_bound_surface`` pins.
    """
    assert tuple(toolkit.__all__) == _EXPORTED
    assert len(set(_EXPORTED)) == 39
    assert all(hasattr(toolkit, name) for name in _EXPORTED)
    attributes = {name: value for name, value in vars(toolkit).items() if not name.startswith("_")}
    public = {name for name, value in attributes.items() if not isinstance(value, ModuleType)}
    assert public == set(_EXPORTED)
    assert {name for name, value in attributes.items() if isinstance(value, ModuleType)} <= {
        "self_bound"
    }
    assert toolkit.__file__ is not None
    package = Path(toolkit.__file__).parent
    assert sorted(path.stem for path in package.glob("[!_]*.py")) == ["self_bound"]


def test_the_operations_are_the_six_functions() -> None:
    """Six exported names are functions; a seventh operation would change this set."""
    functions = {name for name in _EXPORTED if signatures.isfunction(getattr(toolkit, name))}
    assert functions == set(_OPERATIONS)


def test_each_operation_is_defined_once_in_the_package_and_exported_from_its_owner() -> None:
    """No module of the package holds a second function under the name of an operation.

    Notes
    -----
    Every source file of the package is parsed; a module-level function named as one of the
    six operations may occur in its owning module only, and the exported object is that
    function. A copy under another name is not seen by this test.
    """
    assert toolkit.__file__ is not None
    modules = sorted(Path(toolkit.__file__).parent.rglob("*.py"))
    assert len(modules) > len(_OPERATIONS)
    defined: dict[str, list[str]] = {name: [] for name in _OPERATIONS}
    for module in modules:
        for node in ast.parse(module.read_bytes()).body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in defined:
                defined[node.name].append(module.stem)
    assert defined == {name: [owner] for name, owner in _OWNERS.items()}
    for name, owner in _OWNERS.items():
        assert getattr(toolkit, name).__module__ == "evidence_manifest_toolkit." + owner


@pytest.mark.parametrize("operation", _OPERATIONS)
def test_an_operation_has_no_default_for_its_bounds(operation: str) -> None:
    """The bounds are a required keyword of every operation, and a call without them fails.

    Parameters
    ----------
    operation : str
        One of the six exported operation names.
    """
    parameter = signatures.signature(getattr(toolkit, operation)).parameters["limits"]
    assert parameter.kind is signatures.Parameter.KEYWORD_ONLY
    assert parameter.default is signatures.Parameter.empty
    call, resolver = _call(operation)
    with pytest.raises(TypeError, match="missing 1 required keyword-only argument: 'limits'"):
        call()
    assert resolver is None or resolver.calls == []


@pytest.mark.parametrize("invalid", (0, -1, True), ids=("zero", "negative", "truth-value"))
@pytest.mark.parametrize("field", _FIELDS)
@pytest.mark.parametrize("operation", _OPERATIONS)
def test_an_invalid_bound_is_refused_by_every_operation_before_any_read(
    operation: str, field: str, invalid: int
) -> None:
    """Each operation names the invalid bound and reads nothing.

    Parameters
    ----------
    operation : str
        One of the six exported operation names.
    field : str
        The one bound that is not a positive integer.
    invalid : int
        Zero, a negative number or a truth value; none is coerced.
    """
    limits = replace(_VALID, **{field: invalid})
    call, resolver = _call(operation)
    with pytest.raises(ConfigurationError) as caught:
        call(limits=limits)
    assert asdict(caught.value.reason) == {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": "/limits/" + field,
        "detail": "Limits require positive integers.",
    }
    assert resolver is None or resolver.calls == []
    assert getattr(limits, field) is invalid


@pytest.mark.parametrize("operation", _OPERATIONS)
def test_the_first_invalid_bound_in_the_fixed_order_is_the_one_named(operation: str) -> None:
    """With two invalid bounds the refusal names the earlier field, whatever the operation.

    Parameters
    ----------
    operation : str
        One of the six exported operation names.
    """
    limits = replace(_VALID, max_json_depth=0, max_reference_count=-5)
    call, resolver = _call(operation)
    with pytest.raises(ConfigurationError) as caught:
        call(limits=limits)
    assert caught.value.reason.pointer == "/limits/max_reference_count"
    assert resolver is None or resolver.calls == []


@pytest.mark.parametrize("operation", _OPERATIONS)
def test_bounds_that_are_not_a_limits_value_are_refused_by_every_operation(operation: str) -> None:
    """A mapping with the six right numbers is not the value type and is not converted.

    Parameters
    ----------
    operation : str
        One of the six exported operation names.
    """
    call, resolver = _call(operation)
    with pytest.raises(ConfigurationError) as caught:
        call(limits=asdict(_VALID))
    assert asdict(caught.value.reason) == {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": "/limits",
        "detail": "Limits require positive integers.",
    }
    assert resolver is None or resolver.calls == []


def test_the_same_arguments_with_valid_bounds_complete_every_operation() -> None:
    """The refusals above are of the bounds alone: with valid bounds each operation completes."""
    assert _call("canonicalize_json")[0](limits=_VALID) == _DOCUMENT
    assert asdict(cast(BlobRef, _call("reference_bytes")[0](limits=_VALID))) == {
        "digest": "sha256:" + hashlib.sha256(_DOCUMENT).hexdigest(),
        "byte_length": "11",
        "media_type": "application/json",
        "digest_basis": "raw_bytes",
        "schema_id": None,
    }
    inspection = _call("inspect")[0](limits=_VALID)
    assert isinstance(inspection, Inspection) and inspection.acceptance == "not_evaluated"
    difference = _call("diff")[0](limits=_VALID)
    assert isinstance(difference, Difference) and difference.content_equal is True
    sealed_packet = _object(
        json.loads((_FIXTURES / "seal-unsigned-whole-fixture.json").read_bytes())
    )
    call, resolver = _call("seal")
    assert _mapping(call(limits=_VALID)) == sealed_packet["expected_entire_SealResult"]
    assert resolver is not None and resolver.calls
    verified = _source("verify-current-whole-fixture")
    call, resolver = _call("verify")
    assert _mapping(call(limits=_VALID)) == verified["expected_entire_VerificationReport"]
    assert resolver is not None and resolver.calls
