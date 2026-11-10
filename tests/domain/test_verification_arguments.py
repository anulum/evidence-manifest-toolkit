# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — public verification argument precedence and whole recovery

"""Check public configuration refusals before malformed content or source acquisition."""

from dataclasses import asdict
from pathlib import Path
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

from evidence_manifest_toolkit import (
    BlobRef,
    ConfigurationError,
    Limits,
    SchemaRegistry,
    TrustContext,
    Utc,
    VerificationPolicy,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"


@pytest.mark.parametrize(
    "condition", ("registry", "schema", "envelope_container", "envelope_member")
)
def test_public_verification_arguments_precede_content_and_source_with_whole_recovery(
    condition: str,
) -> None:
    """Retain configuration precedence, zero reads and the complete original report.

    Parameters
    ----------
    condition : str
        Actual caller mapping instead of registry object, empty schema selection,
        a receipt list instead of tuple, or a nonbytes receipt member.

    Notes
    -----
    Deliberate casts supply actual dynamic Python misuse through the public API.
    No production helper, fake resolver, provider interception or source acceptance
    is used. The healthy fixture recovery remains its original conditional class.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    registry = _registry(inputs["registry"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    declared = _object(inputs["policy"])
    assert _array(declared["required_purposes"]) == ["evidence"]
    policy = VerificationPolicy(
        BlobRef.from_mapping(_object(declared["policy_ref"])),
        tuple(_text(value) for value in _array(declared["required_claim_ids"])),
        ("evidence",),
    )
    local = _object(inputs["trust"])
    trust = TrustContext(
        BlobRef.from_mapping(_object(local["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(local["current_snapshot_ref"])),
        _text(local["accepted_sequence_floor"]),
        cast(Literal["current", "historical"], _text(local["evaluation_mode"])),
        Utc(local["evaluation_time"]),
        tuple(_bytes(value) for value in _array(local["control_envelopes"])),
        _optional_reference(local.get("archived_snapshot_ref")),
    )
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    originals = {path: path.read_bytes() for path in population.values()}
    resolver = _FileResolver(population)
    envelopes = tuple(_bytes(value) for value in _array(inputs["envelopes"]))
    bad_envelopes = (
        cast(tuple[bytes, ...], list(envelopes))
        if condition == "envelope_container"
        else cast(tuple[bytes, ...], ("not receipt bytes",))
        if condition == "envelope_member"
        else envelopes
    )
    with pytest.raises(ConfigurationError) as caught:
        verify(
            b"{",
            schema_id="" if condition == "schema" else _text(inputs["schema_id"]),
            envelopes=bad_envelopes,
            registry=cast(SchemaRegistry, inputs["registry"])
            if condition == "registry"
            else registry,
            resolver=resolver,
            limits=limits,
            policy=policy,
            trust=trust,
        )
    assert asdict(caught.value.reason) == {
        "code": "configuration_error",
        "subject_digest": None,
        "claim_id": None,
        "pointer": "/registry"
        if condition == "registry"
        else "/schema_id"
        if condition == "schema"
        else "/envelopes",
        "detail": "Invalid local configuration.",
    }
    assert resolver.calls == []
    report = verify(
        _bytes(inputs["content_json"]),
        schema_id=_text(inputs["schema_id"]),
        envelopes=envelopes,
        registry=registry,
        resolver=resolver,
        limits=limits,
        policy=policy,
        trust=trust,
    )
    assert _mapping(report) == source["expected_entire_VerificationReport"]
    assert resolver.calls
    assert all(path.read_bytes() == raw for path, raw in originals.items())
