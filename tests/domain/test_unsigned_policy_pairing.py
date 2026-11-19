# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — unsigned policy pairing and the unsigned route's reads

"""Refuse every unsigned policy mismatch on the policy alone, and read no authority on the route.

A successor policy pairs with its caller class before any authority source is acquired: each
refusal here is asserted together with the resolver's record, which holds the selected policy
and nothing else. The positive unsigned route reads no bootstrap policy, snapshot or control
source of the legacy trust that the same fixture also carries.
"""

from dataclasses import asdict
from pathlib import Path
from typing import cast

import pytest
from tests.domain.test_cli_evidence_sources import _source, _transport
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow
from tests.domain.test_policy_selection_sources import _successor_policy
from tests.domain.test_successor_trust import _callers, _sources
from tests.domain.test_verification_report_sources import (
    _array,
    _bytes,
    _FileResolver,
    _object,
    _registry,
    _text,
)

from evidence_manifest_toolkit import (
    BlobRef,
    ConfigurationError,
    Limits,
    TrustContext,
    Utc,
    VerificationPolicy,
    reference_bytes,
    verify,
)

_FIXTURES = Path(__file__).parent / "fixtures/evidence-command-sources"
_POINTERS = {
    "legacy_trust": "/trust",
    "unsigned_grant": "/root_grant_ref",
    "unsigned_rule": "/authority_rule_ref",
}


def _legacy_trust(value: dict[str, object]) -> TrustContext:
    """Return the fixture's complete legacy trust context."""
    archived = value.get("archived_snapshot_ref")
    return TrustContext(
        BlobRef.from_mapping(_object(value["bootstrap_policy_ref"])),
        BlobRef.from_mapping(_object(value["current_snapshot_ref"])),
        _text(value["accepted_sequence_floor"]),
        "current",
        Utc(_text(value["evaluation_time"])),
        tuple(_bytes(x) for x in _array(value["control_envelopes"])),
        None if archived is None else BlobRef.from_mapping(_object(archived)),
    )


@pytest.mark.parametrize("case", ["legacy_trust", "unsigned_grant", "unsigned_rule"])
def test_an_unsigned_policy_mismatch_is_refused_on_the_policy_alone(
    case: str, tmp_path: Path
) -> None:
    """Refuse a v2 policy for a legacy caller, or an unsigned policy naming a grant or a rule.

    Parameters
    ----------
    case : str
        ``legacy_trust``: an unsigned v2 policy with the legacy ``TrustContext``;
        ``unsigned_grant`` and ``unsigned_rule``: an unsigned v2 policy whose
        ``root_grant_ref`` or ``authority_rule_ref`` is not null, with the unsigned caller.
    tmp_path : Path
        Owned policy carrier.
    """
    source = _source("verify-current-whole-fixture")
    inputs = _object(source["complete_library_inputs"])
    limits = Limits(**cast(dict[str, int], _object(inputs["limits"])))
    registry = _registry(inputs["registry"])
    declaration = _object(inputs["policy"])
    original_ref = BlobRef.from_mapping(_object(declaration["policy_ref"]))
    population = {
        key: _FIXTURES / "objects" / _text(_object(row)["sha256"])
        for key, row in _object(inputs["resolver_input_population"]).items()
    }
    binding, references, _ = _sources()
    unsigned = _callers(binding, references, "current")[0]
    value = _successor_policy(original_ref)
    value["profile_class"] = unsigned.profile_class
    if case == "unsigned_grant":
        value["root_grant_ref"] = dict(original_ref.to_mapping())
    if case == "unsigned_rule":
        value["authority_rule_ref"] = dict(original_ref.to_mapping())
    raw = _transport(value)
    path = tmp_path / "selected-whole-policy.json"
    path.write_bytes(raw)
    selected = reference_bytes(
        raw,
        media_type="application/json",
        digest_basis="raw_bytes",
        schema_id="evidence_manifest_toolkit.authority_policy.v2",
        limits=limits,
    )
    population[selected.digest + "|raw_bytes"] = path
    policy = VerificationPolicy(
        selected, tuple(_text(x) for x in _array(declaration["required_claim_ids"])), ("evidence",)
    )
    trust = _legacy_trust(_object(inputs["trust"])) if case == "legacy_trust" else unsigned
    resolver = _FileResolver(population)
    with pytest.raises(ConfigurationError) as caught:
        verify(
            _bytes(inputs["content_json"]),
            schema_id=_text(inputs["schema_id"]),
            envelopes=(),
            registry=registry,
            resolver=resolver,
            limits=limits,
            policy=policy,
            trust=trust,
        )
    assert asdict(caught.value.reason) == {
        "code": "configuration_error",
        "subject_digest": selected.digest,
        "claim_id": None,
        "pointer": _POINTERS[case],
        "detail": "Invalid local trust or policy configuration.",
    }
    assert tuple(argument for argument, _ in resolver.calls) == (selected,)


def test_the_unsigned_route_reads_no_legacy_authority_source(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """The positive unsigned route reads the policy and its sources, and no legacy authority.

    Parameters
    ----------
    tmp_path : Path
        Owned fixture directory of the whole workflow.
    capfd : pytest.CaptureFixture
        Actual stdout/stderr capture used by the workflow.
    """
    calls: list[tuple[BlobRef | str, int]] = []
    assert_whole_clock_source_workflow("sig_exception", tmp_path, capfd, resolver_calls=calls)
    legacy = _object(
        _object(_source("verify-current-whole-fixture")["complete_library_inputs"])["trust"]
    )
    authority = {
        BlobRef.from_mapping(_object(legacy[name])).digest
        for name in ("bootstrap_policy_ref", "current_snapshot_ref")
    }
    read = [argument for argument, _ in calls if isinstance(argument, BlobRef)]
    assert len(read) == len(calls)
    assert authority.isdisjoint(reference.digest for reference in read)
    assert sorted({str(reference.schema_id) for reference in read}) == sorted(
        {
            "None",
            "evidence_manifest_toolkit.authority_policy.v2",
            "evidence_manifest_toolkit.manifest.v1",
            "evidence_manifest_toolkit.target_descriptor.v1",
        }
    )
