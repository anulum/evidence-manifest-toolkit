# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — a self-bound launch builds and verifies its own request

"""Check that a child builds its whole unsigned V2 request and verifies it in its own process."""

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from fractions import Fraction
from importlib.resources import files
from pathlib import Path
from typing import cast

import pytest
from tests.domain.self_bound_inputs import SelfBoundInputs, self_bound_inputs
from tests.domain.test_cli_evidence_sources import _run
from tests.domain.test_successor_provider_boundary import _stored

from evidence_manifest_toolkit import BlobRef, ConfigurationError, InputRefused, StorageError
from evidence_manifest_toolkit._clock_verdict import CHECK_IDS
from evidence_manifest_toolkit._clock_windows import EVALUATION_BUDGET_NS
from evidence_manifest_toolkit._entry_observation import NativeEntryUnavailable
from evidence_manifest_toolkit._offline_store import OfflineStore
from evidence_manifest_toolkit._self_bound_declaration import EVIDENCE_ROLES
from evidence_manifest_toolkit._self_bound_launch import _StagedResolver, identity_sources
from evidence_manifest_toolkit._self_bound_records import StagedObjects, exchange_from_reply

QUALIFIED = Fraction(15, 1_000_000)


def test_a_self_bound_child_verifies_its_own_request_as_eligible(tmp_path: Path) -> None:
    """All six declared checks hold, so the unsigned report is eligible on consistency alone."""
    case = self_bound_inputs(
        tmp_path,
        rate=QUALIFIED,
        declared_checks=dict.fromkeys(CHECK_IDS, "pass"),
        evidence={"whole_source_match": [{"role": "annual_ntp_reply"}, {"role": "profile"}]},
    )
    report, request = case.launch()
    assert (report.authenticity, report.common_eligibility) == ("unsigned", "eligible")
    assert report.reasons[0].code == "time_consistency_only"
    published = tmp_path / "request"
    assert sorted(path.name for path in published.iterdir()) == [
        "policy.json",
        "request.json",
        "trust.json",
    ]
    record = json.loads((published / "request.json").read_bytes())
    assert record["request_id"] == request.request_id
    assert record["acceptance"]["holds_for"] == "this_boot_only"
    acceptance = _stored_json(case, request.records["acceptance"])
    first = _stored_json(case, request.records["first_sample"])
    start = datetime.strptime(cast(str, acceptance["valid_from"]), "%Y-%m-%dT%H:%M:%SZ")
    earliest = int(cast(str, first["utc_epoch_ns"])) - EVALUATION_BUDGET_NS
    assert start.replace(tzinfo=UTC).timestamp() * 1_000_000_000 <= earliest
    for reference in request.records.values():
        stored = (tmp_path / "objects" / reference.digest[7:]).read_bytes()
        assert "sha256:" + hashlib.sha256(stored).hexdigest() == reference.digest


def _listing(directory: Path) -> dict[str, bytes]:
    """Return every file under ``directory`` with its bytes."""
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def _stored_json(case: SelfBoundInputs, reference: BlobRef) -> dict[str, object]:
    """Read one stored JSON record."""
    return cast(dict[str, object], json.loads((case.objects / reference.digest[7:]).read_bytes()))


def test_the_published_request_replayed_in_another_process_is_refused(tmp_path: Path) -> None:
    """A request binds the process that built it; ``emt verify`` in a new child refuses it."""
    case = self_bound_inputs(
        tmp_path, rate=QUALIFIED, declared_checks=dict.fromkeys(CHECK_IDS, "pass")
    )
    report, _ = case.launch()
    assert report.common_eligibility == "eligible"
    before = _listing(case.objects)
    replay = tmp_path / "replay-report.json"
    result = _run(
        [
            "verify",
            "--content",
            str(case.content),
            "--schema-id",
            case.schema_id,
            "--registry",
            str(case.registry),
            "--objects",
            str(case.objects),
            "--limits",
            str(case.limits),
            "--policy",
            str(case.request / "policy.json"),
            "--trust",
            str(case.request / "trust.json"),
            "--report",
            str(replay),
        ],
        tmp_path,
    )
    error = json.loads(result.stdout)
    assert (result.returncode, result.stderr, replay.exists()) == (2, b"", False)
    assert error["operation"] == "verify"
    assert [reason["code"] for reason in error["reasons"]] == ["policy_unavailable"]
    assert _listing(case.objects) == before


def test_a_contradicted_declaration_is_refused_and_writes_nothing(tmp_path: Path) -> None:
    """A budget declared to hold at a rate below the minimum is refused; no record is written."""
    case = self_bound_inputs(
        tmp_path, rate=Fraction(1, 1_000_000), declared_checks=dict.fromkeys(CHECK_IDS, "pass")
    )
    before = _listing(case.objects)
    with pytest.raises(InputRefused) as caught:
        case.launch()
    reason = caught.value.reason
    assert (reason.code, reason.pointer) == (
        "policy_unavailable",
        f"/checks/{CHECK_IDS.index('proven_uncertainty_budget')}/result",
    )
    assert _listing(case.objects) == before
    assert not case.request.exists()


def test_undeclared_checks_stay_unavailable_and_the_time_is_not_qualified(tmp_path: Path) -> None:
    """Nothing is upgraded: with no declared pass, the report keeps the qualification refusal."""
    case = self_bound_inputs(tmp_path, rate=QUALIFIED)
    report, request = case.launch()
    assert report.common_eligibility == "refused"
    assert report.reasons[0].code == "policy_unavailable"
    acceptance = _stored_json(case, request.records["acceptance"])
    assert [check["result"] for check in cast(list[dict[str, object]], acceptance["checks"])] == [
        "unavailable"
    ] * len(CHECK_IDS)


def test_a_declared_adjustment_enters_every_holdover(tmp_path: Path) -> None:
    """With a one-second adjustment, a holdover that left it out would contradict the budget.

    The sample's accuracy radius must cover the adjustment too, so it is declared as 3 s.
    """
    case = self_bound_inputs(
        tmp_path,
        rate=QUALIFIED,
        declared_checks=dict.fromkeys(CHECK_IDS, "pass"),
        sample_bounds={
            "post_exchange_adjustment_ns": "1000000000",
            "accuracy_radius_ns": "3000000000",
        },
    )
    report, request = case.launch()
    assert report.common_eligibility == "eligible"
    use = _stored_json(case, request.records["use_method"])
    bounds = cast(dict[str, dict[str, dict[str, str]]], use["sample_bounds"])
    for name in ("before", "after"):
        assert int(bounds[name]["elapsed_holdover"]["bound_ns"]) >= 15_000


def test_every_evidence_role_resolves_to_the_record_stored_before_the_acceptance(
    tmp_path: Path,
) -> None:
    """The closed role vocabulary is exactly what the launch resolves, each to its own record."""
    roles: list[dict[str, object]] = [{"role": role} for role in EVIDENCE_ROLES]
    case = self_bound_inputs(tmp_path, rate=QUALIFIED, evidence={"whole_source_match": roles})
    _, request = case.launch()
    acceptance = _stored_json(case, request.records["acceptance"])
    checks = cast(list[dict[str, object]], acceptance["checks"])
    resolved = checks[CHECK_IDS.index("whole_source_match")]["evidence_refs"]
    before = cast(dict[str, object], acceptance["before"])
    after = cast(dict[str, object], acceptance["after"])
    expected = {
        **{
            name: dict(request.records[name].to_mapping())
            for name in EVIDENCE_ROLES
            if name in request.records
        },
        "annual_before_raw_sample": before["clock_sample_raw_ref"],
        "annual_ntp_reply": cast(list[object], acceptance["raw_synchronization_refs"])[0],
        "annual_after_raw_sample": after["clock_sample_raw_ref"],
    }
    assert resolved == [expected[role] for role in EVIDENCE_ROLES]


def test_each_launch_captures_its_own_acceptance_and_keeps_equal_records(tmp_path: Path) -> None:
    """A second launch on the same store re-captures the acceptance; equal records are kept."""
    case = self_bound_inputs(
        tmp_path, rate=QUALIFIED, declared_checks=dict.fromkeys(CHECK_IDS, "pass")
    )
    _, first = case.launch()
    second_case = replace(case, request=tmp_path / "second-request")
    report, second = second_case.launch()
    assert report.common_eligibility == "eligible"
    assert first.request_id != second.request_id
    assert first.records["acceptance"] != second.records["acceptance"]
    earlier = _stored_json(case, first.records["witness"])
    later = _stored_json(case, second.records["acceptance"])
    earlier_use = int(cast(str, earlier["use_utc_upper_ns"]))
    later_before = int(cast(str, cast(dict[str, object], later["before"])["utc_epoch_ns"]))
    assert later_before > earlier_use - 2 * 1_000_000_000
    for name in ("environment", "boot_domain", "entry_method"):
        assert first.records[name] == second.records[name]


def test_a_store_with_different_bytes_under_a_staged_digest_is_refused(tmp_path: Path) -> None:
    """A conflicting store file is refused before verification, and nothing is written."""
    case = self_bound_inputs(
        tmp_path, rate=QUALIFIED, declared_checks=dict.fromkeys(CHECK_IDS, "pass")
    )
    method = files("evidence_manifest_toolkit").joinpath("_native_entry_method.json").read_bytes()
    name = hashlib.sha256(method).hexdigest()
    (case.objects / name).write_bytes(b"different bytes")
    before = _listing(case.objects)
    with pytest.raises(StorageError) as caught:
        case.launch()
    assert caught.value.reason.pointer == "/objects/" + name
    assert _listing(case.objects) == before
    assert not case.request.exists()


def test_an_existing_request_name_is_refused_before_any_capture(tmp_path: Path) -> None:
    """The request directory must be fresh."""
    case = self_bound_inputs(tmp_path, rate=QUALIFIED)
    case.request.mkdir()
    before = _listing(case.objects)
    with pytest.raises(ConfigurationError) as caught:
        case.launch()
    assert caught.value.reason.pointer == "/request"
    assert _listing(case.objects) == before


def test_a_base_policy_whose_clock_is_already_qualified_is_refused(tmp_path: Path) -> None:
    """The launch fills the base policy's Clock qualification; one already filled is refused."""
    case = self_bound_inputs(tmp_path, rate=QUALIFIED)
    base_ref = BlobRef.from_mapping(cast(dict[str, object], case.declaration["base_policy_ref"]))
    base = _stored_json(case, base_ref)
    qualification = cast(dict[str, object], base["required_evaluation_time_qualification"])
    filled = _stored(
        {
            **base,
            "required_evaluation_time_qualification": {
                **qualification,
                "clock_qualification_ref": dict(case.launcher_ref.to_mapping()),
            },
        },
        case.objects,
    )
    case.declaration_path.write_text(
        json.dumps({**case.declaration, "base_policy_ref": dict(filled.to_mapping())}),
        encoding="ascii",
    )
    with pytest.raises(ConfigurationError) as caught:
        case.launch()
    assert caught.value.reason.pointer == "/declaration/base_policy_ref"


def test_a_larger_store_file_under_a_staged_digest_is_refused(tmp_path: Path) -> None:
    """A store file longer than the staged record's read bound is refused as a conflict too."""
    case = self_bound_inputs(tmp_path, rate=QUALIFIED)
    method = files("evidence_manifest_toolkit").joinpath("_native_entry_method.json").read_bytes()
    name = hashlib.sha256(method).hexdigest()
    (case.objects / name).write_bytes(method + b"  ")
    with pytest.raises(StorageError) as caught:
        case.launch()
    assert caught.value.reason.pointer == "/objects/" + name
    assert not case.request.exists()


def test_a_store_that_cannot_be_written_publishes_nothing(tmp_path: Path) -> None:
    """When the records cannot be written after verification, no request is published."""
    case = self_bound_inputs(tmp_path, rate=QUALIFIED)
    before = _listing(case.objects)
    case.objects.chmod(0o555)
    try:
        with pytest.raises(StorageError) as caught:
            case.launch()
    finally:
        case.objects.chmod(0o755)
    assert (caught.value.reason.pointer, caught.value.reason.detail) == (
        "/objects",
        "The object store could not be written.",
    )
    assert _listing(case.objects) == before
    assert not case.request.exists()


def test_a_declaration_that_is_not_json_is_refused(tmp_path: Path) -> None:
    """The declaration file must be strict JSON."""
    case = self_bound_inputs(tmp_path, rate=QUALIFIED)
    case.declaration_path.write_bytes(b"{")
    with pytest.raises(ConfigurationError) as caught:
        case.launch()
    assert caught.value.reason.pointer == "/declaration"


def test_a_base_policy_that_is_not_json_is_refused(tmp_path: Path) -> None:
    """The declared base policy must be a JSON object in the store."""
    case = self_bound_inputs(tmp_path, rate=QUALIFIED)
    data = b"not json"
    digest = hashlib.sha256(data).hexdigest()
    (case.objects / digest).write_bytes(data)
    reference = BlobRef("sha256:" + digest, str(len(data)), "application/json", "raw_bytes")
    case.declaration_path.write_text(
        json.dumps({**case.declaration, "base_policy_ref": dict(reference.to_mapping())}),
        encoding="ascii",
    )
    with pytest.raises(ConfigurationError) as caught:
        case.launch()
    assert caught.value.reason.pointer == "/declaration/base_policy_ref"


def test_a_host_without_the_native_entry_method_is_refused() -> None:
    """Without this process's native entry identity, nothing can be bound."""
    with pytest.raises(ConfigurationError) as caught:
        identity_sources(StagedObjects(), NativeEntryUnavailable("unsupported_abi", None))
    assert caught.value.reason.pointer == "/clock/identity_capture"


@pytest.mark.parametrize(
    "raw",
    (
        b"(uuuuittayttttbtt) 1 2\n",
        b"(uuuuittayttttbt) " + b"1 " * 19 + b"\n",
        b"(uuuuittayttttbtt) " + b"1 " * 12 + b"x 1 1 1 " + b"1 " * 3 + b"\n",
    ),
)
def test_a_reply_outside_the_fixed_form_is_refused(raw: bytes) -> None:
    """A reply that is not the 20-token NTPMessage form with integer timestamps is refused."""
    with pytest.raises(StorageError) as caught:
        exchange_from_reply(StagedObjects(), raw)
    assert caught.value.reason.pointer == "/clock/ntp_capture"


def test_the_staged_resolver_serves_staged_records_first_within_the_bound(tmp_path: Path) -> None:
    """Staged bytes are served by reference or digest, bounded; anything else goes to the store."""
    staged = StagedObjects()
    reference = staged.raw(b"staged record", "text/plain")
    held = b"held record"
    digest = "sha256:" + hashlib.sha256(held).hexdigest()
    (tmp_path / digest[7:]).write_bytes(held)
    with OfflineStore(tmp_path) as store:
        resolver = _StagedResolver(staged.objects, store)
        assert resolver.resolve(reference, max_bytes=100) == b"staged record"
        assert resolver.resolve_digest(reference.digest, max_bytes=100) == b"staged record"
        assert resolver.resolve_digest(digest, max_bytes=100) == held
        held_reference = BlobRef(digest, str(len(held)), "text/plain", "raw_bytes")
        assert resolver.resolve(held_reference, max_bytes=100) == held
        with pytest.raises(InputRefused):
            resolver.resolve(reference, max_bytes=3)
        with pytest.raises(ConfigurationError) as bound:
            resolver.resolve_digest(reference.digest, max_bytes=0)
        assert bound.value.reason.pointer == "/resolver/max_bytes"
        with pytest.raises(ConfigurationError) as malformed:
            resolver.resolve_digest("sha256:XYZ", max_bytes=10)
        assert malformed.value.reason.pointer == "/resolver/digest"
