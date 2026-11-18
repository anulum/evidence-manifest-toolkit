# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — evidence core conformance vectors

"""Run the evidence core conformance vector pack, version 1, against this repository's public operations.

The pack ``conformance/evidence-core/v1/vectors.json`` is language-neutral: every case is bytes, limits and expected
results, and the pack states its own case semantics. This file pins the pack's digest, keeps it equal to the sources
it was built from (the reference fixture and the contract page's admission examples), and runs every case through
``canonicalize_json`` and ``reference_bytes``.
"""

import hashlib
import json
import re
from dataclasses import asdict
from typing import Any, cast

import pytest

from evidence_manifest_toolkit import (
    ConfigurationError,
    DigestBasis,
    InputRefused,
    Limits,
    canonicalize_json,
    reference_bytes,
)
from tests.conftest import SOURCE

PACK = SOURCE / "conformance" / "evidence-core" / "v1" / "vectors.json"
PACK_SHA256 = "0ab38dfbb46e0974868bf9e291926dc779301f8ceda741bbc35c8ea8649a665f"
FIXTURE = SOURCE / "tests" / "domain" / "fixtures" / "json-reference-source-vectors.json"
PAGE = SOURCE / "docs" / "contracts" / "evidence-core-v1.md"
EXCLUDED = {"registry_snapshot-canonical", "registry_snapshot-reordered"}
EXAMPLE_ROW = re.compile(
    r"^\| (E\d+) \| (.+?) \| `([0-9a-f]+)` \| (\d+) \| (\d+) \| `([a-z_]+)` \| [^|]+ \|$"
)


def load_pack() -> dict[str, Any]:
    """Return the decoded pack.

    Returns
    -------
    dict[str, Any]
        The whole pack document.
    """
    decoded: dict[str, Any] = json.loads(PACK.read_bytes())
    return decoded


def all_cases() -> list[dict[str, Any]]:
    """Return every case of the pack, admission cases first.

    Returns
    -------
    list of dict
        The cases in pack order.
    """
    groups = load_pack()["groups"]
    return cast(list[dict[str, Any]], groups["admission_order"] + groups["reference"])


def run_canonical(case: dict[str, Any]) -> None:
    """Require the canonical bytes or the refusal the case states.

    Parameters
    ----------
    case : dict
        One pack case.
    """
    raw = bytes.fromhex(case["input_hex"])
    expect = case["expect"]
    if "canonical_hex" in expect:
        assert canonicalize_json(raw, limits=Limits(**case["limits"])) == bytes.fromhex(
            expect["canonical_hex"]
        )
        return
    error_type = ConfigurationError if expect["refusal"] == "configuration_error" else InputRefused
    with pytest.raises(error_type) as refused:
        canonicalize_json(raw, limits=Limits(**case["limits"]))
    assert type(refused.value).__name__ == expect["error_class"]
    assert refused.value.reason.code == expect["refusal"]


def run_reference(case: dict[str, Any], basis: DigestBasis) -> None:
    """Require the byte reference, or the refusal, the pack's semantics give for one basis.

    Parameters
    ----------
    case : dict
        One pack case that states references.
    basis : {"raw_bytes", "jcs_content"}
        The digest basis under test.
    """
    raw = bytes.fromhex(case["input_hex"])
    expected = case["expect"][f"{basis}_reference"]
    code = case["expect"].get("refusal")
    if basis == "raw_bytes" and code != "configuration_error":
        code = None
    if code is None:
        actual = reference_bytes(
            raw,
            media_type="application/json",
            digest_basis=basis,
            schema_id=case["schema_id"],
            limits=Limits(**case["limits"]),
        )
        assert asdict(actual) == expected
        return
    assert expected is None
    error_type = ConfigurationError if code == "configuration_error" else InputRefused
    with pytest.raises(error_type) as refused:
        reference_bytes(
            raw,
            media_type="application/json",
            digest_basis=basis,
            schema_id=case["schema_id"],
            limits=Limits(**case["limits"]),
        )
    assert refused.value.reason.code == code


def test_the_pack_is_the_pinned_version_one() -> None:
    """The pack's bytes are the pinned ones, and it declares its contract, profile and version."""
    assert hashlib.sha256(PACK.read_bytes()).hexdigest() == PACK_SHA256
    pack = load_pack()
    assert pack["pack"] == "evidence-core-conformance" and pack["version"] == 1
    assert pack["contract"] == "docs/contracts/evidence-core-v1.md"
    assert pack["canonical_profile"] == "rfc8785-jcs-v1"
    ids = [case["id"] for case in all_cases()]
    assert len(ids) == len(set(ids)) == 118
    known = set(ids)
    assert all(case["recovery"] in known for case in all_cases() if case.get("recovery"))


def test_the_reference_group_equals_its_fixture() -> None:
    """Every fixture case but the two named exclusions is in the pack, with the same bytes and results."""
    fixture = json.loads(FIXTURE.read_bytes())["cases"]
    pack = load_pack()
    assert set(pack["sources"]["reference_cases_excluded"]) == EXCLUDED
    taken = [case for case in fixture if case["case_id"] not in EXCLUDED]
    reference = pack["groups"]["reference"]
    assert [case["id"] for case in reference] == [case["case_id"] for case in taken]
    for packed, source in zip(reference, taken, strict=True):
        expect = packed["expect"]
        assert packed["input_hex"] == source["raw_hex"]
        assert packed["limits"] == source["explicit_limits"]
        assert packed["schema_id"] == source["schema_id_declaration"]
        assert packed["recovery"] == source["original_recovery_id"]
        assert expect.get("canonical_hex") == source["expected_canonical_hex"]
        assert expect.get("refusal") == source["expected_code"]
        assert expect.get("error_class") == source["expected_error_class"]
        assert expect["raw_bytes_reference"] == source["expected_raw_BlobRef"]
        assert expect["jcs_content_reference"] == source["expected_canonical_BlobRef"]


def test_the_admission_group_equals_the_contract_page() -> None:
    """Cases E1 to E9 carry the page's bytes, limits and codes; the tenth is the depth-in-string case."""
    rows = [EXAMPLE_ROW.match(line) for line in PAGE.read_text(encoding="utf-8").splitlines()]
    table = [row.groups() for row in rows if row is not None]
    admission = load_pack()["groups"]["admission_order"]
    assert len(admission) == len(table) + 1 == 10
    for packed, (label, _, raw, size, depth, code) in zip(admission, table, strict=False):
        assert packed["id"] == f"admission-{label.lower()}"
        assert packed["input_hex"] == raw
        assert packed["limits"]["max_json_bytes"] == int(size)
        assert packed["limits"]["max_json_depth"] == int(depth)
        assert packed["expect"]["refusal"] == code
    assert admission[-1]["id"] == "admission-brackets-in-a-string"


@pytest.mark.parametrize("case", all_cases(), ids=[case["id"] for case in all_cases()])
def test_each_case_canonicalises_or_refuses_as_stated(case: dict[str, Any]) -> None:
    """``canonicalize_json`` returns the stated bytes or refusal, for the case and its recovery."""
    run_canonical(case)
    if case.get("recovery"):
        run_canonical(next(item for item in all_cases() if item["id"] == case["recovery"]))


@pytest.mark.parametrize("basis", ("raw_bytes", "jcs_content"))
@pytest.mark.parametrize(
    "case",
    load_pack()["groups"]["reference"],
    ids=[c["id"] for c in load_pack()["groups"]["reference"]],
)
def test_each_reference_case_gives_the_stated_byte_reference(
    case: dict[str, Any], basis: DigestBasis
) -> None:
    """``reference_bytes`` returns the stated five-field reference, or refuses as the semantics say."""
    run_reference(case, basis)
