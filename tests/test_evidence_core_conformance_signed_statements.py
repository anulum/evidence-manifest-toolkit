# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — evidence core conformance vectors, signed statements

"""Run the signed-statement part of the evidence core conformance vectors, version 1.

The part ``conformance/evidence-core/v1/signed-statements.json`` holds real envelopes from the repository's whole
verification fixture, changed copies of them, and the two published test-vector public keys. This file pins the
part's digest, keeps its envelopes and keys equal to their fixture sources, and runs every case through the key
identity, scope digest, envelope parsing, message construction and Ed25519 verification of this repository.
"""

import base64
import hashlib
import json
from typing import Any, cast

import pytest

from evidence_manifest_toolkit import InputRefused, Limits
from evidence_manifest_toolkit._envelopes import parse_envelope
from evidence_manifest_toolkit._native_signature import NativeVerifier
from evidence_manifest_toolkit._statements import key_id, scope_digest, statement_message
from tests.conftest import SOURCE

PART = SOURCE / "conformance" / "evidence-core" / "v1" / "signed-statements.json"
PART_SHA256 = "5bdb949f69304a78a100df442bd04a3c6bc0be0b624a6846015223474666df8d"
FIXTURES = SOURCE / "tests" / "domain" / "fixtures" / "evidence-command-sources"


def load_part() -> dict[str, Any]:
    """Return the decoded signed-statement part.

    Returns
    -------
    dict[str, Any]
        The whole part document.
    """
    decoded: dict[str, Any] = json.loads(PART.read_bytes())
    return decoded


def group(name: str) -> list[dict[str, Any]]:
    """Return one group of cases.

    Parameters
    ----------
    name : str
        The group name.

    Returns
    -------
    list of dict
        The group's cases in part order.
    """
    return cast(list[dict[str, Any]], load_part()["groups"][name])


def key(name: str) -> bytes:
    """Return a named public key's raw bytes.

    Parameters
    ----------
    name : str
        The key name in the part.

    Returns
    -------
    bytes
        The raw 32-byte public key.
    """
    return bytes.fromhex(load_part()["keys"][name])


def unpadded(text: str) -> bytes:
    """Decode unpadded base64url.

    Parameters
    ----------
    text : str
        The encoded text.

    Returns
    -------
    bytes
        The decoded bytes.
    """
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def test_the_part_is_the_pinned_version_one() -> None:
    """The part's bytes are pinned, and it declares its pack, version, part, contract and profile."""
    assert hashlib.sha256(PART.read_bytes()).hexdigest() == PART_SHA256
    part = load_part()
    assert (part["pack"], part["version"], part["part"]) == (
        "evidence-core-conformance",
        1,
        "signed-statements",
    )
    assert part["contract"] == "docs/contracts/evidence-core-v1.md"
    assert part["profile_id"] == "evidence_manifest_toolkit.jcs_sha256_ed25519.v1"
    counts = {name: len(cases) for name, cases in part["groups"].items()}
    assert counts == {"key_identity": 2, "scope_digest": 3, "envelopes": 9, "messages": 2}


def test_the_keys_and_valid_envelopes_equal_their_fixture_sources() -> None:
    """The keys are the fixture root's and the group certificate's; the valid envelopes are the fixture's."""
    part = load_part()
    bootstrap = json.loads(
        (FIXTURES / "objects" / part["sources"]["keys"][0].split("/")[-1]).read_bytes()
    )
    certificate = json.loads(
        (FIXTURES / "objects" / part["sources"]["keys"][1].split("/")[-1]).read_bytes()
    )
    assert key("fixture-root") == unpadded(bootstrap["fixture_root_public_key_base64url"])
    assert key("group-signer") == unpadded(certificate["public_key_base64url"])
    inputs = json.loads((FIXTURES / "verify-current-whole-fixture.json").read_bytes())
    library = inputs["complete_library_inputs"]
    envelopes = {case["id"]: bytes.fromhex(case["envelope_hex"]) for case in group("envelopes")}
    assert envelopes["envelope-group-valid"] == unpadded(library["envelopes"][0])
    for index, encoded in enumerate(library["trust"]["control_envelopes"], start=1):
        assert envelopes[f"envelope-root-control-valid-{index}"] == unpadded(encoded)


@pytest.mark.parametrize(
    "case", group("key_identity"), ids=[c["id"] for c in group("key_identity")]
)
def test_each_key_identity_is_the_sha256_of_the_raw_key(case: dict[str, Any]) -> None:
    """``key_id`` gives the stated identity for the raw public key."""
    assert key_id(bytes.fromhex(case["public_key_hex"])) == case["expect_key_id"]


@pytest.mark.parametrize(
    "case", group("scope_digest"), ids=[c["id"] for c in group("scope_digest")]
)
def test_each_scope_digest_is_stated(case: dict[str, Any]) -> None:
    """``scope_digest`` gives the stated digest, which is the SHA-256 of the stated scope bytes."""
    expect = case["expect"]
    assert scope_digest(case["statement"]) == expect["scope_digest"]
    scope_bytes = bytes.fromhex(expect["scope_jcs_hex"])
    assert expect["scope_digest"] == "sha256:" + hashlib.sha256(scope_bytes).hexdigest()


@pytest.mark.parametrize("case", group("envelopes"), ids=[c["id"] for c in group("envelopes")])
def test_each_envelope_parses_and_verifies_or_refuses_as_stated(case: dict[str, Any]) -> None:
    """An envelope is refused with the stated code, or gives the stated message, signature and verdict."""
    raw = bytes.fromhex(case["envelope_hex"])
    limits = Limits(**load_part()["limits"])
    expect = case["expect"]
    if "refusal" in expect:
        with pytest.raises(InputRefused) as refused:
            parse_envelope(raw, limits=limits)
        assert refused.value.reason.code == expect["refusal"]
        return
    parsed = parse_envelope(raw, limits=limits)
    assert parsed.message == bytes.fromhex(expect["message_hex"])
    assert parsed.message == statement_message(parsed.statement)
    assert parsed.signature == bytes.fromhex(expect["signature_hex"])
    verdict = NativeVerifier().verify(key(case["verify_with"]), parsed.message, parsed.signature)
    assert verdict is expect["signature_valid"]


@pytest.mark.parametrize("case", group("messages"), ids=[c["id"] for c in group("messages")])
def test_each_message_verifies_as_stated(case: dict[str, Any]) -> None:
    """A message and signature checked directly with the named key give the stated result."""
    verdict = NativeVerifier().verify(
        key(case["verify_with"]),
        bytes.fromhex(case["message_hex"]),
        bytes.fromhex(case["signature_hex"]),
    )
    assert verdict is case["expect_valid"]
