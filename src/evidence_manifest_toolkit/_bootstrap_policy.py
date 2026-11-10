# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — independently selected local bootstrap declarations

"""Parse the closed bootstrap wire without treating artifact fields as owner approval."""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from ._codecs import decode_bytes, decode_reference
from ._errors import ConfigurationError, InputRefused
from ._immutable import FrozenJson, freeze_json
from ._json import AcquiredDocument
from ._statements import key_id
from ._values import BlobRef, Reason

PROFILE = "evidence_manifest_toolkit.jcs_sha256_ed25519.v1"
_FIXTURE_KEY = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
_FIXTURE_ID = "ed25519:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
_FIXTURE_DIGEST = "0b557ac5be9251645e9ab223b210dae33c359311045960927cdc32565a7d3871"


@dataclass(frozen=True, slots=True)
class BootstrapDeclaration:
    """Retain parsed local public declarations separately from the trusted caller premise.

    Attributes
    ----------
    namespace : {"fixture", "operational"}
        Closed selected local wire, without an approval or signer-enrollment verdict.
    root_public_key : bytes
        Exact canonical raw32 public declaration after key-identifier correspondence.
    root_key_id : str
        Original exact native public key identifier.
    schema_catalogue_ref : BlobRef or None
        Explicit operational catalogue, or no invented field for the original fixture.
    declaration : Mapping
        Complete original closed wire, including every false/null fixture fact. Recognition
        of these fields establishes no signer enrollment or previously approved authority.
    """

    namespace: Literal["fixture", "operational"]
    root_public_key: bytes
    root_key_id: str
    schema_catalogue_ref: BlobRef | None
    declaration: Mapping[str, FrozenJson]


def parse_bootstrap(document: AcquiredDocument, *, reference: BlobRef) -> BootstrapDeclaration:
    """Check the complete independently selected original fixture or operational local wire.

    Parameters
    ----------
    document : AcquiredDocument
        Entire identity-checked source, with its original bytes retained.
    reference : BlobRef
        Original caller-selected bootstrap identity used for located refusals.

    Returns
    -------
    BootstrapDeclaration
        Public declarations only. Independent owner or fixture acceptance remains the
        trusted caller's precondition and cannot be proved by these identical input bytes.

    Raises
    ------
    ConfigurationError
        Shape, fixed fixture population, profiles or public-key correspondence is invalid.
    """
    value = document.value

    def refuse(pointer: str, *, unsupported: bool = False) -> ConfigurationError:
        """Construct a fixed refusal at the actual bootstrap declaration position.

        Parameters
        ----------
        pointer : str
            Exact offending local field.
        unsupported : bool
            Whether the independently selected local namespace/profile is unsupported.

        Returns
        -------
        ConfigurationError
            Authored diagnostic without source paths or interpreter exception text.
        """
        return ConfigurationError(
            Reason(
                "configuration_error",
                reference.digest,
                None,
                pointer,
                "Unsupported local trust or policy configuration."
                if unsupported
                else "Invalid local trust or policy configuration.",
            )
        )

    if not isinstance(value, dict):
        raise refuse("")
    fixture = "fixture_root_key_id" in value or "operational" in value
    fields = (
        (
            "enrolled_hardware_signer",
            "fixture_root_key_id",
            "fixture_root_public_key_base64url",
            "operational",
            "profile_id",
        )
        if fixture
        else (
            "root_key_id",
            "root_public_key_base64url",
            "profile_id",
            "canonical_profile",
            "schema_catalogue_ref",
        )
    )
    for name in fields:
        if name not in value:
            raise refuse("/" + name)
    for name in value:
        if name not in fields:
            raise refuse("/" + name)
    if value["profile_id"] != PROFILE:
        raise refuse("/profile_id", unsupported=isinstance(value["profile_id"], str))
    if fixture:
        expected: dict[str, object] = {
            "enrolled_hardware_signer": None,
            "fixture_root_key_id": _FIXTURE_ID,
            "fixture_root_public_key_base64url": _FIXTURE_KEY,
            "operational": False,
        }
        for name, required in expected.items():
            if type(value[name]) is not type(required) or value[name] != required:
                raise refuse("/" + name)
        if hashlib.sha256(document.raw_bytes).hexdigest() != _FIXTURE_DIGEST:
            raise refuse("")
        return BootstrapDeclaration(
            "fixture",
            decode_bytes(_FIXTURE_KEY),
            _FIXTURE_ID,
            None,
            cast(Mapping[str, FrozenJson], freeze_json(value)),
        )
    if value["canonical_profile"] != "rfc8785-jcs-v1":
        raise refuse("/canonical_profile", unsupported=isinstance(value["canonical_profile"], str))
    encoded, identifier = value["root_public_key_base64url"], value["root_key_id"]
    if not isinstance(encoded, str):
        raise refuse("/root_public_key_base64url")
    try:
        public_key = decode_bytes(encoded)
    except ValueError:
        raise refuse("/root_public_key_base64url") from None
    if len(public_key) != 32 or not isinstance(identifier, str) or identifier != key_id(public_key):
        raise refuse("/root_key_id")
    try:
        catalogue = decode_reference(
            value["schema_catalogue_ref"], subject=reference.digest, pointer="/schema_catalogue_ref"
        )
    except InputRefused:
        raise refuse("/schema_catalogue_ref") from None
    if (catalogue.digest_basis, catalogue.media_type, catalogue.schema_id) != (
        "jcs_content",
        "application/json",
        "evidence_manifest_toolkit.registry_snapshot.v1",
    ):
        raise refuse("/schema_catalogue_ref")
    if public_key == decode_bytes(_FIXTURE_KEY):
        raise ConfigurationError(
            Reason(
                "configuration_error",
                reference.digest,
                None,
                "/root_key_id",
                "Fixture root is outside the selected operational namespace.",
            )
        )
    return BootstrapDeclaration(
        "operational",
        public_key,
        identifier,
        catalogue,
        cast(Mapping[str, FrozenJson], freeze_json(value)),
    )
