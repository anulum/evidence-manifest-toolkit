# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — complete declared control target correspondence

"""Match full protected targets to actual selected signers and authorizations."""

from typing import cast

from ._codecs import reference_value
from ._immutable import thaw_json
from ._json import AcquiredDocument, JsonValue
from ._protected_control_bindings import ProtectedControlBinding
from ._protected_state_history import protected_source_conflict
from ._values import BlobRef


def check_protected_control_targets(
    bindings: tuple[ProtectedControlBinding, ...], *, root_selection: BlobRef
) -> None:
    """Compare each complete native target with its matched signer and earlier selection.

    Parameters
    ----------
    bindings : tuple of ProtectedControlBinding
        Entire independently selected controls with original receipt/target correspondence
        and complete source closure. These objects are not admitted transitions.
    root_selection : BlobRef
        Original independently selected and acquired whole root-selection reference,
        separate from the grant's initial issuer and any received target.

    Returns
    -------
    None
        Grant root, certificate issuer/parent and snapshot issuer declarations match.
        Rotation and owner withdrawal retain their distinct original source laws.
        No root, issuer, custody, Clock, signature or state is authenticated here.

    Raises
    ------
    InputRefused
        A complete target contradicts its selected root, signer or authorization.
    """
    for binding in bindings:
        target = cast(
            dict[str, JsonValue], cast(AcquiredDocument, binding.target.source.document).value
        )
        operation = binding.entry["operation"]
        signer = cast(str, binding.entry["signer_key_id"])
        fields: tuple[tuple[str, JsonValue], ...]
        if operation == "authority_grant":
            fields = (
                ("root_key_id", signer),
                ("root_selection_source_ref", reference_value(root_selection)),
            )
        elif operation == "issue_certificate":
            fields = (
                ("issuer_key_id", signer),
                ("parent_authorization_ref", thaw_json(binding.entry["authorization_ref"])),
            )
        elif operation == "issue_snapshot":
            fields = (("current_issuer_key_id", signer),)
        else:
            continue
        for name, expected in fields:
            if target[name] != expected:
                raise protected_source_conflict(binding.target.source.reference.digest, "/" + name)
