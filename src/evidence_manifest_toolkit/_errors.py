# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — typed operation failures

"""Carry thrown failures separately from returned verification refusals."""

from ._values import BlobRef, Digest, Reason


class EmtError(Exception):
    """Carry one exact refusal reason for a thrown operation failure.

    Parameters
    ----------
    reason : Reason
        Actual located failure; unavailable identities remain null.

    Attributes
    ----------
    reason : Reason
        Immutable diagnostic preserved for the operation's ErrorResult.
    """

    def __init__(self, reason: Reason) -> None:
        """Retain the actual immutable caller-safe failure reason.

        Parameters
        ----------
        reason : Reason
            Whole located refusal with no invented unavailable identity.
        """
        self.reason = reason
        super().__init__(reason.code)


class InputRefused(EmtError):
    """Refuse malformed input, unsupported bytes or exhausted operation bounds."""


class ConfigurationError(EmtError):
    """Refuse invalid local configuration before reporting evaluated gates."""


class SignerUnavailable(EmtError):
    """Refuse an unavailable or invalid signer response without unsigned retry."""


class StorageError(EmtError):
    """Refuse exclusive publication without overwriting a prior destination."""


class ReferenceUnavailable(EmtError):
    """Preserve the exact original argument of a failed resolver call.

    Parameters
    ----------
    reference : BlobRef or str
        Whole original reference or original digest-only control identity.

    Attributes
    ----------
    reference : BlobRef or str
        Unchanged resolver argument; no missing length or schema is invented.
    """

    def __init__(self, reference: BlobRef | Digest) -> None:
        """Preserve the exact original unavailable lookup argument.

        Parameters
        ----------
        reference : BlobRef or str
            Whole original reference or original digest-only control identity.
        """
        self.reference = reference
        super().__init__(
            Reason("reference_unavailable", None, None, None, "Required reference unavailable.")
        )
