# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — maintained point provider for the exact reduced challenge

"""Apply the selected uncofactored PureEd25519 equation through maintained point operations."""

import hashlib

import Crypto
from Crypto.PublicKey.ECC import EccPoint
from Crypto.Signature.eddsa import import_public_key

_ORDER = 2**252 + 27742317777372353535851937790883648493
_PROVIDER_VERSION = "3.24.0"
_BASE = b"\x58" + b"\x66" * 31
_TEST_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
_TEST_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def _encoding(point: EccPoint) -> bytes:
    """Encode maintained Edwards point coordinates canonically.

    Parameters
    ----------
    point : EccPoint
        Actual maintained-provider curve point.

    Returns
    -------
    bytes
        Raw32 little-endian y with the exact x parity bit.
    """
    return (int(point.y) | ((int(point.x) & 1) << 255)).to_bytes(32, "little")


def _point(encoded: bytes) -> EccPoint | None:
    """Admit canonical non-small-order points through maintained public operations.

    Parameters
    ----------
    encoded : bytes
        Entire original raw point encoding.

    Returns
    -------
    EccPoint or None
        Canonical admitted point, or explicit length/codec/small-order refusal.
    """
    if len(encoded) != 32:
        return None
    try:
        point = import_public_key(encoded).pointQ
        if _encoding(point) != encoded or (point * 8).is_point_at_infinity():
            return None
    except ValueError:
        return None
    return point


class NativeVerifier:
    """Bind the supported installed provider to the exact project signature procedure.

    Attributes
    ----------
    provider_version : str
        Actual installed maintained point implementation version selected for admission.
    """

    def __init__(self) -> None:
        """Initialize maintained public point operations and check the fixed primitive vector.

        Raises
        ------
        ValueError
            The installed version or fixed public primitive initialization check fails.
            Passing initialization alone is not complete provider/caller qualification.
        """
        self.provider_version = Crypto.__version__
        if self.provider_version != _PROVIDER_VERSION:
            raise ValueError("Unsupported local point provider version.")
        self._base = import_public_key(_BASE).pointQ
        if not self.verify(_TEST_KEY, b"", _TEST_SIGNATURE):
            raise ValueError("Local point provider initialization failed.")

    def public_key_valid(self, public_key: bytes) -> bool:
        """Check canonical raw32 encoding and all small-order guards without a prime-only rule.

        Parameters
        ----------
        public_key : bytes
            Entire exact caller-selected raw public key.

        Returns
        -------
        bool
            Whether the project point/length/small-order guards admit this key.
            Admitted mixed-order keys remain subject to the exact signature equation.
        """
        return isinstance(public_key, bytes) and _point(public_key) is not None

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Check the complete selected message with canonical points and reduced challenge.

        Parameters
        ----------
        public_key : bytes
            Exact raw32 public bytes; no normalization or prime-subgroup restriction.
        message : bytes
            Entire original message, including the applicable statement domain prefix/LF.
        signature : bytes
            Exact raw64 R/S encoding, never padded, repaired or substituted.

        Returns
        -------
        bool
            False for non-bytes arguments; otherwise the conjunction of canonical A/R,
            both all-small-order guards, S < L and
            canonical encoded [S]B = R + [k]A, with k = OS2IP_LE(SHA512(R||A||M)) mod L.
            No cofactor, context/prehash or trusted caller/domain conclusion is supplied.
        """
        if not all(isinstance(value, bytes) for value in (public_key, message, signature)):
            return False
        if len(public_key) != 32 or len(signature) != 64:
            return False
        scalar = int.from_bytes(signature[32:], "little")
        if scalar >= _ORDER:
            return False
        key_point = _point(public_key)
        r_point = _point(signature[:32])
        if key_point is None or r_point is None:
            return False
        challenge = (
            int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
            % _ORDER
        )
        reconstructed = self._base * scalar + -(key_point * challenge)
        return _encoding(reconstructed) == signature[:32]
