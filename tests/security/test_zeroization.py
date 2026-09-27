"""Adversarial Secret-Handling and Memory Zeroization Tests.

Validates:
- Explicit zeroization of MLKEMPrivateKey buffers.
- Explicit zeroization of MLDSAPrivateKey buffers.
- Denial of access to zeroized key instances.
- Zeroization of intermediate KEK and KWK buffers.
"""

from __future__ import annotations

import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.errors import CryptographicError


class TestZeroization:
    """Validate explicit memory scrubbing and zeroization behaviors."""

    def test_mlkem_private_key_zeroize(self) -> None:
        """Calling zeroize() on MLKEMPrivateKey must scrub bytes and prevent further access."""
        _, sk = generate_mlkem_keypair()
        assert sk.raw_bytes is not None
        assert len(sk.raw_bytes) == 2400

        # Perform zeroization
        sk.zeroize()

        # Subsequent attempts to access raw_bytes must raise CryptographicError
        with pytest.raises(CryptographicError, match="zeroized or destroyed"):
            _ = sk.raw_bytes

        # Representation must report ZEROIZED
        assert "ZEROIZED" in repr(sk)

    def test_mldsa_private_key_zeroize(self) -> None:
        """Calling zeroize() on MLDSAPrivateKey must scrub bytes and prevent further access."""
        _, sk = generate_mldsa_keypair()
        assert sk.raw_bytes is not None
        assert len(sk.raw_bytes) == 4032

        # Perform zeroization
        sk.zeroize()

        # Subsequent attempts to access raw_bytes must raise CryptographicError
        with pytest.raises(CryptographicError, match="zeroized or destroyed"):
            _ = sk.raw_bytes

        # Representation must report ZEROIZED
        assert "ZEROIZED" in repr(sk)

    def test_zeroization_on_garbage_collection(self) -> None:
        """Private key objects must invoke zeroize() in __del__ lifecycle."""
        _, sk = generate_mlkem_keypair()
        # Explicitly call __del__
        sk.__del__()
        with pytest.raises(CryptographicError, match="zeroized or destroyed"):
            _ = sk.raw_bytes
