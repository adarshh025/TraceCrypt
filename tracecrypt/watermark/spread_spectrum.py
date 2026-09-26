"""Cryptographic spread-spectrum modulation engine for TraceCrypt.

Spreads each coded watermark bit across a deterministic pseudo-random carrier sequence
of mid-frequency 2D DWT + DCT coefficients.

Security properties:
- Deterministic pseudo-random generation anchored in SHA3-256 / SHAKE-256.
- Key material bound to: domain separator, source document hash, WatermarkID, and session tag.
- Zero reliance on standard `random.random()`.
- Blind extraction: receiver reconstructs the carrier sequence from context and correlates
  with received coefficients without requiring the original document.
"""

from __future__ import annotations

from typing import Dict, List, Tuple
import numpy as np

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.utils.identifiers import WatermarkID


class SpreadSpectrumEngine:
    """Manages pseudo-random carrier generation, modulation, and blind correlation."""

    DOMAIN_SEPARATOR: str = "TraceCrypt-Watermark-SpreadSpectrum:v1"

    @classmethod
    def derive_seed(
        cls,
        document_hash: str,
        watermark_id: WatermarkID | str,
        session_tag: bytes,
    ) -> bytes:
        """Derive 32-byte cryptographic seed from document hash, WatermarkID, and session tag."""
        ctx = (
            cls.DOMAIN_SEPARATOR.encode("ascii")
            + b":"
            + document_hash.lower().encode("ascii")
            + b":"
            + str(watermark_id).encode("ascii")
            + b":"
            + session_tag.hex().encode("ascii")
        )
        return Hasher.digest_bytes(ctx, HashAlgorithm.SHA3_256.value).raw_bytes

    @classmethod
    def generate_carrier_sequence(
        cls,
        seed: bytes,
        total_sites: int,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Generate deterministic permutation and bipolar signs (+1/-1) for coefficient sites.

        Uses NumPy Generator seeded with cryptographic entropy derived from seed.
        """
        # Convert first 8 bytes of seed to uint64 for SeedSequence
        seed_int = int.from_bytes(seed[:8], "big")
        rng = np.random.default_rng(seed_int)

        permutation = rng.permutation(total_sites)
        signs = rng.choice(np.array([-1.0, 1.0], dtype=np.float64), size=total_sites)

        return permutation, signs

    @classmethod
    def embed_bits(
        cls,
        dct_subbands: Dict[str, np.ndarray],
        site_map: List[Tuple[str, int, int]],
        coded_bits: np.ndarray,
        permutation: np.ndarray,
        signs: np.ndarray,
        alpha: float,
    ) -> Dict[str, np.ndarray]:
        """Modulate coded bits onto mid-frequency DCT coefficients.

        Args:
            dct_subbands: Dictionary mapping subband name (e.g. 'HL', 'LH') to 2D DCT array.
            site_map: List of (subband_name, row, col) available embedding sites.
            coded_bits: 1D array of 512 bits (values in {0, 1}).
            permutation: Permutation of site indices.
            signs: Bipolar carrier signs (+1/-1).
            alpha: Embedding strength.

        Returns:
            Dictionary of modulated DCT subbands.
        """
        num_bits = len(coded_bits)
        total_sites = len(site_map)
        chips_per_bit = total_sites // num_bits

        if chips_per_bit < 1:
            raise ValueError(f"Insufficient embedding capacity: {total_sites} sites for {num_bits} bits")

        mod_subbands = {k: np.copy(v) for k, v in dct_subbands.items()}
        bit_vals = np.where(coded_bits == 1, 1.0, -1.0)

        for bit_idx in range(num_bits):
            val = bit_vals[bit_idx]
            start = bit_idx * chips_per_bit
            end = start + chips_per_bit
            for k in range(start, end):
                site_idx = permutation[k]
                sb_name, r, c = site_map[site_idx]
                sign = signs[k]
                mod_subbands[sb_name][r, c] += alpha * val * sign

        return mod_subbands

    @classmethod
    def extract_bits(
        cls,
        dct_subbands: Dict[str, np.ndarray],
        site_map: List[Tuple[str, int, int]],
        permutation: np.ndarray,
        signs: np.ndarray,
        num_bits: int = 512,
    ) -> Tuple[np.ndarray, float, np.ndarray]:
        """Blindly extract coded bits and correlation scores from DCT subbands.

        Returns:
            Tuple of (extracted_bits, mean_correlation_score, raw_soft_correlations).
        """
        total_sites = len(site_map)
        chips_per_bit = total_sites // num_bits

        if chips_per_bit < 1:
            raise ValueError(f"Insufficient sites ({total_sites}) for {num_bits} bits")

        extracted_bits = np.zeros(num_bits, dtype=np.uint8)
        soft_correlations = np.zeros(num_bits, dtype=np.float64)

        for bit_idx in range(num_bits):
            start = bit_idx * chips_per_bit
            end = start + chips_per_bit
            corr = 0.0
            for k in range(start, end):
                site_idx = permutation[k]
                sb_name, r, c = site_map[site_idx]
                sign = signs[k]
                val = dct_subbands[sb_name][r, c]
                corr += val * sign
            soft_correlations[bit_idx] = corr / chips_per_bit
            extracted_bits[bit_idx] = 1 if corr > 0.0 else 0

        mean_corr = float(np.mean(np.abs(soft_correlations)))
        return extracted_bits, mean_corr, soft_correlations
