"""Reed-Solomon RS(32, 16) Forward Error Correction for TraceCrypt.

Provides a self-contained, mathematically rigorous implementation of Reed-Solomon
coding over Galois Field GF(2^8).

Parameters:
- Field: GF(2^8) with primitive polynomial p(x) = x^8 + x^4 + x^3 + x^2 + 1 (0x11D / 285)
- Symbol size: 8 bits (1 byte)
- Codeword length (n): 32 symbols (bytes)
- Message length (k): 16 symbols (bytes)
- Parity symbols (2t): 16 symbols (bytes)
- Error correction capacity (t): 8 symbol errors per block
- Generator polynomial: g(x) = prod_{i=0}^{15} (x - alpha^i)
- Algorithm: Systematic encoding, Berlekamp-Massey decoding, Chien search, Forney algorithm

Zero external dependencies; fully compliant with air-gapped offline operation.
"""

from __future__ import annotations

from typing import List, Tuple
from tracecrypt.errors import CryptographicError


class ReedSolomonError(CryptographicError):
    """Raised when Reed-Solomon decoding fails due to uncorrectable corruption."""
    pass


class GaloisField256:
    """Galois Field GF(2^8) arithmetic with precomputed exp/log tables."""

    PRIMITIVE_POLYNOMIAL: int = 0x11D  # x^8 + x^4 + x^3 + x^2 + 1

    def __init__(self) -> None:
        self.exp: List[int] = [0] * 512
        self.log: List[int] = [0] * 256

        x = 1
        for i in range(255):
            self.exp[i] = x
            self.log[x] = i
            x <<= 1
            if x & 0x100:
                x ^= self.PRIMITIVE_POLYNOMIAL

        for i in range(255, 512):
            self.exp[i] = self.exp[i - 255]

    def add(self, a: int, b: int) -> int:
        """Galois Field addition (bitwise XOR)."""
        return a ^ b

    def sub(self, a: int, b: int) -> int:
        """Galois Field subtraction (identical to addition)."""
        return a ^ b

    def mul(self, a: int, b: int) -> int:
        """Galois Field multiplication."""
        if a == 0 or b == 0:
            return 0
        return self.exp[self.log[a] + self.log[b]]

    def div(self, a: int, b: int) -> int:
        """Galois Field division."""
        if b == 0:
            raise ZeroDivisionError("Division by zero in GF(2^8)")
        if a == 0:
            return 0
        return self.exp[(self.log[a] - self.log[b]) % 255]

    def power(self, a: int, p: int) -> int:
        """Galois Field exponentiation: a^p."""
        if p == 0:
            return 1
        if a == 0:
            return 0
        return self.exp[(self.log[a] * p) % 255]

    def inv(self, a: int) -> int:
        """Galois Field multiplicative inverse: a^(-1)."""
        if a == 0:
            raise ZeroDivisionError("Cannot invert zero in GF(2^8)")
        return self.exp[255 - self.log[a]]

    def poly_mul(self, p1: List[int], p2: List[int]) -> List[int]:
        """Multiply two polynomials over GF(2^8)."""
        r = [0] * (len(p1) + len(p2) - 1)
        for i, c1 in enumerate(p1):
            if c1 == 0:
                continue
            for j, c2 in enumerate(p2):
                if c2 != 0:
                    r[i + j] ^= self.mul(c1, c2)
        return r

    def poly_eval(self, poly: List[int], x: int) -> int:
        """Evaluate polynomial at x using Horner's rule."""
        y = poly[0]
        for c in poly[1:]:
            y = self.add(self.mul(y, x), c)
        return y


# Singleton instance of the field
GF = GaloisField256()


class ReedSolomon32_16:
    """Reed-Solomon RS(32, 16) Codec.

    Codeword length n = 32
    Data symbols k = 16
    Parity symbols 2t = 16
    Maximum correctable symbol errors t = 8
    """

    N: int = 32
    K: int = 16
    N_PARITY: int = 16
    T_CAPACITY: int = 8

    def __init__(self) -> None:
        self.generator = self._build_generator_polynomial(self.N_PARITY)

    def _build_generator_polynomial(self, n_parity: int) -> List[int]:
        """Generate g(x) = prod_{i=0}^{n_parity-1} (x - alpha^i)."""
        g = [1]
        for i in range(n_parity):
            # multiply by (x - alpha^i) = (x + alpha^i)
            root = GF.exp[i]
            g = GF.poly_mul(g, [1, root])
        return g

    def encode(self, data: bytes | bytearray | List[int]) -> bytes:
        """Systematically encode 16 data bytes into a 32-byte codeword."""
        if len(data) != self.K:
            raise ValueError(f"RS(32, 16) encoder expects exactly {self.K} bytes, got {len(data)}")

        msg = list(data)
        # Shift message by n_parity positions: msg * x^(n_parity)
        shifted = msg + [0] * self.N_PARITY
        remainder = list(shifted)

        for i in range(len(msg)):
            coeff = remainder[i]
            if coeff != 0:
                for j in range(1, len(self.generator)):
                    remainder[i + j] ^= GF.mul(self.generator[j], coeff)

        parity = remainder[len(msg):]
        codeword = msg + parity
        return bytes(codeword)

    def _compute_syndromes(self, received: List[int]) -> List[int]:
        """Compute 2t syndromes: S_i = r(alpha^i) for i in 0..2t-1."""
        syndromes = [0] * self.N_PARITY
        for i in range(self.N_PARITY):
            syndromes[i] = GF.poly_eval(received, GF.exp[i])
        return syndromes

    def _find_error_locator(self, syndromes: List[int]) -> List[int]:
        """Berlekamp-Massey algorithm to find the error locator polynomial Lambda(x)."""
        C = [1]
        B = [1]
        L = 0
        m = 1
        b = 1

        for n in range(self.N_PARITY):
            # Compute discrepancy delta
            delta = syndromes[n]
            for i in range(1, L + 1):
                if i < len(C):
                    delta ^= GF.mul(C[i], syndromes[n - i])

            if delta == 0:
                m += 1
            elif 2 * L <= n:
                T = list(C)
                factor = GF.div(delta, b)
                # C(x) = C(x) - (delta/b) * x^m * B(x)
                shifted_B = [0] * m + [GF.mul(c, factor) for c in B]
                new_len = max(len(C), len(shifted_B))
                new_C = [0] * new_len
                for idx, c in enumerate(C):
                    new_C[idx] ^= c
                for idx, c in enumerate(shifted_B):
                    new_C[idx] ^= c
                C = new_C
                L = n + 1 - L
                B = T
                b = delta
                m = 1
            else:
                factor = GF.div(delta, b)
                shifted_B = [0] * m + [GF.mul(c, factor) for c in B]
                new_len = max(len(C), len(shifted_B))
                new_C = [0] * new_len
                for idx, c in enumerate(C):
                    new_C[idx] ^= c
                for idx, c in enumerate(shifted_B):
                    new_C[idx] ^= c
                C = new_C
                m += 1

        return C

    def _chien_search(self, locator: List[int], length: int) -> List[int]:
        """Chien search to find roots of locator polynomial."""
        deg = len(locator) - 1
        # Strip leading zeros if any
        while len(locator) > 1 and locator[-1] == 0:
            locator.pop()
        deg = len(locator) - 1

        error_positions: List[int] = []
        for i in range(length):
            # Check if alpha^(-i) is a root
            # alpha^(-i) = alpha^(255 - i)
            x_val = GF.exp[(255 - i) % 255]
            val = 0
            for power_idx, c in enumerate(locator):
                val ^= GF.mul(c, GF.power(x_val, power_idx))
            if val == 0:
                # Root found! Location in codeword: length - 1 - i
                error_positions.append(length - 1 - i)

        if len(error_positions) != deg:
            raise ReedSolomonError(
                f"Chien search found {len(error_positions)} roots, expected {deg}. "
                "Errors exceed correction capacity."
            )

        return error_positions

    def _forney_algorithm(
        self,
        syndromes: List[int],
        locator: List[int],
        error_positions: List[int],
        codeword_len: int,
    ) -> List[int]:
        """Forney algorithm to compute error values at identified positions."""
        # Compute Error Evaluator Polynomial: Omega(x) = [S(x) * Lambda(x)] mod x^(2t)
        poly_mul_res = GF.poly_mul(syndromes, locator)
        omega = poly_mul_res[:self.N_PARITY]

        # Formal derivative of Lambda(x): Lambda'(x)
        # Over GF(2), derivative of x^(2k) is 0, derivative of x^(2k+1) is x^(2k)
        deriv = [0] * len(locator)
        for i in range(1, len(locator), 2):
            deriv[i - 1] = locator[i]
        while len(deriv) > 1 and deriv[-1] == 0:
            deriv.pop()

        error_values = []
        for pos in error_positions:
            # X_k = alpha^(codeword_len - 1 - pos)
            X_k = GF.exp[codeword_len - 1 - pos]
            X_k_inv = GF.inv(X_k)

            # Evaluate Omega(X_k_inv)
            num = 0
            for i, c in enumerate(omega):
                num ^= GF.mul(c, GF.power(X_k_inv, i))

            # Evaluate Lambda'(X_k_inv)
            den = 0
            for i, c in enumerate(deriv):
                den ^= GF.mul(c, GF.power(X_k_inv, i))

            if den == 0:
                raise ReedSolomonError("Forney denominator is zero.")

            # e_k = X_k * Omega(X_k_inv) / Lambda'(X_k_inv)
            val = GF.mul(X_k, GF.div(num, den))
            error_values.append(val)

        return error_values

    def decode(self, codeword: bytes | bytearray | List[int]) -> Tuple[bytes, int]:
        """Decode a 32-byte codeword, correcting up to 8 symbol errors.

        Returns:
            Tuple of (16-byte decoded data, number of corrected symbol errors).

        Raises:
            ReedSolomonError: If errors exceed correction capacity (t > 8) or corruption
                              is unrecoverable.
        """
        if len(codeword) != self.N:
            raise ValueError(f"RS(32, 16) decoder expects exactly {self.N} bytes, got {len(codeword)}")

        r = list(codeword)
        syndromes = self._compute_syndromes(r)

        # Check if error-free
        if all(s == 0 for s in syndromes):
            return bytes(r[:self.K]), 0

        # Find error locator polynomial
        locator = self._find_error_locator(syndromes)
        deg = len(locator) - 1

        if deg > self.T_CAPACITY:
            raise ReedSolomonError(
                f"Error locator degree {deg} exceeds maximum correction capacity {self.T_CAPACITY}"
            )

        # Find error positions
        error_positions = self._chien_search(locator, self.N)

        # Find error values
        error_values = self._forney_algorithm(syndromes, locator, error_positions, self.N)

        # Apply correction
        corrected = list(r)
        for pos, val in zip(error_positions, error_values):
            corrected[pos] ^= val

        # Verify corrected codeword
        new_syndromes = self._compute_syndromes(corrected)
        if any(s != 0 for s in new_syndromes):
            raise ReedSolomonError("Correction verification failed; syndromes non-zero.")

        return bytes(corrected[:self.K]), len(error_positions)


class WatermarkPayloadEncoder:
    """Encodes a 256-bit (32-byte) logical watermark payload into 64 bytes (512 bits).

    Uses 2 interleaved blocks of RS(32, 16) to provide burst error resistance:
    - 32 bytes data -> Block 0 (16 bytes) and Block 1 (16 bytes)
    - Each block encoded to 32 bytes (16 data + 16 parity) with RS(32, 16)
    - Symbols are interleaved so adjacent byte errors affect alternating blocks
    - Can correct up to 8 symbol errors in EACH 32-byte block (up to 16 total symbol errors!)
    """

    def __init__(self) -> None:
        self.codec = ReedSolomon32_16()

    def encode_payload(self, payload_bytes: bytes) -> bytes:
        """Encode 32-byte payload to 64-byte interleaved codeword."""
        if len(payload_bytes) != 32:
            raise ValueError(f"Payload must be exactly 32 bytes (256 bits), got {len(payload_bytes)}")

        block0_data = payload_bytes[:16]
        block1_data = payload_bytes[16:]

        block0_coded = self.codec.encode(block0_data)  # 32 bytes
        block1_coded = self.codec.encode(block1_data)  # 32 bytes

        # Interleave symbols: [B0_0, B1_0, B0_1, B1_1, ..., B0_31, B1_31]
        interleaved = bytearray(64)
        for i in range(32):
            interleaved[2 * i] = block0_coded[i]
            interleaved[2 * i + 1] = block1_coded[i]

        return bytes(interleaved)

    def decode_payload(self, encoded_bytes: bytes) -> Tuple[bytes, int]:
        """De-interleave and decode 64-byte codeword back to 32-byte payload.

        Returns:
            Tuple of (32-byte payload, total corrected symbol errors).

        Raises:
            ReedSolomonError: If either block exceeds 8 symbol errors.
        """
        if len(encoded_bytes) != 64:
            raise ValueError(f"Encoded stream must be exactly 64 bytes (512 bits), got {len(encoded_bytes)}")

        block0_coded = bytearray(32)
        block1_coded = bytearray(32)

        for i in range(32):
            block0_coded[i] = encoded_bytes[2 * i]
            block1_coded[i] = encoded_bytes[2 * i + 1]

        data0, errs0 = self.codec.decode(bytes(block0_coded))
        data1, errs1 = self.codec.decode(bytes(block1_coded))

        return data0 + data1, errs0 + errs1
