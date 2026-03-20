"""Runar built-in functions.

Real crypto verification for ECDSA, Rabin, WOTS+, and SLH-DSA.
Real hash functions use Python's hashlib (stdlib, no dependencies).
"""

import hashlib
import math
import struct

from runar.ecdsa import ecdsa_verify, TEST_MESSAGE_DIGEST
from runar.rabin_sig import rabin_verify as _rabin_verify_real
from runar.wots import wots_verify as _wots_verify_real
from runar.slhdsa_impl import slh_verify as _slh_verify


# -- Assertion ---------------------------------------------------------------

def assert_(condition: bool) -> None:
    """Runar assertion. Raises AssertionError if condition is False."""
    if not condition:
        raise AssertionError("runar: assertion failed")


# -- Real ECDSA Verification ------------------------------------------------

def check_sig(sig, pk) -> bool:
    """Verify an ECDSA signature over the fixed TEST_MESSAGE.

    Uses real secp256k1 ECDSA verification against SHA256("runar-test-message-v1").
    Accepts both raw bytes and hex-encoded strings (Runar ByteString convention).
    """
    return ecdsa_verify(_as_bytes(sig), _as_bytes(pk), TEST_MESSAGE_DIGEST)

def check_multi_sig(sigs: list, pks: list) -> bool:
    """Verify multiple ECDSA signatures (Bitcoin-style multi-sig).

    Each signature is verified against the public keys in order.
    Accepts both raw bytes and hex-encoded strings.
    """
    if len(sigs) > len(pks):
        return False
    pk_idx = 0
    for s in sigs:
        matched = False
        while pk_idx < len(pks):
            if check_sig(s, pks[pk_idx]):
                pk_idx += 1
                matched = True
                break
            pk_idx += 1
        if not matched:
            return False
    return True

def check_preimage(preimage: bytes) -> bool:
    """Mock preimage check — always returns True for business logic testing."""
    return True


# -- Real Rabin Verification ------------------------------------------------

def verify_rabin_sig(msg: bytes, sig: bytes, padding: bytes, pk: bytes) -> bool:
    """Verify a Rabin signature.

    All parameters are bytes. sig and pk are interpreted as unsigned
    little-endian integers. Equation: (sig^2 + padding) mod n == SHA256(msg) mod n.
    """
    return _rabin_verify_real(msg, sig, padding, pk)


# -- Real WOTS+ Verification ------------------------------------------------

def verify_wots(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    return _wots_verify_real(msg, sig, pubkey)


# -- Real SLH-DSA Verification (falls back to mock if slhdsa not installed) -

def verify_slh_dsa_sha2_128s(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    return _slh_verify(msg, sig, pubkey, 'sha2_128s')

def verify_slh_dsa_sha2_128f(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    return _slh_verify(msg, sig, pubkey, 'sha2_128f')

def verify_slh_dsa_sha2_192s(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    return _slh_verify(msg, sig, pubkey, 'sha2_192s')

def verify_slh_dsa_sha2_192f(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    return _slh_verify(msg, sig, pubkey, 'sha2_192f')

def verify_slh_dsa_sha2_256s(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    return _slh_verify(msg, sig, pubkey, 'sha2_256s')

def verify_slh_dsa_sha2_256f(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    return _slh_verify(msg, sig, pubkey, 'sha2_256f')


# -- Byte coercion -----------------------------------------------------------

def _as_bytes(x) -> bytes:
    """Accept both raw bytes/bytearray and hex-encoded strings.

    In Rúnar, ByteString literals are hex strings (e.g. "1976a914" = 4 bytes).
    This mirrors the TypeScript interpreter which hex-decodes string literals.
    """
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return bytes.fromhex(x)
    raise TypeError(f"Expected bytes or hex-encoded string, got {type(x).__name__}")


# -- Mock BLAKE3 Functions (compiler intrinsics — stubs return 32 zero bytes)

def blake3_compress(chaining_value, block) -> bytes:
    """Mock BLAKE3 single-block compression.
    In compiled Bitcoin Script this expands to ~10,000 opcodes.
    Returns 32 zero bytes for business-logic testing."""
    return b'\x00' * 32

def blake3_hash(message) -> bytes:
    """Mock BLAKE3 hash for messages up to 64 bytes.
    In compiled Bitcoin Script this uses the IV as the chaining value and
    applies zero-padding before calling the compression function.
    Returns 32 zero bytes for business-logic testing."""
    return b'\x00' * 32


# -- SHA-256 Compression (real implementation) --------------------------------

_SHA256_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)


def _rotr(x: int, n: int) -> int:
    """Right-rotate a 32-bit unsigned integer by n bits."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256_compress(state: bytes, block: bytes) -> bytes:
    """SHA-256 single-block compression function (FIPS 180-4 Section 6.2.2).

    Performs one round of SHA-256 block compression: message schedule
    expansion (W[0..63]), then 64 compression rounds with Sigma/Ch/Maj
    functions and the K constants, followed by addition back to the
    initial state.

    Args:
        state: 32-byte intermediate hash state (8 big-endian uint32 words).
            Use the SHA-256 IV for the first block.
        block: 64-byte message block (512 bits).

    Returns:
        32-byte updated hash state (big-endian).
    """
    assert len(state) == 32, f"state must be 32 bytes, got {len(state)}"
    assert len(block) == 64, f"block must be 64 bytes, got {len(block)}"

    # Parse state as 8 big-endian uint32
    H = list(struct.unpack('>8I', state))

    # Parse block as 16 big-endian uint32 and expand to 64 words
    W = list(struct.unpack('>16I', block))
    for t in range(16, 64):
        s0 = (_rotr(W[t - 15], 7) ^ _rotr(W[t - 15], 18) ^ (W[t - 15] >> 3)) & 0xFFFFFFFF
        s1 = (_rotr(W[t - 2], 17) ^ _rotr(W[t - 2], 19) ^ (W[t - 2] >> 10)) & 0xFFFFFFFF
        W.append((s1 + W[t - 7] + s0 + W[t - 16]) & 0xFFFFFFFF)

    # Initialize working variables
    a, b, c, d, e, f, g, h = H

    # 64 compression rounds
    for t in range(64):
        S1 = (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) & 0xFFFFFFFF
        ch = ((e & f) ^ (~e & g)) & 0xFFFFFFFF
        temp1 = (h + S1 + ch + _SHA256_K[t] + W[t]) & 0xFFFFFFFF
        S0 = (_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) & 0xFFFFFFFF
        maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    # Add compressed chunk to hash state
    result = tuple((H[i] + v) & 0xFFFFFFFF for i, v in enumerate((a, b, c, d, e, f, g, h)))
    return struct.pack('>8I', *result)


def sha256_finalize(state: bytes, remaining: bytes, msg_bit_len: int) -> bytes:
    """SHA-256 finalization with FIPS 180-4 padding.

    Applies SHA-256 padding (append 0x80 byte, zero-pad, append 8-byte
    big-endian bit length) and runs the final 1-2 compression rounds:

    - Single-block path (remaining <= 55 bytes): pads to one 64-byte
      block and compresses once.
    - Two-block path (56-119 bytes): pads to two 64-byte blocks and
      compresses twice.

    Args:
        state: 32-byte intermediate hash state. Use SHA-256 IV when
            finalizing a message that fits in a single compress+finalize
            call, or the output of a prior sha256_compress for multi-block.
        remaining: Unprocessed trailing message bytes (0-119 bytes).
        msg_bit_len: Total message length in bits across all blocks
            (used in the 64-bit length suffix of SHA-256 padding).

    Returns:
        Final 32-byte SHA-256 digest.
    """
    # Append the 0x80 byte
    padded = remaining + b'\x80'

    if len(padded) + 8 <= 64:
        # Fits in one block: pad to 56 bytes, then append 8-byte BE bit length
        padded = padded.ljust(56, b'\x00')
        padded += struct.pack('>Q', msg_bit_len)
        return sha256_compress(state, padded)
    else:
        # Need two blocks: pad to 120 bytes, then append 8-byte BE bit length
        padded = padded.ljust(120, b'\x00')
        padded += struct.pack('>Q', msg_bit_len)
        state = sha256_compress(state, padded[:64])
        return sha256_compress(state, padded[64:])


# -- Real Hash Functions -----------------------------------------------------

def hash160(data) -> bytes:
    """RIPEMD160(SHA256(data))"""
    data = _as_bytes(data)
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def hash256(data) -> bytes:
    """SHA256(SHA256(data))"""
    data = _as_bytes(data)
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def sha256(data) -> bytes:
    data = _as_bytes(data)
    return hashlib.sha256(data).digest()

def ripemd160(data) -> bytes:
    data = _as_bytes(data)
    return hashlib.new('ripemd160', data).digest()


# -- Mock Preimage Extraction ------------------------------------------------

def extract_locktime(preimage: bytes) -> int:
    return 0

def extract_output_hash(preimage) -> bytes:
    """Returns the first 32 bytes of the preimage in test mode.
    Tests set tx_preimage = hash256(expected_output_bytes) so the assertion
    hash256(outputs) == extract_output_hash(tx_preimage) passes.
    Falls back to 32 zero bytes when the preimage is shorter than 32 bytes."""
    preimage = _as_bytes(preimage)
    if len(preimage) >= 32:
        return preimage[:32]
    return b'\x00' * 32

def extract_amount(preimage: bytes) -> int:
    return 10000

def extract_version(preimage: bytes) -> int:
    return 1

def extract_sequence(preimage: bytes) -> int:
    return 0xFFFFFFFF

def extract_hash_prevouts(preimage: bytes) -> bytes:
    """Returns hash256(72 zero bytes) in test mode.

    This is consistent with passing all_prevouts = 72 zero bytes in tests,
    since extract_outpoint also returns 36 zero bytes.
    """
    return hash256(b'\x00' * 72)

def extract_outpoint(preimage: bytes) -> bytes:
    return b'\x00' * 36


# -- Math Utilities ----------------------------------------------------------

def safediv(a: int, b: int) -> int:
    if b == 0:
        return 0
    # Python integer division truncates toward negative infinity,
    # but Bitcoin Script truncates toward zero. Match that behavior.
    if (a < 0) != (b < 0) and a % b != 0:
        return -(abs(a) // abs(b))
    return a // b

def safemod(a: int, b: int) -> int:
    if b == 0:
        return 0
    r = a % b
    # Ensure sign matches dividend (Bitcoin Script behavior)
    if r != 0 and (a < 0) != (r < 0):
        r -= b
    return r

def clamp(value: int, lo: int, hi: int) -> int:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value

def sign(n: int) -> int:
    if n > 0:
        return 1
    if n < 0:
        return -1
    return 0

def pow_(base: int, exp: int) -> int:
    return base ** exp

def mul_div(a: int, b: int, c: int) -> int:
    return (a * b) // c

def percent_of(amount: int, bps: int) -> int:
    return (amount * bps) // 10000

def sqrt(n: int) -> int:
    """Integer square root using Newton's method."""
    if n < 0:
        raise ValueError("sqrt of negative number")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

def gcd(a: int, b: int) -> int:
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a

def divmod_(a: int, b: int) -> int:
    """Returns quotient only (matching Runar's divmod which returns quotient)."""
    return a // b

def log2(n: int) -> int:
    if n <= 0:
        return 0
    return n.bit_length() - 1

def bool_cast(n: int) -> bool:
    return n != 0


# -- Binary Utilities --------------------------------------------------------

def num2bin(v: int, length: int) -> bytes:
    """Convert integer to little-endian sign-magnitude byte string."""
    if v == 0:
        return b'\x00' * length
    negative = v < 0
    val = abs(v)
    result = []
    while val > 0:
        result.append(val & 0xFF)
        val >>= 8
    # Sign bit
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    # Pad to requested length, keeping sign bit on the last byte
    if len(result) < length:
        sign_byte = result[-1] & 0x80
        result[-1] &= 0x7F  # clear sign from current last byte
        while len(result) < length:
            result.append(0)
        result[-1] |= sign_byte  # set sign on actual last byte
    return bytes(result[:length])

def bin2num(data: bytes) -> int:
    """Convert a byte string (Bitcoin Script LE signed-magnitude) to an integer.
    Inverse of num2bin."""
    if len(data) == 0:
        return 0
    last = data[-1]
    negative = (last & 0x80) != 0
    result = last & 0x7F
    for i in range(len(data) - 2, -1, -1):
        result = (result << 8) | data[i]
    return -result if negative else result

def cat(a, b) -> bytes:
    return _as_bytes(a) + _as_bytes(b)

def substr(data, start: int, length: int) -> bytes:
    return _as_bytes(data)[start:start + length]

def reverse_bytes(data) -> bytes:
    return _as_bytes(data)[::-1]

def len_(data) -> int:
    return len(_as_bytes(data))


# -- Test Helpers ------------------------------------------------------------

def mock_sig() -> bytes:
    """Return ALICE's real ECDSA test signature (DER-encoded).

    This is a valid signature over TEST_MESSAGE that will pass check_sig()
    verification when paired with mock_pub_key().
    """
    from runar.test_keys import ALICE
    return ALICE.test_sig

def mock_pub_key() -> bytes:
    """Return ALICE's real compressed public key (33 bytes).

    This is a valid secp256k1 public key that will pass check_sig()
    verification when paired with mock_sig().
    """
    from runar.test_keys import ALICE
    return ALICE.pub_key

def mock_preimage() -> bytes:
    return b'\x00' * 181
