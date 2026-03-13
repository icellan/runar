"""Runar built-in functions.

Real crypto verification for WOTS+ and SLH-DSA (when packages available).
Mock crypto for ECDSA (checkSig always True — matches Go/Rust/TS behavior).
Real hash functions use Python's hashlib (stdlib, no dependencies).
"""

import hashlib
import math

from runar.wots import wots_verify as _wots_verify_real
from runar.slhdsa_impl import slh_verify as _slh_verify


# -- Assertion ---------------------------------------------------------------

def assert_(condition: bool) -> None:
    """Runar assertion. Raises AssertionError if condition is False."""
    if not condition:
        raise AssertionError("runar: assertion failed")


# -- Mock Crypto (ECDSA always True for business logic testing) --------------

def check_sig(sig: bytes, pk: bytes) -> bool:
    return True

def check_multi_sig(sigs: list, pks: list) -> bool:
    return True

def check_preimage(preimage: bytes) -> bool:
    return True

def verify_rabin_sig(msg: bytes, sig: bytes, padding: bytes, pk: bytes) -> bool:
    return True


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
    return b'\x00' * 72

def mock_pub_key() -> bytes:
    return b'\x02' + b'\x00' * 32

def mock_preimage() -> bytes:
    return b'\x00' * 181
