"""Real ECDSA signing and verification for Runar contract testing.

Uses the pure-Python secp256k1 implementation from runar.ec to perform
real ECDSA verification. Signing uses RFC 6979 deterministic k for
reproducibility across all four compiler runtimes (TS, Go, Rust, Python).

TEST_MESSAGE is the UTF-8 encoding of "runar-test-message-v1" (21 bytes).
The ECDSA digest is SHA256(TEST_MESSAGE):
  ee5e6c74a298854942a9eadd789f2812b38936691230134ad50b884cc1f119fa
"""

import hashlib
import hmac

from runar.ec import EC_P, EC_N, EC_G_X, EC_G_Y, _point_add, _point_mul, _modinv

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEST_MESSAGE = b"runar-test-message-v1"
TEST_MESSAGE_DIGEST = hashlib.sha256(TEST_MESSAGE).digest()

# ---------------------------------------------------------------------------
# Compressed public key parsing
# ---------------------------------------------------------------------------


def _decompress_pubkey(pk_bytes: bytes) -> tuple[int, int]:
    """Decompress a 33-byte compressed public key to (x, y).

    Compressed format: 0x02 or 0x03 prefix + 32-byte x-coordinate.
    y = sqrt(x^3 + 7) mod p, choosing even/odd based on prefix.
    Since p = 3 (mod 4), sqrt is computed as y = (x^3 + 7)^((p+1)/4) mod p.
    """
    if len(pk_bytes) != 33:
        raise ValueError(f"Expected 33-byte compressed pubkey, got {len(pk_bytes)}")

    prefix = pk_bytes[0]
    if prefix not in (0x02, 0x03):
        raise ValueError(f"Invalid compressed pubkey prefix: 0x{prefix:02x}")

    x = int.from_bytes(pk_bytes[1:], 'big')

    # y^2 = x^3 + 7 (mod p)
    y_sq = (pow(x, 3, EC_P) + 7) % EC_P
    y = pow(y_sq, (EC_P + 1) // 4, EC_P)

    # Verify the sqrt is correct
    if (y * y) % EC_P != y_sq:
        raise ValueError("Point not on curve")

    # Choose even/odd y based on prefix
    if prefix == 0x02 and y % 2 != 0:
        y = EC_P - y
    elif prefix == 0x03 and y % 2 == 0:
        y = EC_P - y

    return x, y


# ---------------------------------------------------------------------------
# DER signature parsing and encoding
# ---------------------------------------------------------------------------


def _parse_der_signature(der_bytes: bytes, sighash_byte: bool = True) -> tuple[int, int] | None:
    """Parse a DER-encoded ECDSA signature into (r, s) integers.

    DER format: 0x30 [total_len] 0x02 [r_len] [r_bytes] 0x02 [s_len] [s_bytes]

    Strict DER, the BIP66 rule a node applies to every OP_CHECKSIG signature
    (F-242): the SEQUENCE length covers exactly r and s, both INTEGERs are
    non-empty, non-negative (top bit clear unless behind a 0x00 pad) and
    minimally encoded, and nothing follows s. Any other encoding of the same
    (r, s) returns None, so one signature has exactly one byte string.

    With ``sighash_byte`` (the default, Bitcoin convention) one trailing
    sighash type byte after the SEQUENCE is dropped first. Pass False for bare
    DER, e.g. a signed envelope.
    """
    if len(der_bytes) < 2:
        return None
    if sighash_byte and len(der_bytes) == der_bytes[1] + 3:
        der_bytes = der_bytes[:-1]

    n = len(der_bytes)
    if n < 8 or n > 72:
        return None
    if der_bytes[0] != 0x30 or der_bytes[1] != n - 2:
        return None

    r_len = der_bytes[3]
    if der_bytes[2] != 0x02 or r_len == 0 or 5 + r_len >= n:
        return None
    s_len = der_bytes[5 + r_len]
    if der_bytes[4 + r_len] != 0x02 or s_len == 0:
        return None
    if r_len + s_len + 6 != n:
        return None

    r_bytes = der_bytes[4:4 + r_len]
    s_bytes = der_bytes[6 + r_len:]
    if not (_is_canonical_der_integer(r_bytes) and _is_canonical_der_integer(s_bytes)):
        return None

    return int.from_bytes(r_bytes, 'big'), int.from_bytes(s_bytes, 'big')


def _is_canonical_der_integer(b: bytes) -> bool:
    """A DER INTEGER body is canonical for an unsigned value when it is not
    negative (top bit clear) and carries no superfluous leading 0x00."""
    if b[0] & 0x80:
        return False
    if len(b) > 1 and b[0] == 0x00 and not (b[1] & 0x80):
        return False
    return True


def _encode_der_signature(r: int, s: int) -> bytes:
    """Encode (r, s) integers as a DER-encoded ECDSA signature.

    DER format: 0x30 [total_len] 0x02 [r_len] [r_bytes] 0x02 [s_len] [s_bytes]
    Integer bytes are unsigned big-endian with a leading 0x00 if the high bit is set.
    """
    def _int_to_der_bytes(v: int) -> bytes:
        # Convert to unsigned big-endian bytes
        byte_len = (v.bit_length() + 7) // 8
        if byte_len == 0:
            byte_len = 1
        b = v.to_bytes(byte_len, 'big')
        # Add leading zero if high bit is set (to keep unsigned)
        if b[0] & 0x80:
            b = b'\x00' + b
        return b

    r_bytes = _int_to_der_bytes(r)
    s_bytes = _int_to_der_bytes(s)

    inner = bytes([0x02, len(r_bytes)]) + r_bytes + bytes([0x02, len(s_bytes)]) + s_bytes
    return bytes([0x30, len(inner)]) + inner


# ---------------------------------------------------------------------------
# ECDSA Verification
# ---------------------------------------------------------------------------


def ecdsa_verify(
    sig_bytes: bytes, pk_bytes: bytes, msg_hash: bytes, sighash_byte: bool = True
) -> bool:
    """Verify an ECDSA signature over a message hash.

    Standard ECDSA verification:
      1. w = s^-1 mod n
      2. u1 = z * w mod n
      3. u2 = r * w mod n
      4. (x, y) = u1*G + u2*Q
      5. Valid if x mod n == r

    Args:
        sig_bytes: DER-encoded signature (with optional trailing sighash byte)
        sighash_byte: accept one trailing sighash type byte (default True, the
            OP_CHECKSIG convention). The signed envelope passes False: its
            signature is bare DER.
        pk_bytes: 33-byte compressed public key
        msg_hash: 32-byte SHA-256 hash of the message

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        parsed = _parse_der_signature(sig_bytes, sighash_byte)
        if parsed is None:
            return False
        r, s = parsed

        if r <= 0 or r >= EC_N or s <= 0 or s >= EC_N:
            return False

        qx, qy = _decompress_pubkey(pk_bytes)

        z = int.from_bytes(msg_hash, 'big')

        w = _modinv(s, EC_N)
        u1 = (z * w) % EC_N
        u2 = (r * w) % EC_N

        # u1*G + u2*Q
        p1x, p1y = _point_mul(EC_G_X, EC_G_Y, u1)
        p2x, p2y = _point_mul(qx, qy, u2)
        rx, ry = _point_add(p1x, p1y, p2x, p2y)

        if rx == 0 and ry == 0:
            return False

        return rx % EC_N == r
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ECDSA Signing (RFC 6979 deterministic k)
# ---------------------------------------------------------------------------


def _rfc6979_k(priv_key: int, msg_hash: bytes) -> int:
    """Generate deterministic k per RFC 6979 using HMAC-SHA256.

    This is the standard HMAC-DRBG algorithm from Section 3.2 of RFC 6979.
    """
    # Step a: h1 = msg_hash (already a 32-byte hash)
    h1 = msg_hash

    # Private key as 32-byte big-endian
    x = priv_key.to_bytes(32, 'big')

    # Step b: V = 0x01 * 32
    v = b'\x01' * 32

    # Step c: K = 0x00 * 32
    k = b'\x00' * 32

    # Step d: K = HMAC_K(V || 0x00 || x || h1)
    k = hmac.new(k, v + b'\x00' + x + h1, hashlib.sha256).digest()

    # Step e: V = HMAC_K(V)
    v = hmac.new(k, v, hashlib.sha256).digest()

    # Step f: K = HMAC_K(V || 0x01 || x || h1)
    k = hmac.new(k, v + b'\x01' + x + h1, hashlib.sha256).digest()

    # Step g: V = HMAC_K(V)
    v = hmac.new(k, v, hashlib.sha256).digest()

    # Step h: generate candidate k
    while True:
        # h1: V = HMAC_K(V), T = V
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, 'big')

        # h3: if candidate is in [1, n-1], use it
        if 1 <= candidate < EC_N:
            return candidate

        # Otherwise, K = HMAC_K(V || 0x00), V = HMAC_K(V)
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign(priv_key: int, msg_hash: bytes) -> bytes:
    """Sign a message hash using ECDSA with RFC 6979 deterministic k.

    Returns a DER-encoded signature.
    """
    z = int.from_bytes(msg_hash, 'big')

    k = _rfc6979_k(priv_key, msg_hash)

    # R = k * G
    rx, _ry = _point_mul(EC_G_X, EC_G_Y, k)
    r = rx % EC_N

    if r == 0:
        raise ValueError("ECDSA signing failed: r == 0")

    # s = k^-1 * (z + r * privKey) mod n
    k_inv = _modinv(k, EC_N)
    s = (k_inv * (z + r * priv_key)) % EC_N

    if s == 0:
        raise ValueError("ECDSA signing failed: s == 0")

    # Low-S normalization (BIP 62): if s > n/2, use n - s
    if s > EC_N // 2:
        s = EC_N - s

    return _encode_der_signature(r, s)


# ---------------------------------------------------------------------------
# Public API helpers
# ---------------------------------------------------------------------------


def sign_test_message(priv_key_hex: str) -> bytes:
    """Sign the fixed TEST_MESSAGE with a private key.

    Returns DER-encoded ECDSA signature bytes.
    The result is deterministic (RFC 6979) and must match the TypeScript output.
    """
    priv_key = int(priv_key_hex, 16)
    return ecdsa_sign(priv_key, TEST_MESSAGE_DIGEST)


def pub_key_from_priv_key(priv_key_hex: str) -> bytes:
    """Derive the compressed public key from a private key.

    Returns 33-byte compressed public key bytes.
    """
    priv_key = int(priv_key_hex, 16)
    x, y = _point_mul(EC_G_X, EC_G_Y, priv_key)
    prefix = 0x02 if y % 2 == 0 else 0x03
    return bytes([prefix]) + x.to_bytes(32, 'big')
