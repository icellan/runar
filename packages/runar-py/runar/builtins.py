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


# -- Real P-256 ECDSA Verification ------------------------------------------

def verify_ecdsa_p256(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    """Verify a P-256 ECDSA signature.

    msg is the raw message (SHA-256 hashed internally).
    sig is the 64-byte raw signature: r[32] || s[32].
    pubkey is the 33-byte compressed P-256 public key (02/03 prefix).
    """
    import hashlib
    msg = _as_bytes(msg)
    sig = _as_bytes(sig)
    pubkey = _as_bytes(pubkey)
    if len(sig) != 64:
        return False
    # P-256 curve parameters
    _P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    _P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    _P256_A = -3 % _P256_P
    _P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    _P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    _P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    def _modinv_p256(a: int, m: int) -> int:
        g, x, _ = _ext_gcd_p256(a % m, m)
        if g != 1:
            return 0
        return x % m

    def _ext_gcd_p256(a: int, b: int):
        if a == 0:
            return b, 0, 1
        g, x, y = _ext_gcd_p256(b % a, a)
        return g, y - (b // a) * x, x

    def _p256_add(x1, y1, x2, y2):
        if x1 is None:
            return x2, y2
        if x2 is None:
            return x1, y1
        if x1 == x2:
            if y1 != y2:
                return None, None
            lam = (3 * x1 * x1 + _P256_A) * _modinv_p256(2 * y1, _P256_P) % _P256_P
        else:
            lam = (y2 - y1) * _modinv_p256(x2 - x1, _P256_P) % _P256_P
        x3 = (lam * lam - x1 - x2) % _P256_P
        y3 = (lam * (x1 - x3) - y1) % _P256_P
        return x3, y3

    def _p256_mul(x, y, k):
        rx, ry = None, None
        qx, qy = x, y
        while k > 0:
            if k & 1:
                rx, ry = _p256_add(rx, ry, qx, qy)
            qx, qy = _p256_add(qx, qy, qx, qy)
            k >>= 1
        return rx, ry

    # Decode compressed public key
    prefix = pubkey[0]
    if prefix not in (0x02, 0x03) or len(pubkey) != 33:
        return False
    pkx = int.from_bytes(pubkey[1:], 'big')
    # Recover y from x: y^2 = x^3 + ax + b (mod p)
    y2 = (pow(pkx, 3, _P256_P) + _P256_A * pkx + _P256_B) % _P256_P
    y = pow(y2, (_P256_P + 1) // 4, _P256_P)
    if pow(y, 2, _P256_P) != y2:
        return False
    if (y % 2) != (prefix % 2):
        y = _P256_P - y

    # Hash message
    digest = hashlib.sha256(_as_bytes(msg)).digest()
    z = int.from_bytes(digest, 'big')

    # Decode signature r, s
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')
    if r == 0 or s == 0 or r >= _P256_N or s >= _P256_N:
        return False

    w = _modinv_p256(s, _P256_N)
    u1 = z * w % _P256_N
    u2 = r * w % _P256_N

    # Compute u1*G + u2*Q
    gx, gy = _p256_mul(_P256_GX, _P256_GY, u1)
    qx, qy = _p256_mul(pkx, y, u2)
    rx, ry = _p256_add(gx, gy, qx, qy)
    if rx is None:
        return False
    return rx % _P256_N == r


# -- Real P-384 ECDSA Verification ------------------------------------------

def verify_ecdsa_p384(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    """Verify a P-384 ECDSA signature.

    msg is the raw message (SHA-256 hashed internally, matching the on-chain
    codegen which uses OP_SHA256 for both P-256 and P-384).
    sig is the 96-byte raw signature: r[48] || s[48].
    pubkey is the 49-byte compressed P-384 public key (02/03 prefix + x[48]).
    """
    import hashlib
    msg = _as_bytes(msg)
    sig = _as_bytes(sig)
    pubkey = _as_bytes(pubkey)
    if len(sig) != 96:
        return False
    # P-384 curve parameters
    _P384_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
    _P384_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    _P384_A = -3 % _P384_P
    _P384_B = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
    _P384_GX = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
    _P384_GY = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F

    def _modinv_p384(a: int, m: int) -> int:
        g, x, _ = _ext_gcd_p384(a % m, m)
        if g != 1:
            return 0
        return x % m

    def _ext_gcd_p384(a: int, b: int):
        if a == 0:
            return b, 0, 1
        g, x, y = _ext_gcd_p384(b % a, a)
        return g, y - (b // a) * x, x

    def _p384_add(x1, y1, x2, y2):
        if x1 is None:
            return x2, y2
        if x2 is None:
            return x1, y1
        if x1 == x2:
            if y1 != y2:
                return None, None
            lam = (3 * x1 * x1 + _P384_A) * _modinv_p384(2 * y1, _P384_P) % _P384_P
        else:
            lam = (y2 - y1) * _modinv_p384(x2 - x1, _P384_P) % _P384_P
        x3 = (lam * lam - x1 - x2) % _P384_P
        y3 = (lam * (x1 - x3) - y1) % _P384_P
        return x3, y3

    def _p384_mul(x, y, k):
        rx, ry = None, None
        qx, qy = x, y
        while k > 0:
            if k & 1:
                rx, ry = _p384_add(rx, ry, qx, qy)
            qx, qy = _p384_add(qx, qy, qx, qy)
            k >>= 1
        return rx, ry

    # Decode compressed public key (49 bytes)
    prefix = pubkey[0]
    if prefix not in (0x02, 0x03) or len(pubkey) != 49:
        return False
    pkx = int.from_bytes(pubkey[1:], 'big')
    # Recover y from x: y^2 = x^3 + ax + b (mod p)
    y2 = (pow(pkx, 3, _P384_P) + _P384_A * pkx + _P384_B) % _P384_P
    y = pow(y2, (_P384_P + 1) // 4, _P384_P)
    if pow(y, 2, _P384_P) != y2:
        return False
    if (y % 2) != (prefix % 2):
        y = _P384_P - y

    # Hash message (SHA-256, matching on-chain codegen for both curves)
    digest = hashlib.sha256(_as_bytes(msg)).digest()
    z = int.from_bytes(digest, 'big')

    # Decode signature r, s (48 bytes each)
    r = int.from_bytes(sig[:48], 'big')
    s = int.from_bytes(sig[48:], 'big')
    if r == 0 or s == 0 or r >= _P384_N or s >= _P384_N:
        return False

    w = _modinv_p384(s, _P384_N)
    u1 = z * w % _P384_N
    u2 = r * w % _P384_N

    # Compute u1*G + u2*Q
    gx, gy = _p384_mul(_P384_GX, _P384_GY, u1)
    qx, qy = _p384_mul(pkx, y, u2)
    rx, ry = _p384_add(gx, gy, qx, qy)
    if rx is None:
        return False
    return rx % _P384_N == r


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


# -- BLAKE3 Functions (compiler intrinsics — real single-block implementation)
#
# Matches the compiler's codegen (blockLen=64, counter=0, flags=11 =
# CHUNK_START | CHUNK_END | ROOT) and the TS interpreter reference in
# packages/runar-testing/src/interpreter/interpreter.ts:1742 (blake3CompressImpl).
# This covers all one-block uses exercised by contracts; multi-block BLAKE3 is
# not expressible in the emitted script so no multi-block interpreter branch
# is needed.

_BLAKE3_IV_WORDS = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)

_BLAKE3_IV_BYTES = b"".join(w.to_bytes(4, "big") for w in _BLAKE3_IV_WORDS)

_BLAKE3_MSG_PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)


def _blake3_rotr32(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def _blake3_g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & 0xFFFFFFFF
    s[d] = _blake3_rotr32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _blake3_rotr32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & 0xFFFFFFFF
    s[d] = _blake3_rotr32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _blake3_rotr32(s[b] ^ s[c], 7)


def _blake3_round(s, m):
    _blake3_g(s, 0, 4, 8, 12, m[0], m[1])
    _blake3_g(s, 1, 5, 9, 13, m[2], m[3])
    _blake3_g(s, 2, 6, 10, 14, m[4], m[5])
    _blake3_g(s, 3, 7, 11, 15, m[6], m[7])
    _blake3_g(s, 0, 5, 10, 15, m[8], m[9])
    _blake3_g(s, 1, 6, 11, 12, m[10], m[11])
    _blake3_g(s, 2, 7, 8, 13, m[12], m[13])
    _blake3_g(s, 3, 4, 9, 14, m[14], m[15])


def _blake3_compress_impl(cv: bytes, block: bytes) -> bytes:
    """Single-block BLAKE3 compression with blockLen=64, counter=0, flags=11."""
    if len(cv) != 32:
        raise ValueError(f"blake3 chaining value must be 32 bytes, got {len(cv)}")
    if len(block) != 64:
        raise ValueError(f"blake3 block must be 64 bytes, got {len(block)}")

    h = [int.from_bytes(cv[i * 4:i * 4 + 4], "big") for i in range(8)]
    m = [int.from_bytes(block[i * 4:i * 4 + 4], "big") for i in range(16)]

    state = [
        h[0], h[1], h[2], h[3],
        h[4], h[5], h[6], h[7],
        _BLAKE3_IV_WORDS[0], _BLAKE3_IV_WORDS[1],
        _BLAKE3_IV_WORDS[2], _BLAKE3_IV_WORDS[3],
        0, 0, 64, 11,
    ]

    msg = list(m)
    for r in range(7):
        _blake3_round(state, msg)
        if r < 6:
            msg = [msg[i] for i in _BLAKE3_MSG_PERM]

    out = bytearray(32)
    for i in range(8):
        w = (state[i] ^ state[i + 8]) & 0xFFFFFFFF
        out[i * 4:i * 4 + 4] = w.to_bytes(4, "big")
    return bytes(out)


def blake3_compress(chaining_value, block) -> bytes:
    """BLAKE3 single-block compression (blockLen=64, counter=0, flags=11)."""
    cv = _as_bytes(chaining_value)
    blk = _as_bytes(block)
    return _blake3_compress_impl(cv, blk)


def blake3_hash(message) -> bytes:
    """BLAKE3 hash for messages up to 64 bytes.

    Uses IV as the chaining value and applies zero-padding before calling the
    single-block compression function. Matches the compiler codegen and the TS
    interpreter reference.
    """
    msg = _as_bytes(message)
    padded = msg[:64] + b"\x00" * max(0, 64 - len(msg))
    return _blake3_compress_impl(_BLAKE3_IV_BYTES, padded)


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

def sha256_hash(data) -> bytes:
    """Alias for sha256. Provides an explicitly-named spelling so cross-format
    contract sources that reference `Sha256Hash` (which every parser resolves
    to the `sha256` builtin) have a matching runtime function on the Python
    side too."""
    return sha256(data)

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

def int_to_str(v: int, length: int) -> bytes:
    """Convert an integer to its fixed-width byte-string representation.

    Alias for :func:`num2bin`. The Rúnar built-in ``int2str`` (TypeScript name)
    is exposed as ``int_to_str`` in Python snake_case. Lowers to ``OP_NUM2BIN``
    in compiled Bitcoin Script.
    """
    return num2bin(v, length)


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


# -- Baby Bear field arithmetic (p = 2^31 - 2^27 + 1 = 2013265921) ---------

_BB_P = 2013265921

def bb_field_add(a: int, b: int) -> int:
    """Baby Bear field addition: (a + b) mod p."""
    return (a + b) % _BB_P

def bb_field_sub(a: int, b: int) -> int:
    """Baby Bear field subtraction: (a - b + p) mod p."""
    return ((a - b) % _BB_P + _BB_P) % _BB_P

def bb_field_mul(a: int, b: int) -> int:
    """Baby Bear field multiplication: (a * b) mod p."""
    return (a * b) % _BB_P

def bb_field_inv(a: int) -> int:
    """Baby Bear field inverse via Fermat's little theorem: a^(p-2) mod p."""
    return pow(((a % _BB_P) + _BB_P) % _BB_P, _BB_P - 2, _BB_P)


# -- Baby Bear quartic extension field (x^4 - W, W = 11) ---------------------
#
# Mirrors the Go reference in packages/runar-go/runar.go (BbExt4Mul{0..3},
# BbExt4Inv{0..3}, bbExt4Inv) and the compiler codegen used by the `babybear-ext4`
# conformance fixture.

_BB_EXT4_W = 11


def bb_ext4_mul0(a0: int, a1: int, a2: int, a3: int,
                 b0: int, b1: int, b2: int, b3: int) -> int:
    r = bb_field_mul(a0, b0)
    t = bb_field_add(bb_field_mul(a1, b3),
                     bb_field_add(bb_field_mul(a2, b2), bb_field_mul(a3, b1)))
    return bb_field_add(r, bb_field_mul(_BB_EXT4_W, t))


def bb_ext4_mul1(a0: int, a1: int, a2: int, a3: int,
                 b0: int, b1: int, b2: int, b3: int) -> int:
    r = bb_field_add(bb_field_mul(a0, b1), bb_field_mul(a1, b0))
    t = bb_field_add(bb_field_mul(a2, b3), bb_field_mul(a3, b2))
    return bb_field_add(r, bb_field_mul(_BB_EXT4_W, t))


def bb_ext4_mul2(a0: int, a1: int, a2: int, a3: int,
                 b0: int, b1: int, b2: int, b3: int) -> int:
    r = bb_field_add(bb_field_mul(a0, b2),
                     bb_field_add(bb_field_mul(a1, b1), bb_field_mul(a2, b0)))
    return bb_field_add(r, bb_field_mul(_BB_EXT4_W, bb_field_mul(a3, b3)))


def bb_ext4_mul3(a0: int, a1: int, a2: int, a3: int,
                 b0: int, b1: int, b2: int, b3: int) -> int:
    return bb_field_add(
        bb_field_mul(a0, b3),
        bb_field_add(
            bb_field_mul(a1, b2),
            bb_field_add(bb_field_mul(a2, b1), bb_field_mul(a3, b0)),
        ),
    )


def _bb_ext4_inv_all(a0: int, a1: int, a2: int, a3: int) -> tuple[int, int, int, int]:
    """Invert a BabyBear Ext4 element; returns the four components."""
    # conj(a) for x^4 - W: (a0, -a1, a2, -a3)
    c0 = a0
    c1 = bb_field_sub(0, a1)
    c2 = a2
    c3 = bb_field_sub(0, a3)

    # a * conj(a) lands in Fp2 (components 1, 3 = 0)
    p0 = bb_ext4_mul0(a0, a1, a2, a3, c0, c1, c2, c3)
    p2 = bb_ext4_mul2(a0, a1, a2, a3, c0, c1, c2, c3)

    # Invert the Fp2 element (p0, p2) in Fp[y]/(y^2 - W)
    norm_sq = bb_field_sub(bb_field_mul(p0, p0),
                           bb_field_mul(_BB_EXT4_W, bb_field_mul(p2, p2)))
    norm_inv = bb_field_inv(norm_sq)

    inv0 = bb_field_mul(p0, norm_inv)
    inv2 = bb_field_sub(0, bb_field_mul(p2, norm_inv))

    r0 = bb_field_add(bb_field_mul(c0, inv0),
                      bb_field_mul(_BB_EXT4_W, bb_field_mul(c2, inv2)))
    r1 = bb_field_add(bb_field_mul(c1, inv0),
                      bb_field_mul(_BB_EXT4_W, bb_field_mul(c3, inv2)))
    r2 = bb_field_add(bb_field_mul(c0, inv2), bb_field_mul(c2, inv0))
    r3 = bb_field_add(bb_field_mul(c1, inv2), bb_field_mul(c3, inv0))
    return r0, r1, r2, r3


def bb_ext4_inv0(a0: int, a1: int, a2: int, a3: int) -> int:
    return _bb_ext4_inv_all(a0, a1, a2, a3)[0]


def bb_ext4_inv1(a0: int, a1: int, a2: int, a3: int) -> int:
    return _bb_ext4_inv_all(a0, a1, a2, a3)[1]


def bb_ext4_inv2(a0: int, a1: int, a2: int, a3: int) -> int:
    return _bb_ext4_inv_all(a0, a1, a2, a3)[2]


def bb_ext4_inv3(a0: int, a1: int, a2: int, a3: int) -> int:
    return _bb_ext4_inv_all(a0, a1, a2, a3)[3]


# -- KoalaBear field arithmetic (p = 2^31 - 2^24 + 1 = 2,130,706,433) --------

_KB_P = 2130706433
_KB_EXT4_W = 3


def kb_field_add(a: int, b: int) -> int:
    return (a + b) % _KB_P


def kb_field_sub(a: int, b: int) -> int:
    return ((a - b) % _KB_P + _KB_P) % _KB_P


def kb_field_mul(a: int, b: int) -> int:
    return (a * b) % _KB_P


def kb_field_inv(a: int) -> int:
    return pow(((a % _KB_P) + _KB_P) % _KB_P, _KB_P - 2, _KB_P)


def kb_ext4_mul0(a0: int, a1: int, a2: int, a3: int,
                 b0: int, b1: int, b2: int, b3: int) -> int:
    r = kb_field_mul(a0, b0)
    t = kb_field_add(kb_field_mul(a1, b3),
                     kb_field_add(kb_field_mul(a2, b2), kb_field_mul(a3, b1)))
    return kb_field_add(r, kb_field_mul(_KB_EXT4_W, t))


def kb_ext4_mul1(a0: int, a1: int, a2: int, a3: int,
                 b0: int, b1: int, b2: int, b3: int) -> int:
    r = kb_field_add(kb_field_mul(a0, b1), kb_field_mul(a1, b0))
    t = kb_field_add(kb_field_mul(a2, b3), kb_field_mul(a3, b2))
    return kb_field_add(r, kb_field_mul(_KB_EXT4_W, t))


def kb_ext4_mul2(a0: int, a1: int, a2: int, a3: int,
                 b0: int, b1: int, b2: int, b3: int) -> int:
    r = kb_field_add(kb_field_mul(a0, b2),
                     kb_field_add(kb_field_mul(a1, b1), kb_field_mul(a2, b0)))
    return kb_field_add(r, kb_field_mul(_KB_EXT4_W, kb_field_mul(a3, b3)))


def kb_ext4_mul3(a0: int, a1: int, a2: int, a3: int,
                 b0: int, b1: int, b2: int, b3: int) -> int:
    return kb_field_add(
        kb_field_mul(a0, b3),
        kb_field_add(
            kb_field_mul(a1, b2),
            kb_field_add(kb_field_mul(a2, b1), kb_field_mul(a3, b0)),
        ),
    )


def _kb_ext4_inv_all(a0: int, a1: int, a2: int, a3: int) -> tuple[int, int, int, int]:
    c0 = a0
    c1 = kb_field_sub(0, a1)
    c2 = a2
    c3 = kb_field_sub(0, a3)

    p0 = kb_ext4_mul0(a0, a1, a2, a3, c0, c1, c2, c3)
    p2 = kb_ext4_mul2(a0, a1, a2, a3, c0, c1, c2, c3)

    norm_sq = kb_field_sub(kb_field_mul(p0, p0),
                           kb_field_mul(_KB_EXT4_W, kb_field_mul(p2, p2)))
    norm_inv = kb_field_inv(norm_sq)

    inv0 = kb_field_mul(p0, norm_inv)
    inv2 = kb_field_sub(0, kb_field_mul(p2, norm_inv))

    r0 = kb_field_add(kb_field_mul(c0, inv0),
                      kb_field_mul(_KB_EXT4_W, kb_field_mul(c2, inv2)))
    r1 = kb_field_add(kb_field_mul(c1, inv0),
                      kb_field_mul(_KB_EXT4_W, kb_field_mul(c3, inv2)))
    r2 = kb_field_add(kb_field_mul(c0, inv2), kb_field_mul(c2, inv0))
    r3 = kb_field_add(kb_field_mul(c1, inv2), kb_field_mul(c3, inv0))
    return r0, r1, r2, r3


def kb_ext4_inv0(a0: int, a1: int, a2: int, a3: int) -> int:
    return _kb_ext4_inv_all(a0, a1, a2, a3)[0]


def kb_ext4_inv1(a0: int, a1: int, a2: int, a3: int) -> int:
    return _kb_ext4_inv_all(a0, a1, a2, a3)[1]


def kb_ext4_inv2(a0: int, a1: int, a2: int, a3: int) -> int:
    return _kb_ext4_inv_all(a0, a1, a2, a3)[2]


def kb_ext4_inv3(a0: int, a1: int, a2: int, a3: int) -> int:
    return _kb_ext4_inv_all(a0, a1, a2, a3)[3]


# -- BN254 field arithmetic (p = 21888...8583) -------------------------------

_BN254_P = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47


def bn254_field_add(a: int, b: int) -> int:
    return (a + b) % _BN254_P


def bn254_field_sub(a: int, b: int) -> int:
    return ((a - b) % _BN254_P + _BN254_P) % _BN254_P


def bn254_field_mul(a: int, b: int) -> int:
    return (a * b) % _BN254_P


def bn254_field_inv(a: int) -> int:
    return pow(((a % _BN254_P) + _BN254_P) % _BN254_P, _BN254_P - 2, _BN254_P)


def bn254_field_neg(a: int) -> int:
    return (_BN254_P - (a % _BN254_P)) % _BN254_P


# -- Merkle proof verification -----------------------------------------------

def merkle_root_sha256(leaf: bytes, proof: bytes, index: int, depth: int) -> bytes:
    """Compute a Merkle root using SHA-256 as the hash function."""
    return _merkle_root_impl(leaf, proof, index, depth, sha256)

def merkle_root_hash256(leaf: bytes, proof: bytes, index: int, depth: int) -> bytes:
    """Compute a Merkle root using Hash256 (double SHA-256)."""
    return _merkle_root_impl(leaf, proof, index, depth, hash256)

def _merkle_root_impl(leaf: bytes, proof: bytes, index: int, depth: int, hash_fn) -> bytes:
    current = _as_bytes(leaf)
    proof_bytes = _as_bytes(proof)
    for i in range(depth):
        sibling = proof_bytes[i * 32:(i + 1) * 32]
        bit = (index >> i) & 1
        if bit == 1:
            preimage = sibling + current
        else:
            preimage = current + sibling
        current = hash_fn(preimage)
    return current
