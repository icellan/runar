"""Regression tests for the off-chain Rabin verifier padding bound.

The deployed locking script enforces 0 <= padding < 65536 via OP_WITHIN. The
off-chain verifier must mirror that bound, otherwise it accepts the universal
forgery sig=0, padding=SHA256(msg), since (0^2 + SHA256(msg)) mod n ==
SHA256(msg) mod n holds for every message.
"""

import hashlib

from runar.rabin_sig import RABIN_PADDING_LIMIT, rabin_verify

# Canonical test modulus, consistent with RABIN_TEST_KEY in the TS tier
# (packages/runar-testing/src/crypto/rabin.ts): two 130-bit primes ≡ 3 (mod 4)
# whose product n > 2^256.
P = 1361129467683753853853498429727072846227
Q = 1361129467683753853853498429727082846007
N = P * Q


def _int_to_le_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, "little")


def _bytes_to_unsigned_le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _is_qr(a: int, p: int) -> bool:
    if a % p == 0:
        return True
    return pow(a, (p - 1) // 2, p) == 1


def _crt(a1: int, m1: int, a2: int, m2: int) -> int:
    m = m1 * m2
    inv1 = pow(m2, m1 - 2, m1)
    inv2 = pow(m1, m2 - 2, m2)
    return ((a1 * m2 * inv1 + a2 * m1 * inv2) % m + m) % m


def _rabin_sign(msg: bytes):
    """Produce an honest (sig, padding) pair for the test key."""
    hash_bn = _bytes_to_unsigned_le(hashlib.sha256(msg).digest())
    for padding in range(1000):
        target = (hash_bn - padding) % N
        if _is_qr(target, P) and _is_qr(target, Q):
            sp = pow(target, (P + 1) // 4, P)
            sq = pow(target, (Q + 1) // 4, Q)
            sig = _crt(sp, P, sq, Q)
            for candidate in (sig, N - sig):
                if (candidate * candidate + padding) % N == hash_bn % N:
                    return candidate, padding
    raise AssertionError("could not generate honest Rabin signature")


def test_forgery_sig_zero_padding_hash_rejected():
    msg = b"attack at dawn"
    hash_bytes = hashlib.sha256(msg).digest()  # 32-byte SHA256, far above the bound
    pubkey = _int_to_le_bytes(N, 64)
    sig = _int_to_le_bytes(0, 1)
    # padding = SHA256(msg) would satisfy the bare equation but exceeds the bound.
    assert _bytes_to_unsigned_le(hash_bytes) >= RABIN_PADDING_LIMIT
    assert rabin_verify(msg, sig, hash_bytes, pubkey) is False


def test_honest_signature_verifies():
    msg = b"attack at dawn"
    sig_int, padding_int = _rabin_sign(msg)
    assert 0 <= padding_int < RABIN_PADDING_LIMIT

    pubkey = _int_to_le_bytes(N, 64)
    sig = _int_to_le_bytes(sig_int, (sig_int.bit_length() + 7) // 8 or 1)
    padding = _int_to_le_bytes(padding_int, (padding_int.bit_length() + 7) // 8 or 1)

    assert rabin_verify(msg, sig, padding, pubkey) is True


def test_non_canonical_sig_ge_n_rejected():
    """N-380 (F-368 follow-up): the script asserts sig < n, so sig + k*n aborts.

    Proves: the canonical sig and the second root n - sig verify; sig + n and
    sig + 2n (same padding) are rejected. Does not prove the verdict equals the
    consensus interpreter's (conformance/negatives/f368 does that).
    """
    msg = b"attack at dawn"
    sig_int, padding_int = _rabin_sign(msg)
    pubkey = _int_to_le_bytes(N, 64)
    padding = _int_to_le_bytes(padding_int, (padding_int.bit_length() + 7) // 8 or 1)

    def enc(v: int) -> bytes:
        return _int_to_le_bytes(v, (v.bit_length() + 7) // 8 or 1)

    assert rabin_verify(msg, enc(sig_int), padding, pubkey) is True
    assert rabin_verify(msg, enc(N - sig_int), padding, pubkey) is True
    assert rabin_verify(msg, enc(sig_int + N), padding, pubkey) is False
    assert rabin_verify(msg, enc(sig_int + 2 * N), padding, pubkey) is False
