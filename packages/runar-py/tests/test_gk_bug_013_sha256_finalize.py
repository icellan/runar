"""GK-BUG-013 (off-chain half, Python tier).

sha256_finalize must refuse a msgBitLen outside [0, 2^64), the domain the
compiled script enforces with its ``<00> OP_EQUALVERIFY`` sign-byte check.
It used to hand the value straight to ``struct.pack('>Q', ...)``, which
raised an unrelated ``struct.error`` ("argument out of range") for both
halves of the bad range; the refusal now carries the shared diagnostic every
tier uses.

Proves: -24, -1, 2^64 and 2^64 + 24 raise ValueError naming the domain and
the value; 24 still yields hashlib's SHA-256("abc"); 2^64 - 8 (the top of the
domain) is accepted and equals a one-block FIPS 180-4 reference anchored to
hashlib.
Does not prove: the other six tiers (each has its own gk-bug-013 test).
"""

import hashlib
import struct

import pytest

from runar import sha256_compress, sha256_finalize

IV = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
DOMAIN = r"sha256Finalize: msgBitLen must be in \[0, 2\^64\), got "


def _ref_one_block(tail: bytes, length_field: int) -> bytes:
    block = (tail + b"\x80").ljust(56, b"\x00") + struct.pack(">Q", length_field)
    return sha256_compress(IV, block)


def test_reference_is_anchored_to_hashlib():
    assert _ref_one_block(b"abc", 24) == hashlib.sha256(b"abc").digest()


def test_honest_length_still_hashes():
    assert sha256_finalize(IV, b"abc", 24) == hashlib.sha256(b"abc").digest()


@pytest.mark.parametrize("bit_len", [-24, -1, 1 << 64, (1 << 64) + 24])
def test_refuses_bit_len_outside_the_domain(bit_len):
    with pytest.raises(ValueError, match=DOMAIN + str(bit_len) + r"\b"):
        sha256_finalize(IV, b"abc", bit_len)


def test_top_of_the_domain_is_accepted():
    top = (1 << 64) - 8
    assert sha256_finalize(IV, b"abc", top) == _ref_one_block(b"abc", top)
