"""Tests for Python BLAKE3 runtime — real single-block implementation.

Verifies agreement with the Go / TypeScript reference implementations against
a handful of known inputs. Multi-block BLAKE3 is not expressible in the
emitted Bitcoin Script so only single-block compression / padded-short-message
hash is covered.
"""

from runar.builtins import blake3_compress, blake3_hash, _BLAKE3_IV_BYTES


def test_blake3_compress_zero_block_zero_cv():
    """Compressing all-zero CV with all-zero block is deterministic and non-zero."""
    out = blake3_compress(b"\x00" * 32, b"\x00" * 64)
    assert len(out) == 32
    assert out != b"\x00" * 32  # real impl is not a zero stub


def test_blake3_hash_empty_matches_cross_reference():
    """Empty message hash must match the official BLAKE3 KAT.

    blake3_hash uses the real message length as block_len (0 here), so it is
    NOT equal to blake3_compress(IV, zero-pad(msg, 64)) — that identity only
    holds for a full 64-byte message. All seven runtimes must agree on this
    official value; any change is a cross-compiler regression.
    """
    h = blake3_hash(b"")
    assert len(h) == 32
    assert h.hex() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"


def test_blake3_hash_abc_matches_cross_reference():
    """'abc' input hash must match the official BLAKE3 KAT (block_len=3)."""
    h = blake3_hash(b"abc")
    assert h.hex() == "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"


def test_blake3_hash_full_block_equals_compress():
    """For a full 64-byte message, blake3_hash == blake3_compress(IV, msg).

    Both use block_len=64, so this is the one input length where the
    hash/compress cross-reference identity holds under standard BLAKE3.
    """
    msg = bytes(range(64))
    assert blake3_hash(msg) == blake3_compress(_BLAKE3_IV_BYTES, msg)


def test_blake3_hash_accepts_hex_string_literal():
    """ByteString literals are hex strings in Rúnar; the runtime decodes them."""
    # "1976a914" = 4 bytes
    h_hex = blake3_hash("1976a914")
    h_bytes = blake3_hash(bytes.fromhex("1976a914"))
    assert h_hex == h_bytes


def test_blake3_compress_determinism():
    """Same inputs must produce same output across invocations."""
    cv = bytes(range(32))
    block = bytes(range(64))
    a = blake3_compress(cv, block)
    b = blake3_compress(cv, block)
    assert a == b
    assert len(a) == 32


def test_blake3_compress_differs_from_zero_stub():
    """Guards against regression back to the zero-byte stub."""
    out = blake3_compress(_BLAKE3_IV_BYTES, b"hello world" + b"\x00" * 53)
    assert out != b"\x00" * 32


def test_blake3_hash_matches_typescript_reference():
    """Byte-identical output against the TS interpreter reference.

    These expected hex strings were produced by running the exact algorithm
    in the TS interpreter (packages/runar-testing/src/interpreter/interpreter.ts
    :blake3CompressImpl) and are pinned here so any divergence is caught.
    """
    assert (
        blake3_hash(b"").hex()
        == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    )
    assert (
        blake3_hash(b"abc").hex()
        == "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    )
    assert (
        blake3_hash(b"hello world").hex()
        == "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
    )
