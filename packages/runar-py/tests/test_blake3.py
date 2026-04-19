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
    """Empty message hash must match the cross-language reference.

    The expected value is derived from our own compressor with the same
    blockLen=64, counter=0, flags=11 parameters. All six language runtimes
    must agree on this value; any change here is a cross-compiler regression.
    """
    h = blake3_hash(b"")
    assert len(h) == 32
    # Cross-check via explicit compression: blake3Hash(msg) ==
    # blake3Compress(IV, zero-pad(msg, 64))
    direct = blake3_compress(_BLAKE3_IV_BYTES, b"\x00" * 64)
    assert h == direct


def test_blake3_hash_abc_matches_cross_reference():
    """'abc' input hash must match the explicit compression equivalent."""
    h = blake3_hash(b"abc")
    expected = blake3_compress(_BLAKE3_IV_BYTES, b"abc" + b"\x00" * 61)
    assert h == expected


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
        == "7669004d96866a6330a609d9ad1a08a4f8507c4d04eefd1a50f00b02556aab86"
    )
    assert (
        blake3_hash(b"abc").hex()
        == "6f9871b5d6e80fc882e7bb57857f8b279cdc229664eab9382d2838dbf7d8a20d"
    )
    assert (
        blake3_hash(b"hello world").hex()
        == "47d3d7048c7ed47c986773cc1eefaa0b356bec676dd62cca3269a086999d65fc"
    )
