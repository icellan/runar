import pytest
from runar import sha256_compress, sha256_finalize, sha256

SHA256_IV = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")

def test_sha256_compress_abc():
    block = bytes.fromhex(
        "6162638000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000018"
    )
    result = sha256_compress(SHA256_IV, block)
    assert result.hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_sha256_compress_empty():
    block = bytes.fromhex(
        "8000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    result = sha256_compress(SHA256_IV, block)
    assert result.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_sha256_finalize_abc():
    result = sha256_finalize(SHA256_IV, b"abc", 24)
    assert result.hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_sha256_finalize_empty():
    result = sha256_finalize(SHA256_IV, b"", 0)
    assert result.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_sha256_finalize_cross_verify():
    for msg in [b"", b"abc", b"hello world"]:
        finalized = sha256_finalize(SHA256_IV, msg, len(msg) * 8)
        hashed = sha256(msg)
        assert finalized == hashed, f"mismatch for {msg!r}"
