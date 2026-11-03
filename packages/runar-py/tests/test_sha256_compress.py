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


def test_sha256_compress_refuses_wrong_size_operands_under_python_O():
    """N-336: the operand-size guard must survive ``python -O``.

    Proves: with assertions stripped (``-O``), a 31-byte state and a 63-byte
    block each raise ValueError (not silently accepted / struct.error), and
    correct sizes still work.
    Does not prove: anything about the on-chain F-114 guard itself, or other
    runtime helpers (blake3_compress has its own ValueError tests).
    """
    import subprocess
    import sys
    from pathlib import Path

    pkg_root = Path(__file__).resolve().parent.parent
    code = (
        "from runar import sha256_compress\n"
        "if __debug__:\n"
        "    raise SystemExit('-O not in effect')\n"
        "for st, blk in ((b'\\x00'*31, b'\\x00'*64), (b'\\x00'*32, b'\\x00'*63)):\n"
        "    try:\n"
        "        sha256_compress(st, blk)\n"
        "    except ValueError:\n"
        "        continue\n"
        "    raise SystemExit('accepted wrong-size operand %d/%d' % (len(st), len(blk)))\n"
        "sha256_compress(b'\\x00'*32, b'\\x00'*64)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-O", "-c", code],
        cwd=pkg_root, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
