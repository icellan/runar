"""Runtime vectors — cross-SDK consistency check.

Loads ``conformance/runtime-vectors/hashes.json`` (the cross-SDK source of
truth for ``sha256Finalize``, ``blake3Compress``, and ``blake3Hash`` outputs)
and asserts that the Python SDK's runtime helpers in ``runar.builtins``
produce the documented output byte-for-byte. Every other consumer (TS /
Java / Go / Rust / Zig / Ruby) loads the same file and runs the equivalent
assertion; a divergence between any two runtime impls shows up here.

Reference: ``_consumers`` in the JSON file enumerates the per-SDK tests
that share these vectors.
"""

import json
from pathlib import Path

import pytest

from runar.builtins import blake3_compress, blake3_hash, sha256_finalize


def _vectors_path() -> Path:
    """Walk up from this file until we find ``conformance/runtime-vectors/``."""
    here = Path(__file__).resolve()
    for ancestor in (here, *here.parents):
        candidate = ancestor / "conformance" / "runtime-vectors" / "hashes.json"
        if candidate.is_file():
            return candidate
    raise RuntimeError(
        "could not locate conformance/runtime-vectors/hashes.json "
        f"walking up from {here}"
    )


def _load_vectors() -> dict:
    return json.loads(_vectors_path().read_text())


VECTORS = _load_vectors()


@pytest.mark.parametrize(
    "case",
    VECTORS["sha256_finalize"],
    ids=lambda v: v["name"],
)
def test_sha256_finalize(case: dict) -> None:
    state = bytes.fromhex(case["state"])
    remaining = bytes.fromhex(case["remaining"])
    got = sha256_finalize(state, remaining, case["msg_bit_len"])
    assert got.hex() == case["expected"], (
        f"sha256_finalize({case['name']}) mismatch"
    )


@pytest.mark.parametrize(
    "case",
    VECTORS["blake3_compress"],
    ids=lambda v: v["name"],
)
def test_blake3_compress(case: dict) -> None:
    state = bytes.fromhex(case["state"])
    block = bytes.fromhex(case["block"])
    got = blake3_compress(state, block)
    assert got.hex() == case["expected"], (
        f"blake3_compress({case['name']}) mismatch"
    )


@pytest.mark.parametrize(
    "case",
    VECTORS["blake3_hash"],
    ids=lambda v: v["name"],
)
def test_blake3_hash(case: dict) -> None:
    inp = bytes.fromhex(case["input"])
    got = blake3_hash(inp)
    assert got.hex() == case["expected"], (
        f"blake3_hash({case['name']}) mismatch"
    )


def test_constants() -> None:
    # BLAKE3 deliberately reuses the SHA-256 IV. Catching a constant-table
    # typo against the JSON source is the whole point of this row.
    assert (
        VECTORS["constants"]["blake3_iv"] == VECTORS["constants"]["sha256_iv"]
    ), "blake3_iv must equal sha256_iv (BLAKE3 spec)"
    cv = bytes.fromhex(VECTORS["constants"]["blake3_iv"])
    zero_block = b"\x00" * 64
    got = blake3_compress(cv, zero_block)
    assert len(got) == 32, "blake3_compress(IV, zeros) must yield 32 bytes"
