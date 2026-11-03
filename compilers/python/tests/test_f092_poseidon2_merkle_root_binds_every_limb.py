"""F-092 (CL-BUG-145): ``merkleRootPoseidon2KB`` must authenticate ALL EIGHT
KoalaBear limbs of the Poseidon2 Merkle root, not just ``root_7``.

The Python source path refuses this builtin as Go-only (R-258), but the
``--ir`` path runs no typecheck and lowers it through
``_lower_merkle_root_poseidon2_kb``. That lowering used to reconcile the eight
limbs the emitter leaves on the stack with seven ``OP_NIP``s, keeping only
``root_7``: ``assert(merkleRootPoseidon2KB(...) === expected)`` then
authenticated a single ~31-bit field element. The Go reference fixed the same
truncation in R-056 / CL-BUG-099 by packing the eight limbs base-2^32
(``EmitPoseidon2RootPack``, root_7 most significant). Under the Go-only-parity
policy a non-Go port must match Go byte for byte or refuse; this tier now
matches Go (the byte-identity half is gated by
``conformance/go-only-parity/go-only-parity.test.ts``).

What this proves: the Python-compiled script, EXECUTED on bsv-sdk's ``Spend``
for a depth-1 proof whose true root is an independent Plonky3 ``compress``
vector (``tests/vectors/poseidon2_koalabear.json``), accepts the honest
base-2^32-packed root, rejects the old truncated answer (``root_7`` alone), and
rejects a packed root that differs from the true one in exactly one limb, for
each of the eight limbs.

What it does not prove: anything about depth > 1 or index != 0 (the emitter's
permutation and sibling ordering are shared with Go and gated by Go's own
execution tests plus the byte-identity check), nor resistance to a real
second-preimage — tampering the expected root in limb i is the decidable dual
of "limb i is load-bearing in the on-chain comparison".
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_ir_bytes


def _spec_missing(module_name: str) -> bool:
    """``importlib.util.find_spec`` for a dotted name imports its parent
    packages first and raises ``ModuleNotFoundError`` if one is absent
    (e.g. ``runar`` not on ``PYTHONPATH``), rather than returning ``None``
    the way it does for a missing top-level module. Treat either outcome
    as "missing"."""
    try:
        return importlib.util.find_spec(module_name) is None
    except ModuleNotFoundError:
        return True


# N-209: in CI we want a missing `bsv-sdk`, or a `runar-py` not on
# PYTHONPATH, to be loud, not a silent skip — mirrors
# packages/runar-py/tests/test_script_vm.py's T-8 guard
# (audits/cross-language-completeness-20260514.md §5.2) for both of this
# file's optional dependencies.
if os.environ.get("CI") and _spec_missing("bsv"):
    pytest.fail(
        "test_f092_poseidon2_merkle_root_binds_every_limb.py: CI environment "
        "detected ($CI is set) but the optional `bsv-sdk` package is not "
        "installed — this module's tests would silently skip. Install the "
        "`script-vm` extra in CI (`pip install runar[script-vm]` or "
        "`pip install bsv-sdk`). See "
        "audits/cross-language-completeness-20260514.md T-8.",
        pytrace=False,
    )
if os.environ.get("CI") and _spec_missing("runar.sdk.script_vm"):
    pytest.fail(
        "test_f092_poseidon2_merkle_root_binds_every_limb.py: CI environment "
        "detected ($CI is set) but `runar.sdk.script_vm` is not importable "
        "— `packages/runar-py` is missing from PYTHONPATH and this "
        "module's tests would silently skip. Set PYTHONPATH to include "
        "`packages/runar-py` in CI (see `.github/workflows/ci.yml`'s "
        "`python-compiler` job). See "
        "audits/cross-language-completeness-20260514.md T-8.",
        pytrace=False,
    )

pytest.importorskip("bsv", reason="bsv-sdk not installed (runar[script-vm] extra)")
script_vm = pytest.importorskip(
    "runar.sdk.script_vm", reason="runar-py not installed / on PYTHONPATH"
)

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS = REPO_ROOT / "tests" / "vectors" / "poseidon2_koalabear.json"
BASE = 1 << 32


def _probe_ir() -> bytes:
    """ANF IR for `assert(merkleRootPoseidon2KB(l0..l7, s0_0..s0_7, idx, 1n) === expected)`,
    the shape the Go tier emits for that source (``--emit-ir``)."""
    names = [f"l{i}" for i in range(8)] + [f"s0_{i}" for i in range(8)] + ["idx"]
    params = [{"name": n, "type": "bigint"} for n in names + ["expected"]]
    body = [
        {"name": f"t{i}", "value": {"kind": "load_param", "name": n}}
        for i, n in enumerate(names)
    ]
    body += [
        {"name": "t17", "value": {"kind": "load_const", "value": 1}},
        {"name": "t18", "value": {"kind": "call", "func": "merkleRootPoseidon2KB",
                                  "args": [f"t{i}" for i in range(18)]}},
        {"name": "t19", "value": {"kind": "load_param", "name": "expected"}},
        {"name": "t20", "value": {"kind": "bin_op", "op": "===", "left": "t18", "right": "t19"}},
        {"name": "t21", "value": {"kind": "assert", "value": "t20"}},
    ]
    program = {
        "contractName": "P2KBRootBinding",
        "parentClass": "SmartContract",
        "properties": [],
        "methods": [
            {"name": "constructor", "isPublic": False, "params": [],
             "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
            {"name": "verify", "isPublic": True, "params": params, "body": body},
        ],
    }
    return json.dumps(program).encode("utf-8")


def _push_num(n: int) -> bytes:
    """Minimal push of a non-negative Script number."""
    if n == 0:
        return b"\x00"
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    data = bytearray()
    while n:
        data.append(n & 0xFF)
        n >>= 8
    if data[-1] & 0x80:
        data.append(0)
    if len(data) <= 75:
        return bytes([len(data)]) + bytes(data)
    raise AssertionError("push too large for this probe")


def _pack(limbs: list[int]) -> int:
    return sum(v * BASE**i for i, v in enumerate(limbs))


def _vector() -> dict:
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    for v in data["vectors"]:
        # A vector with non-zero inputs and eight distinct limbs, so a fold that
        # ignores or swaps limbs cannot pass by coincidence.
        if (v["op"] == "compress" and any(v["left"]) and any(v["right"])
                and len(set(v["expected"])) == 8):
            return v
    raise AssertionError(f"no usable compress vector in {VECTORS}")


@pytest.fixture(scope="module")
def locking() -> bytes:
    return bytes.fromhex(compile_from_ir_bytes(_probe_ir()).script)


def _spend(locking: bytes, v: dict, expected: int):
    unlocking = b"".join(_push_num(x) for x in v["left"] + v["right"] + [0, expected])
    return script_vm.ScriptVM().execute(unlocking, locking)


def test_honest_packed_root_is_accepted(locking):
    v = _vector()
    r = _spend(locking, v, _pack(v["expected"]))
    assert r.success, f"honest base-2^32-packed root must be accepted: {r.error}"


def test_truncated_root7_alone_is_rejected(locking):
    v = _vector()
    r = _spend(locking, v, v["expected"][7])
    assert not r.success, (
        "the script accepted root_7 ALONE as the Merkle root -- limbs 0..6 are "
        "discarded, so the check authenticates one ~31-bit field element"
    )


@pytest.mark.parametrize("limb", range(8))
def test_every_limb_is_load_bearing(locking, limb):
    v = _vector()
    tampered = list(v["expected"])
    tampered[limb] = (tampered[limb] + 1) % 2130706433
    r = _spend(locking, v, _pack(tampered))
    assert not r.success, f"perturbing root limb {limb} must make the spend fail"
