"""F-260 (CL-BUG-154): ``merkleRootPoseidon2KB``'s caller-side depth guard
admitted 1..64 while ``emit_poseidon2_merkle_root`` refuses anything above 32.

Depths 33..64 passed the gate in ``_lower_merkle_root_poseidon2_kb`` and then
died in the emitter under a message naming ``emit_poseidon2_merkle_root`` -- a
function the author never called -- while the gate's own message (shown for
depth >= 65) told the author 64 was allowed. The Go reference fixed the same
split in R-172 (``compilers/go/compiler/r172_p2kb_merkle_depth_test.go``) by
narrowing the caller's interval to 32 and reporting
``merkleRootPoseidon2KB: depth must be between 1 and 32, got N``. Under the
Go-only-family policy (R58) this non-Go port must refuse exactly what Go
refuses; this test pins that.

The Python source path refuses this builtin as Go-only (R-258), so the only
way to reach the lowering is ``--ir`` (``compile_from_ir_bytes``), which is
what the test drives.

What this proves: through the ``--ir`` path, depths 33, 40, 64 and 65 are
refused by the builtin's own gate, with a message that names
``merkleRootPoseidon2KB``, states 32 as the limit, does not name the internal
emitter and does not offer 64 as the limit; depths 1 and 32 still compile.

What it does not prove: anything about the emitted bytes (byte identity with
Go is gated by ``conformance/go-only-parity``), nor anything about the
``merkleRootSha256`` sibling, whose 1..64 gate is unchanged and correct.
"""

from __future__ import annotations

import json

import pytest

from runar_compiler.compiler import compile_from_ir_bytes


def _ir(depth: int) -> bytes:
    """ANF IR for ``assert(merkleRootPoseidon2KB(l0..l7, s*_*, idx, <depth>n) === expected)``."""
    names = [f"l{i}" for i in range(8)]
    names += [f"s{lvl}_{i}" for lvl in range(depth) for i in range(8)]
    names += ["idx"]
    params = [{"name": n, "type": "bigint"} for n in names + ["expected"]]
    body = [
        {"name": f"t{i}", "value": {"kind": "load_param", "name": n}}
        for i, n in enumerate(names)
    ]
    k = len(names)
    body += [
        {"name": f"t{k}", "value": {"kind": "load_const", "value": depth}},
        {"name": f"t{k + 1}", "value": {"kind": "call", "func": "merkleRootPoseidon2KB",
                                        "args": [f"t{i}" for i in range(k + 1)]}},
        {"name": f"t{k + 2}", "value": {"kind": "load_param", "name": "expected"}},
        {"name": f"t{k + 3}", "value": {"kind": "bin_op", "op": "===",
                                        "left": f"t{k + 1}", "right": f"t{k + 2}"}},
        {"name": f"t{k + 4}", "value": {"kind": "assert", "value": f"t{k + 3}"}},
    ]
    program = {
        "contractName": "P2KBDepth",
        "parentClass": "SmartContract",
        "properties": [],
        "methods": [
            {"name": "constructor", "isPublic": False, "params": [],
             "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
            {"name": "verify", "isPublic": True, "params": params, "body": body},
        ],
    }
    return json.dumps(program).encode("utf-8")


@pytest.mark.parametrize("depth", [1, 32])
def test_legal_depths_still_compile(depth: int) -> None:
    artifact = compile_from_ir_bytes(_ir(depth))
    assert artifact.script, f"depth {depth} produced an empty script"


@pytest.mark.parametrize("depth", [33, 40, 64, 65])
def test_depths_above_32_are_refused_by_the_builtin(depth: int) -> None:
    with pytest.raises(Exception) as exc_info:
        compile_from_ir_bytes(_ir(depth))
    msg = str(exc_info.value)
    assert "merkleRootPoseidon2KB" in msg, msg
    assert "emit_poseidon2_merkle_root" not in msg, msg
    assert "between 1 and 32" in msg, msg
    # "64" alone would match the reported depth; check the spelling of a LIMIT.
    assert "and 64" not in msg and "1, 64" not in msg, msg
