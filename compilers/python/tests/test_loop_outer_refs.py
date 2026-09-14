"""Stack lowering across unrolled for-loops -- outer-scope refs (method params,
pre-loop consts) must survive loop unrolling.

Mirrors packages/runar-compiler/src/__tests__/loop-outer-refs.test.ts.

Two related defects around unrolled for-loops:
 (a) a const defined before a loop and referenced inside it (including only
     inside a nested if-branch) was consumed by the first iteration, failing
     compilation with "Value 'X' not found on stack";
 (b) worse, a method PARAM referenced after an unrolled loop whose body also
     references it was silently lowered to an empty push (OP_0): compilation
     succeeded, the env-based interpreter passed, but the emitted Script would
     fail at runtime.

The fix: _lower_loop collects outer refs deeply (nested branches included) and
protects them in non-final iterations, and in the final iteration whenever the
enclosing scope still references them after the loop. The old silent OP_0
fallbacks in _lower_load_param / _lower_load_const are now hard errors.
"""

from __future__ import annotations

import json
import textwrap

import pytest

from runar_compiler.compiler import compile_from_ir_bytes, compile_from_source


# ---------------------------------------------------------------------------
# Sources (Python surface). snake_case identifiers map to camelCase in the AST.
# ---------------------------------------------------------------------------

# V003 repro: multi-input tx walk -- param `data` used inside AND after the loop.
LOOP_WALK_SOURCE = textwrap.dedent("""\
    from runar import SmartContract, ByteString, Bigint, public, assert_, substr, cat, bin2num

    class LoopWalk(SmartContract):
        pad00: ByteString = "00"

        def __init__(self):
            super().__init__()

        @public
        def walk(self, data: ByteString):
            off: Bigint = 5
            for i in range(3):
                if i < bin2num(cat(substr(data, 4, 1), self.pad00)):
                    sl: Bigint = bin2num(cat(substr(data, off + 36, 1), self.pad00))
                    assert_(sl < 253)
                    off = off + 36 + 1 + sl + 4
            tail: Bigint = bin2num(cat(substr(data, off, 1), self.pad00))
            assert_(tail == 7)
""")

# Symptom (a): const defined before the loop, referenced inside it.
CONST_BEFORE_LOOP_SOURCE = textwrap.dedent("""\
    from runar import SmartContract, ByteString, Bigint, public, assert_, substr, cat, bin2num

    class ConstLoop(SmartContract):
        pad00: ByteString = "00"

        def __init__(self):
            super().__init__()

        @public
        def probe(self, data: ByteString):
            base: Bigint = 5
            acc: Bigint = 0
            for i in range(3):
                b: Bigint = bin2num(cat(substr(data, base + i, 1), self.pad00))
                acc = acc + b
            assert_(acc == 6)
""")


# A loop-carried local REASSIGNED and then READ AGAIN in the same iteration.
# The rebinding shadows the incoming slot under the same name; the later read
# was its last body use, so it consumed the UPDATED value and left the dead
# incoming one for the next iteration to resolve. `wacc` came out as `step*N`
# instead of `step*N*(N+1)/2` -- silently in a stateless contract, and as a
# permanently unspendable UTXO in a stateful one. Real-VM proof:
# packages/runar-testing/src/__tests__/loop-carried-local-read-after-reassign-vm.test.ts
CARRIED_REBIND_SOURCE = """import { SmartContract, assert } from 'runar-lang';

class LoopCarriedRebind extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    let wacc = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + step;
      wacc = wacc + acc;
    }
    assert(wacc === this.expected);
  }
}
"""

# Control: the same loop with a single self-accumulating carrier -- no read
# after the rebinding. Its bytes must NOT move, or the carried-rebind fix has
# been written too wide and every shipped BoundedLoop-shaped contract pays.
# R-186 / R-292 re-stamped this pin on 2026-09-14: the accumulator body leaves
# the carried local on top, so the iteration variable sat one slot down and
# `lowerLoop`'s `depth == 0` cleanup never fired. The control still says what it
# was written to say about the carried-rebind fix; it no longer pins the bytes
# that predate it.
PLAIN_ACCUMULATOR_SOURCE = """import { SmartContract, assert } from 'runar-lang';

class LoopPlainAccumulator extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + step;
    }
    assert(acc === this.expected);
  }
}
"""

# The same cross-read one loop deeper. The predicate keys on the body's
# TOP-LEVEL binding names, and at the OUTER level `acc` is bound only inside the
# nested loop -- so it was neither an outer ref nor a carried rebind, and every
# outer iteration restarted from the slot the previous one left behind. `wacc`
# came out 24 where the source says 30 (step = 3). Real-VM proof:
# packages/runar-testing/src/__tests__/nested-loop-carried-local-vm.test.ts
NESTED_CARRIED_REBIND_SOURCE = """import { SmartContract, assert } from 'runar-lang';

class LoopNestedCarriedRebind extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    let wacc = 0n;
    for (let i = 0n; i < 2n; i++) {
      for (let j = 0n; j < 2n; j++) {
        acc = acc + step;
        wacc = wacc + acc;
      }
    }
    assert(wacc === this.expected);
  }
}
"""

# Control: NESTED loops with a single self-accumulating carrier. The flatten
# step fires here (the body does contain a nested loop) but the predicate still
# says "not carried", so the bytes must NOT move -- that is what keeps nesting
# itself from costing anything.
# R-186 / R-292 re-stamped this pin on 2026-09-14 as well. Nesting still costs
# nothing -- the single-level accumulator moved by exactly the same change.
NESTED_PLAIN_ACCUMULATOR_SOURCE = """import { SmartContract, assert } from 'runar-lang';

class LoopNestedPlainAccumulator extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    for (let i = 0n; i < 2n; i++) {
      for (let j = 0n; j < 2n; j++) {
        acc = acc + step;
      }
    }
    assert(acc === this.expected);
  }
}
"""

# Byte-identical across all seven compiler tiers (fold-OFF).
CARRIED_REBIND_HEX = "000000537953797c937b78937b7551547a53797c937b7c9377009c7777"
PLAIN_ACCUMULATOR_HEX = "000052797b7c9377517b7b7c9377009c"
NESTED_CARRIED_REBIND_HEX = (
    "00000000547954797c93537a78937b7551557953797c937b78937b75537a755100567954"
    "797c93537a78937b7551577a53797c937b7c93777b75009c77777777"
)
NESTED_PLAIN_ACCUMULATOR_HEX = (
    "0000005379537a7c93775153797b7c93777751005379537a7c937751537a7b7c937777009c"
)


def _compile(tmp_path, source: str, name: str):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return compile_from_source(str(path))


def _compile_hex(tmp_path, source: str, name: str) -> str:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return compile_from_source(str(path), disable_constant_folding=True).script


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestLoopCarriedRebind:
    def test_local_reassigned_then_read_again_survives_the_iteration(self, tmp_path):
        script = _compile_hex(
            tmp_path, CARRIED_REBIND_SOURCE, "LoopCarriedRebind.runar.ts"
        )
        assert script == CARRIED_REBIND_HEX

    def test_plain_accumulator_loop_is_untouched(self, tmp_path):
        script = _compile_hex(
            tmp_path, PLAIN_ACCUMULATOR_SOURCE, "LoopPlainAccumulator.runar.ts"
        )
        assert script == PLAIN_ACCUMULATOR_HEX

    def test_nested_cross_read_survives_the_iteration(self, tmp_path):
        script = _compile_hex(
            tmp_path, NESTED_CARRIED_REBIND_SOURCE, "LoopNestedCarriedRebind.runar.ts"
        )
        assert script == NESTED_CARRIED_REBIND_HEX

    def test_nested_plain_accumulator_is_untouched(self, tmp_path):
        script = _compile_hex(
            tmp_path,
            NESTED_PLAIN_ACCUMULATOR_SOURCE,
            "LoopNestedPlainAccumulator.runar.ts",
        )
        assert script == NESTED_PLAIN_ACCUMULATOR_HEX


class TestLoopOuterRefs:
    def test_param_after_loop_not_lowered_to_empty_push(self, tmp_path):
        # The post-loop code reads `data` via substr(data, off, 1). With the
        # bug, `data` was emitted as OP_0 right after the final OP_ENDIF; the
        # fix brings the real param up. Compilation must succeed and the
        # post-loop region must not carry a bare OP_0 placeholder.
        artifact = _compile(tmp_path, LOOP_WALK_SOURCE, "LoopWalk.runar.py")
        assert len(artifact.script) > 0
        asm = artifact.asm
        post_loop = asm[asm.rfind("OP_ENDIF"):]
        assert "OP_0" not in post_loop, (
            f"post-loop region carries an OP_0 placeholder: {post_loop!r}"
        )

    def test_const_before_loop_referenced_inside_compiles(self, tmp_path):
        # Previously: "Value 'base' not found on stack (...)" on iteration 2.
        artifact = _compile(tmp_path, CONST_BEFORE_LOOP_SOURCE, "ConstLoop.runar.py")
        assert len(artifact.script) > 0

    def test_load_param_that_cannot_be_satisfied_is_loud_error_not_op0(self):
        # Hand-written ANF referencing a parameter the method does not have --
        # the old code silently emitted OP_0 here.
        ir = json.dumps({
            "contractName": "Broken",
            "properties": [],
            "methods": [
                {
                    "name": "run",
                    "params": [{"name": "x", "type": "bigint"}],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_param", "name": "ghost"}},
                        {"name": "t1", "value": {"kind": "assert", "value": "t0"}},
                    ],
                    "isPublic": True,
                }
            ],
        }).encode("utf-8")

        with pytest.raises(RuntimeError, match="Refusing to emit a silent OP_0"):
            compile_from_ir_bytes(ir)

    def test_load_const_ref_that_cannot_be_satisfied_is_loud_error_not_op0(self):
        # Hand-written ANF aliasing (@ref:) a binding that is not on the stack.
        ir = json.dumps({
            "contractName": "Broken",
            "properties": [],
            "methods": [
                {
                    "name": "run",
                    "params": [{"name": "x", "type": "bigint"}],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_const", "value": "@ref:ghost"}},
                        {"name": "t1", "value": {"kind": "assert", "value": "t0"}},
                    ],
                    "isPublic": True,
                }
            ],
        }).encode("utf-8")

        with pytest.raises(RuntimeError, match="Refusing to emit a silent OP_0"):
            compile_from_ir_bytes(ir)
