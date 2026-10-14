"""N-264: call depth x nesting must not overflow the host stack.

Private methods are inlined at every call site, so F-213's per-method nesting
bound (128) and N-180's call-depth bound (128) compose multiplicatively: a chain
of D helpers that each call the next under K nested ifs is D*K nested ifs after
inlining. This tier refused D=32 x 120 with "maximum recursion depth exceeded"
(stack lowering recursed once per nested if, past the raised recursion limit).
User decision R106: lower iteratively, with an explicit work stack.

The source is remediation-logs/N-180/compgen.py's shape. The pinned digests are
sha256 of the script hex the UNMODIFIED Go compiler printed for the same source
(at 5b75534ec, before any N-264 change): goroutine stacks grow, so Go compiled
every depth, and its D=8 output was byte-identical to all six other tiers'.

Proves: this tier compiles D=32 x 120 (3,840 nested ifs) and the deepest
admissible chain D=127 x 120, byte-identical to Go.
Does not prove: the other tiers (conformance/negatives/
n264-composite-nesting-parity.test.ts drives all seven CLIs), nor that Go's deep
output is right beyond agreeing with every tier at D=8.
"""

from __future__ import annotations

import hashlib

import pytest

from runar_compiler.compiler import compile_from_source


def _comp(d: int, k: int) -> str:
    """remediation-logs/N-180/compgen.py, verbatim."""
    def body(i: int) -> str:
        s = "  let r: bigint = x;\n"
        s += "".join(f"  if (x > {j}n) {{\n" for j in range(k))
        s += f"  r = this.m{i + 1}(x);\n" + "  }\n" * k
        return s + "  return r;\n"
    ms = "".join(f" private m{i}(x: bigint): bigint {{\n{body(i)} }}\n" for i in range(d))
    return (
        "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n"
        + ms
        + f" private m{d}(x: bigint): bigint {{ return x; }}\n public verify(a: bigint) {{ assert(this.m0(a) == this.t); }}\n}}\n"
    )


GO_DIGEST = {
    32: "edf53286692322f6787832929bb6aaf18d2b686e9bef2ad4683cbaf3e8a25fc2",
    127: "d1a30af5609fe4b5704c58f518cb9bdd1f31fce14df88c650dcf33fe25153c53",
}


@pytest.mark.parametrize("d", [32, 127])
def test_composite_chain_compiles_byte_identical_to_go(tmp_path, d):
    src = tmp_path / f"comp{d}k120.runar.ts"
    src.write_text(_comp(d, 120))
    artifact = compile_from_source(str(src))
    assert hashlib.sha256(artifact.script.encode()).hexdigest() == GO_DIGEST[d]
