"""N-180: the shared call-depth limit, MAX_CALL_DEPTH = 128.

A chain of private helpers ``verify -> m0 -> m1 -> ... -> mN`` is flat source
(MAX_SOURCE_NESTING never fires) but N+1 nested inlinings. Before N-180 this
tier answered an 8000-link chain with whatever ``maximum recursion depth
exceeded`` surfaced first, and its recursion check restarted its DFS from every
method (quadratic).

Proves, on the .ts, .sol (bare ``m(x)`` calls) and .py surfaces: the chain at
the limit (N=127, verify at depth 128) passes validation; one past (N=128) is
refused with the shared diagnostic naming ``verify``; N=20000 is refused naming
``m0``, promptly, with no RecursionError; and a cycle is still the recursion
diagnostic, once per method that reaches it.

Does not prove: that the other surfaces agree, or that the accepted chain
compiles to the TS bytes (conformance/negatives/n180-call-depth-parity.test.ts
drives every CLI on all nine surfaces), nor anything about the --ir JSON path.
"""

from __future__ import annotations

import time

import pytest

from runar_compiler.frontend.input_limits import MAX_CALL_DEPTH
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate


def _diag(m: str) -> str:
    return f"call depth of method '{m}' exceeds MAX_CALL_DEPTH (limit=128)"


def _chain(ext: str, n: int) -> str:
    if ext == "ts":
        return (
            "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n"
            + "".join(f" private m{i}(x: bigint): bigint {{ return this.m{i + 1}(x); }}\n" for i in range(n))
            + f" private m{n}(x: bigint): bigint {{ return x; }}\n public verify(a: bigint) {{ assert(this.m0(a) == this.t); }}\n}}\n"
        )
    if ext == "sol":
        return (
            "pragma runar ^0.1.0;\ncontract P is SmartContract {\n int immutable t;\n constructor(int _t) { t = _t; }\n"
            + "".join(f" function m{i}(int x) private returns (int) {{ return m{i + 1}(x); }}\n" for i in range(n))
            + f" function m{n}(int x) private returns (int) {{ return x; }}\n function verify(int a) public {{ require(m0(a) == t); }}\n}}\n"
        )
    assert ext == "py"
    return (
        "from runar import SmartContract, Bigint, public, assert_\n\nclass P(SmartContract):\n    t: Bigint\n\n    def __init__(self, t: Bigint):\n        super().__init__(t)\n        self.t = t\n\n"
        + "".join(f"    def m{i}(self, x: Bigint) -> Bigint:\n        return self.m{i + 1}(x)\n\n" for i in range(n))
        + f"    def m{n}(self, x: Bigint) -> Bigint:\n        return x\n\n    @public\n    def verify(self, a: Bigint):\n        assert_(self.m0(a) == self.t)\n"
    )


def _errors(src: str, file: str) -> list[str]:
    parsed = parse_source(src, file)
    assert parsed.contract is not None, [e.message for e in parsed.errors]
    return [d.message for d in validate(parsed.contract).errors]


def test_max_call_depth_is_128():
    assert MAX_CALL_DEPTH == 128


@pytest.mark.parametrize("ext", ["ts", "sol", "py"])
def test_chain_boundary(ext: str):
    file = f"P.runar.{ext}"
    assert _errors(_chain(ext, 127), file) == []
    assert _errors(_chain(ext, 128), file) == [_diag("verify")]


@pytest.mark.parametrize("ext", ["ts", "sol", "py"])
def test_chain_of_20000_is_refused_promptly(ext: str):
    src = _chain(ext, 20000)
    start = time.monotonic()
    errs = _errors(src, f"P.runar.{ext}")
    assert errs == [_diag("m0")]
    assert time.monotonic() - start < 60, "quadratic call-graph walk?"


def test_cycle_is_still_reported_as_recursion():
    src = (
        "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n"
        " private a(x: bigint): bigint { return this.b(x); }\n"
        " private b(x: bigint): bigint { return this.c(x); }\n"
        " private c(x: bigint): bigint { return this.b(x); }\n"
        " private d(x: bigint): bigint { return x; }\n"
        " public verify(v: bigint) { assert(this.a(v) + this.d(v) == this.t); }\n}\n"
    )
    want = [f"recursion detected: method '{m}' calls itself directly or indirectly" for m in ["a", "b", "c", "verify"]]
    assert _errors(src, "P.runar.ts") == want
