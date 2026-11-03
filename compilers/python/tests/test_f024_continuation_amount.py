"""F-024 (CL-BUG-079, user decision R14) -- Python-tier port of
packages/runar-compiler/src/__tests__/f024-continuation-amount.test.ts.

Proves (Python tier, TS surface): every default single-output continuation
carries the injected ``assert(_newAmount >= extractAmount(txPreimage))`` ANF
(load_param txPreimage; call extractAmount; load_param _newAmount; bin_op >=;
assert) after the body; addOutput and terminal methods do not;
``continuationAmount()`` lowers to load_param _newAmount where that witness
exists and is refused everywhere else; a write to it is refused.
Does NOT prove on-chain rejection of a drain (the TS Spend test does) or
cross-tier byte parity (conformance).
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result
from runar_compiler.frontend.diagnostic import Severity

COUNTER = """
class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count = this.count + 1n; }
  public addTo(amount: bigint) { this.addOutput(1000n, this.count + amount); }
  public close() { assert(this.count > 0n); }
  public log(payload: ByteString) { this.addDataOutput(0n, payload); }
}
"""

READ_ONLY = "continuationAmount() is read-only and cannot be assigned"
UNAVAILABLE = (
    "continuationAmount() is only available in a public StatefulSmartContract method whose state "
    "continues through the default single-output continuation"
)


def _pot(body: str) -> str:
    return (
        "class Pot extends StatefulSmartContract {\n  count: bigint;\n"
        "  constructor(count: bigint) { super(count); this.count = count; }\n  "
        + body + "\n}\n"
    )


def _compile(src: str):
    return compile_from_source_str_with_result(src, "C.runar.ts", disable_constant_folding=True)


def _errors(r) -> str:
    return " | ".join(d.format_message() for d in r.diagnostics if d.severity == Severity.ERROR)


def _public(anf, name):
    for m in anf.methods:
        if m.name == name and m.is_public:
            return m
    raise AssertionError(f"no public method {name}")


def _kinds(body):
    return [f"call:{b.value.func}" if b.value.kind == "call" else b.value.kind for b in body]


def _injected_check_at(body):
    hits = []
    for i in range(len(body) - 4):
        a, b, c, d, e = (x.value for x in body[i:i + 5])
        n = [x.name for x in body[i:i + 5]]
        if (a.kind == "load_param" and a.name == "txPreimage"
                and b.kind == "call" and b.func == "extractAmount" and b.args == [n[0]]
                and c.kind == "load_param" and c.name == "_newAmount"
                and d.kind == "bin_op" and d.op == ">=" and d.left == n[2] and d.right == n[1]
                and e.kind == "assert" and e.value_ref == n[3]):
            hits.append(i)
    return hits


def test_default_continuation_carries_the_value_check():
    r = _compile(COUNTER)
    assert r.success, _errors(r)
    body = _public(r.anf, "increment").body
    hits = _injected_check_at(body)
    assert len(hits) == 1, _kinds(body)
    k = _kinds(body)
    assert "update_prop" in k[:hits[0]]
    for want in ("if", "get_state_script", "call:computeStateOutput"):
        assert want in k[hits[0] + 5:], (want, k)
    assert body[hits[0] + 4].value.is_auto_injected_state_check is False
    assert len(_injected_check_at(_public(r.anf, "log").body)) == 1
    for name in ("addTo", "close"):
        m = _public(r.anf, name)
        assert "_newAmount" not in [p.name for p in m.params]
        assert "call:extractAmount" not in _kinds(m.body)


def test_continuation_amount_read_lowers_to_new_amount():
    r = _compile(_pot(
        "public join(bet: bigint) {\n"
        "    assert(continuationAmount() == extractAmount(this.txPreimage) + bet);\n"
        "    this.count = this.count + 1n;\n  }"
    ))
    assert r.success, _errors(r)
    body = _public(r.anf, "join").body
    hits = _injected_check_at(body)
    assert len(hits) == 1
    first = next(i for i, b in enumerate(body) if b.value.kind == "load_param" and b.value.name == "_newAmount")
    assert first < hits[0]


STATELESS = """
class P extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public unlock() { assert(continuationAmount() > this.x); }
}
"""


@pytest.mark.parametrize("name,src,want", [
    ("write", _pot("public join() { continuationAmount() = 5n; this.count = this.count + 1n; }"), READ_ONLY),
    ("increment", _pot("public join() { continuationAmount()++; this.count = this.count + 1n; }"), READ_ONLY),
    ("stateless", STATELESS, "continuationAmount() is only available in StatefulSmartContract methods"),
    ("terminal", _pot("public close() { assert(continuationAmount() > 0n); }"), UNAVAILABLE),
    ("addOutput", _pot("public split() { this.addOutput(continuationAmount(), this.count); }"), UNAVAILABLE),
    ("private", _pot("private amt(): bigint { return continuationAmount(); }\n"
                     "  public bump() { this.count = this.count + this.amt(); }"), UNAVAILABLE),
])
def test_continuation_amount_refusals(name, src, want):
    r = _compile(src)
    assert not r.success, f"{name}: expected a refusal, it compiled"
    assert want in _errors(r), (name, _errors(r))
