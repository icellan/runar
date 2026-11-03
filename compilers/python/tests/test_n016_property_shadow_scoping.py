"""N-016 — a local that shares a contract property's name must never capture a
later ``this.<prop>`` read or write (user decision R8: correct scoping). Port of
packages/runar-compiler/src/__tests__/n016-property-shadow-scoping.test.ts.

``const target = n + 1n; assert(target == this.target);`` compiled to 8b769c
(OP_1ADD OP_DUP OP_NUMEQUAL): the property read resolved by name to the local's
stack slot, an always-true self-comparison.

Oracle: alpha-equivalence, from the source language rather than compiler
output. Renaming a local / private-helper param / public param to a fresh name
cannot change the program's meaning, so each template compiled with ``$L`` =
the property's name must produce exactly the bytes of ``$L`` = ``lcl``, in both
constant-folding modes.

Proves: in the Python tier, property-named locals (top level, if-arm, nested
block, loop variable, ++, byte-typed, inside a private helper), a private
helper's param and a public param never capture ``this.<prop>``; stateful
property reads/writes and the continuation are unaffected by a same-named
local, including an if whose arms rebind the local and write the property.
Does NOT prove: on-chain behaviour (see
packages/runar-testing/src/__tests__/n016-property-shadow-spend.test.ts) or
local-vs-compiler-temp collisions (a local literally named ``t3``).
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result


def _stateless(body: str, prop_type: str = "bigint") -> str:
    return f"""import {{ SmartContract, assert, cat, ByteString }} from 'runar-lang';

class Shadow extends SmartContract {{
  readonly target: {prop_type};
  constructor(target: {prop_type}) {{
    super(target);
    this.target = target;
  }}

{body}
}}
"""


def _stateful(body: str) -> str:
    return f"""import {{ StatefulSmartContract, assert }} from 'runar-lang';

class Shadow extends StatefulSmartContract {{
  count: bigint;

  constructor(count: bigint) {{
    super(count);
    this.count = count;
  }}

{body}
}}
"""


SHAPES = [
    ("local at method top level", "target", _stateless("""  public unlock(n: bigint) {
    const $L = n + 1n;
    assert($L == this.target);
  }""")),
    ("local inside an if-arm", "target", _stateless("""  public unlock(n: bigint) {
    if (n > 0n) {
      const $L = n + 1n;
      assert($L == this.target);
    } else {
      assert(n == this.target);
    }
  }""")),
    ("local inside a nested block", "target", _stateless("""  public unlock(n: bigint) {
    if (n > 0n) {
      if (n > 1n) {
        const $L = n + 1n;
        assert($L == this.target);
      } else {
        assert(n + 2n == this.target);
      }
    } else {
      assert(false);
    }
  }""")),
    ("loop variable", "target", _stateless("""  public unlock(n: bigint) {
    let acc = 0n;
    for (let $L = 0n; $L < 2n; $L++) {
      acc = acc + this.target - $L;
    }
    assert(acc == n);
  }""")),
    ("local mutated with ++", "target", _stateless("""  public unlock(n: bigint) {
    let $L = n;
    $L++;
    assert($L == this.target);
  }""")),
    ("byte-typed local", "target", _stateless("""  public unlock(a: ByteString) {
    const $L = cat(a, a);
    assert($L == this.target);
  }""", "ByteString")),
    ("local inside a private helper", "target", _stateless("""  private chk(n: bigint): boolean {
    const $L = n + 1n;
    return $L == this.target;
  }

  public unlock(n: bigint) {
    assert(this.chk(n));
  }""")),
    ("private helper parameter", "target", _stateless("""  private chk($L: bigint): boolean {
    return this.target == $L + 1n;
  }

  public unlock(n: bigint) {
    assert(this.chk(n));
  }""")),
    ("public parameter, property read first", "target", _stateless("""  public unlock($L: bigint) {
    assert(this.target == $L + 1n);
  }""")),
    ("stateful: local, then property read + write", "count", _stateful("""  public bump(n: bigint) {
    const $L = n * 2n;
    this.count = this.count + $L;
    assert($L > 0n);
  }""")),
    ("stateful: local live across a property write", "count", _stateful("""  public bump(n: bigint) {
    let $L = n;
    this.count = this.count + 1n;
    assert(this.count > $L);
  }""")),
    ("stateful: if-arms rebind the local and write the property", "count", _stateful("""  public bump(n: bigint) {
    let $L = n;
    if (n > 3n) {
      $L = $L + 1n;
      this.count = this.count + $L;
    } else {
      this.count = this.count + 1n;
    }
  }""")),
    ("stateful: an if-arm writes the property, then rebinds the local read after the if", "count", _stateful("""  public bump(n: bigint) {
    let $L = n;
    if (n > 3n) {
      this.count = this.count + $L;
      $L = $L + 1n;
    } else {
      this.count = this.count + 1n;
    }
    assert($L > 0n);
  }""")),
]


def _hex(source: str, disable: bool) -> str:
    result = compile_from_source_str_with_result(
        source, "Shadow.runar.ts", disable_constant_folding=disable,
    )
    if not result.success:
        msgs = "; ".join(d.message for d in result.diagnostics)
        pytest.fail(f"compilation failed: {msgs}")
    return result.script_hex


def test_probe_no_longer_self_compares():
    src = SHAPES[0][2].replace("$L", "target")
    assert _hex(src, True) == "8b009c"


@pytest.mark.parametrize("disable", [True, False])
@pytest.mark.parametrize("label,prop,template", SHAPES, ids=[s[0] for s in SHAPES])
def test_shadowing_compiles_like_renamed_spelling(label, prop, template, disable):
    shadow = _hex(template.replace("$L", prop), disable)
    control = _hex(template.replace("$L", "lcl"), disable)
    assert shadow == control, f"{label}: shadowing spelling compiled differently"
