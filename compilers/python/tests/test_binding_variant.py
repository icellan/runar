"""Ports #170 (original design: brendan-elas, #167): the C=1 Any-S binding and
the ``@bindingVariant`` directive in the Python tier.

The two blobs are pinned here as literals so a Python-only drift fails this
file; execution of the same bytes through @bsv/sdk Spend lives in
packages/runar-testing/src/__tests__/binding-variant.test.ts.
"""

from __future__ import annotations

import json

import pytest

from runar_compiler.__main__ import _anf_to_camel_dict
from runar_compiler.compiler import compile_from_ir_bytes, compile_from_source_str_with_result

# 422 bytes: s = lowS((z+1) mod n), C=1 key 038ff83d...
LOWS_HEX = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"
# 376 bytes: s = z+1, no mod-n, no low-S (nVersion > 1 only).
ALL_HEX = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"


def _counter(directive: str) -> str:
    return (
        "class C extends StatefulSmartContract {\n"
        "  count: bigint;\n"
        "  constructor(count: bigint) { super(count); this.count = count; }\n"
        f"  {directive}\n"
        "  public bump() { this.count++; }\n"
        "}\n"
    )


def _compile(src: str, file_name: str = "C.runar.ts"):
    return compile_from_source_str_with_result(src, file_name, disable_constant_folding=True)


def _script(src: str, file_name: str = "C.runar.ts") -> str:
    r = _compile(src, file_name)
    assert r.success, [d.message for d in r.diagnostics]
    return r.script_hex


def _errors(src: str, file_name: str = "C.runar.ts") -> str:
    r = _compile(src, file_name)
    assert not r.success
    return "\n".join(d.message for d in r.diagnostics)


def test_pinned_sizes():
    assert len(LOWS_HEX) // 2 == 422
    assert len(ALL_HEX) // 2 == 376


@pytest.mark.parametrize("directive", ["", "/** @bindingVariant lowS */"])
def test_default_is_c1_lows(directive):
    s = _script(_counter(directive))
    assert s.count(LOWS_HEX) == 1
    assert "02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0" not in s


def test_all_emits_compact_blob():
    s = _script(_counter("/** @bindingVariant all */"))
    assert s.count(ALL_HEX) == 1
    assert LOWS_HEX not in s


def test_nested_arm_inherits():
    src = (
        "class G extends SmartContract {\n"
        "  constructor() { super(); }\n"
        "  /** @bindingVariant all */\n"
        "  public unlock(a: SigHashPreimage, b: SigHashPreimage, c: boolean) {\n"
        "    if (c) { assert(checkPreimage(a)); } else { assert(checkPreimage(b)); }\n"
        "  }\n"
        "}\n"
    )
    s = _script(src, "G.runar.ts")
    assert s.count(ALL_HEX) == 2
    assert LOWS_HEX not in s


@pytest.mark.parametrize("directive,want", [
    ("/** @bindingVariant: all */",
     "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`"),
    ("/** @bindingVariant high */", '@bindingVariant: unknown variant "high" (valid: lowS, all)'),
    ("/** @bindingVariant all */\n  // @bindingVariant lowS",
     "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one"),
])
def test_directive_errors(directive, want):
    assert want in _errors(_counter(directive))


def test_private_method_refused():
    src = _counter("/** @bindingVariant all */").replace("public bump", "private bump")
    assert "@bindingVariant directive on non-public method 'bump' has no effect" in _errors(src)


@pytest.mark.parametrize("file_name,surface", [
    ("C.runar.sol", "Solidity"), ("C.runar.move", "Move"), ("C.runar.py", "Python"),
    ("C.runar.go", "Go DSL"), ("C.runar.rs", "Rust"), ("C.runar.rb", "Ruby"),
    ("C.runar.zig", "Zig"), ("C.runar.java", "Java"),
])
def test_non_ts_surfaces_refuse(file_name, surface):
    want = (f"@bindingVariant directive is not supported by the {surface} surface parser; "
            "write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured")
    assert want in _errors("// @bindingVariant all\n", file_name)


def test_ir_loader_refuses_unknown_variant():
    r = _compile(_counter("/** @bindingVariant all */"))
    assert r.success
    text = json.dumps(_anf_to_camel_dict(r.anf))
    assert '"bindingVariant": "all"' in text
    compile_from_ir_bytes(text.encode())
    bad = text.replace('"bindingVariant": "all"', '"bindingVariant": "high"', 1)
    with pytest.raises(Exception, match='bindingVariant must be "lowS" or "all"'):
        compile_from_ir_bytes(bad.encode())
