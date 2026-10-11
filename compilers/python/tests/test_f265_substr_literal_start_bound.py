"""F-265 -- substr() literal negative start is a compile-time error.

``substr(witness, start, len)`` lowers to a raw ``OP_SPLIT`` argument. No pass
enforced ``start >= 0``: a literal negative start (``substr(a, -5n, 3n)``)
type-checked as plain ``bigint`` (the standard subtype loop never inspects a
literal's VALUE) and compiled to a script that aborts at runtime -- ``-5n``
minimal-encodes to ``<85>``, which ``OP_SPLIT`` rejects as out of range.

Mirrors the existing ``requireOutputP2PKH``/``extractPrevOutputScript``
"must be >= 0" literal-bound pattern in
``compilers/python/runar_compiler/frontend/typecheck.py`` (see
``test_intent_intrinsics_bounds.py``).

Proves: a literal (bare or unary-negated ``BigIntLiteral``) negative start is
now a typecheck-time diagnostic. Does not prove: anything about a NON-literal
negative start (a variable or computed expression) -- that remains a runtime
abort, unchanged, because the stack model has no static value range for a
non-literal.
"""

from __future__ import annotations

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check


def _typecheck_errors(source: str) -> list[str]:
    result = parse_source(source, "Test.runar.ts")
    assert result.errors == [], result.error_strings()
    assert result.contract is not None
    tc_result = type_check(result.contract)
    return [d.format_message() for d in tc_result.errors]


def test_rejects_literal_negative_start():
    source = """
import { SmartContract, assert, ByteString, substr } from 'runar-lang';

class C extends SmartContract {
  readonly a: ByteString;
  constructor(a: ByteString) { super(a); this.a = a; }
  public unlock(): void {
    assert(substr(this.a, -5n, 3n) === this.a);
  }
}
"""
    errs = _typecheck_errors(source)
    assert any("substr() argument 2 (start) must be >= 0; got -5" in m for m in errs), errs


def test_accepts_literal_non_negative_start():
    source = """
import { SmartContract, assert, ByteString, substr } from 'runar-lang';

class C extends SmartContract {
  readonly a: ByteString;
  constructor(a: ByteString) { super(a); this.a = a; }
  public unlock(): void {
    assert(substr(this.a, 0n, 3n) === this.a);
  }
}
"""
    assert _typecheck_errors(source) == []


def test_accepts_non_literal_start_unchanged():
    source = """
import { SmartContract, assert, ByteString, substr } from 'runar-lang';

class C extends SmartContract {
  readonly a: ByteString;
  constructor(a: ByteString) { super(a); this.a = a; }
  public unlock(n: bigint): void {
    assert(substr(this.a, n, 3n) === this.a);
  }
}
"""
    assert _typecheck_errors(source) == []
