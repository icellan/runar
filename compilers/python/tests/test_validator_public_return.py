"""NEW-012 -- ``return`` in a PUBLIC method.

``spec/grammar.md:161`` makes public methods void, ``:162`` makes their trailing
assert the spending condition, and ``spec/semantics.md`` gives ``return`` no
early-exit meaning at all (§4.6 defines only "the value of this method is v";
§4.7 sequences statements unconditionally).

Lowering it as if it were the tail of an inlined helper produced two broken
scripts: ``return;`` left the enclosing arm with no result, so it yielded OP_0
and the whole script evaluated FALSE (unspendable, from source that compiled
clean -- in THIS tier it surfaced as an internal "stack lowering: list index out
of range"); ``return expr;`` made the returned value the branch result and hence
the script's final truthiness, so any truthy expr spent the contract WITHOUT
reaching the guarding assert (fail-OPEN).
"""

from __future__ import annotations

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate

DIAG = "must not use `return`"


def _validate_ts(source: str):
    result = parse_source(source, "Guard.runar.ts")
    assert result.errors == [], result.error_strings()
    assert result.contract is not None
    return validate(result.contract)


def _count(val_result, substr: str) -> int:
    return sum(1 for d in val_result.errors if substr in d.message)


def test_rejects_bare_return_in_public_method():
    result = _validate_ts("""
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) { return; }
    assert(x === this.secret);
  }
}
""")
    assert _count(result, DIAG) == 1, [d.format_message() for d in result.errors]


def test_rejects_valued_return_in_public_method():
    result = _validate_ts("""
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) { return x; }
    assert(x === this.secret);
  }
}
""")
    assert _count(result, DIAG) == 1, [d.format_message() for d in result.errors]


def test_rejects_return_nested_in_loop_in_public_method():
    result = _validate_ts("""
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    for (let i: bigint = 0n; i < 4n; i++) {
      if (x > i) { return; }
    }
    assert(x === this.secret);
  }
}
""")
    assert _count(result, DIAG) == 1, [d.format_message() for d in result.errors]


def test_allows_return_in_private_helper():
    """spec/grammar.md:168 -- "Private methods may return a value."."""
    result = _validate_ts("""
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  private doubled(v: bigint): bigint { return v + v; }

  public unlock(x: bigint) {
    assert(this.doubled(x) === this.secret);
  }
}
""")
    assert result.errors == [], [d.format_message() for d in result.errors]
