"""Audit C3 -- property initializers are restricted to literal values.

``ts``, ``go`` and ``java`` enforced this; ``rust``, ``zig``, ``python`` and
``ruby`` did not -- they compiled e.g. ``p: bigint = 1n + 2n;`` and emitted a
deployable locking script for a program the language does not define.

Mirrors ``packages/runar-compiler/src/__tests__/property-initializer-literal.test.ts``.
"""

from __future__ import annotations

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import ValidationResult, validate

# The cross-tier diagnostic substring.
NON_LITERAL_INIT = "initializer must be a literal value"


def validate_source(source: str) -> ValidationResult:
    result = parse_source(source, "Test.runar.ts")
    assert result.contract is not None, f"parse failed: {result.errors}"
    return validate(result.contract)


def has_error(result: ValidationResult, needle: str) -> bool:
    return any(needle in d.message for d in result.errors)


def test_rejects_arithmetic_property_initializer():
    source = """
import { StatefulSmartContract, Addr } from 'runar-lang';

class Bad extends StatefulSmartContract {
  count: bigint = 1n + 2n;
  readonly owner: Addr;

  constructor(owner: Addr) {
    super(owner);
    this.owner = owner;
  }

  public bump() {
    this.count = this.count + 1n;
  }
}
"""
    result = validate_source(source)
    assert has_error(result, NON_LITERAL_INIT), (
        f"expected a non-literal-initializer error, got: {result.error_strings()}"
    )


def test_rejects_call_expression_property_initializer():
    source = """
import { StatefulSmartContract, Addr } from 'runar-lang';

class Bad2 extends StatefulSmartContract {
  count: bigint = abs(-3n);
  readonly owner: Addr;

  constructor(owner: Addr) {
    super(owner);
    this.owner = owner;
  }

  public bump() {
    this.count = this.count + 1n;
  }
}
"""
    result = validate_source(source)
    assert has_error(result, NON_LITERAL_INIT), (
        f"expected a non-literal-initializer error, got: {result.error_strings()}"
    )


def test_accepts_literal_property_initializers():
    source = """
import { StatefulSmartContract, Addr, ByteString } from 'runar-lang';

class Good extends StatefulSmartContract {
  count: bigint = 7n;
  flag: boolean = true;
  tag: ByteString = 'deadbeef';
  offset: bigint = -3n;
  readonly owner: Addr;

  constructor(owner: Addr) {
    super(owner);
    this.owner = owner;
  }

  public bump() {
    this.count = this.count + 1n;
  }
}
"""
    result = validate_source(source)
    assert result.errors == [], f"expected no errors, got: {result.error_strings()}"


# ---------------------------------------------------------------------------
# ``toByteString('<hex>')`` IS the ByteStringLiteral production -- see
# spec/grammar.md section 11::
#
#     ByteStringLiteral = 'toByteString' '(' StringLiteral ')' ;
#
# 0e192af6 folded it in ANF lowering, which covers every EXPRESSION position.
# A property INITIALIZER is not one: the validator runs on the AST, BEFORE ANF
# lowering, and still saw a call node. The ``.runar.rs`` surface needs exactly
# this spelling in exactly this position -- the Rust DSL writes initializers as
# assignments inside ``init()`` that the parser LIFTS into
# ``PropertyNode.initializer``, and a bare ``"1976a914"`` is a ``&str`` that
# cannot be assigned to a ``ByteString`` (``Vec<u8>``).
#
# Both halves are asserted: accepting it in the validator alone yields a
# property that validates and then loses its default, because
# ``_extract_literal_value`` returns ``None`` for a call node.
# ---------------------------------------------------------------------------

TO_BYTE_STRING_INIT = """
import { SmartContract, Addr, ByteString, toByteString, assert } from 'runar-lang';

class Wrapped extends SmartContract {
  readonly prefix: ByteString = toByteString('1976a914');
  readonly owner: Addr;

  constructor(owner: Addr) {
    super(owner);
    this.owner = owner;
  }

  public unlock(x: ByteString): void {
    assert(x === this.prefix);
  }
}
"""


def test_accepts_to_byte_string_literal_property_initializer():
    result = validate_source(TO_BYTE_STRING_INIT)
    assert result.errors == [], f"expected no validation errors, got: {result.errors}"


def test_unwraps_to_byte_string_literal_initializer_in_anf():
    import json

    from runar_compiler.__main__ import _anf_to_camel_dict
    from runar_compiler.frontend.anf_lower import lower_to_anf

    def anf_of(src: str):
        parsed = parse_source(src, "Test.runar.ts")
        assert parsed.contract is not None, f"parse failed: {parsed.errors}"
        return lower_to_anf(parsed.contract)

    wrapped = anf_of(TO_BYTE_STRING_INIT)
    bare = anf_of(TO_BYTE_STRING_INIT.replace("toByteString('1976a914')", "'1976a914'"))

    # Half two: a bare value, not a call node and not a dropped default.
    assert wrapped.properties[0].initial_value == "1976a914", (
        f"expected initial_value '1976a914', got {wrapped.properties[0].initial_value!r}"
    )

    # ...and the whole program is indistinguishable from the bare spelling,
    # which is what keeps expected-ir.json from moving.
    assert json.dumps(_anf_to_camel_dict(wrapped), default=str) == json.dumps(
        _anf_to_camel_dict(bare), default=str
    ), "wrapped ANF must be byte-identical to the bare-literal ANF"


def test_rejects_to_byte_string_non_literal_property_initializer():
    # Not the ByteStringLiteral production -- a real call, and a call is not a
    # literal. Guards the accept from widening into "any toByteString call".
    source = """
import { SmartContract, Addr, ByteString, toByteString, assert } from 'runar-lang';

class Bad3 extends SmartContract {
  readonly prefix: ByteString = toByteString(someIdent);
  readonly owner: Addr;

  constructor(owner: Addr) {
    super(owner);
    this.owner = owner;
  }

  public unlock(x: ByteString): void {
    assert(x === this.prefix);
  }
}
"""
    result = validate_source(source)
    assert has_error(result, NON_LITERAL_INIT)
