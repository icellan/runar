"""F-206 (CL-BUG-208..213) — ``.runar.rb`` property-declaration edge cases.

Probing this tier's Ruby-surface parser (``parser_ruby.py``) against the TS
reference (``01-parse-ruby.ts``) found three divergences:

  - ``Bool`` as a property type: the TS reference (and the native Ruby
    tier's own reference parser, ``parser_ruby.rb``) alias it to ``boolean``,
    matching ``Boolean``. This tier's ``_TYPE_MAP`` only had ``Boolean``, so
    ``Bool`` fell through to an unresolved ``CustomType(name='Bool')``.
  - ``prop :x, Bigint, default: -5``: the TS reference calls its
    unary-expression parser for a ``default:`` value. This tier called
    ``self._parse_primary()`` directly, which has no unary-minus handling,
    and refused the literal with "unexpected token in expression: '-'".
  - ``FixedArray[Int, N]`` (``N`` not a numeric literal): ``_expect`` already
    logs a diagnostic on the token mismatch and returns the token anyway
    (matching every other malformed-input case in this parser), but the very
    next line, ``int(size_tok.value)``, raised an uncaught ``ValueError``
    instead of producing a clean diagnostic. The exception propagates out of
    ``parse_ruby`` itself -- not merely caught-and-reformatted by the CLI's
    outer handler -- so any caller that invokes the parser directly (as this
    test does, and as ``TestContract``-style harnesses would) gets a crash
    instead of a ``ParseResult`` with diagnostics.

What this proves: ``parse_ruby`` maps ``Bool`` to the same ``PrimitiveType``
as ``Boolean``; a negative ``default:`` literal parses to a single
``UnaryExpr('-', BigIntLiteral(5))`` with no diagnostics; and
``FixedArray[Int, N]`` returns a ``ParseResult`` carrying a diagnostic
instead of raising.
What it does NOT prove: the other six tiers (see
``conformance/negatives/n196-rb-prop-shape-parity.test.ts`` for the
cross-tier gate); ``default:`` with ``~``/``!`` prefixes beyond what
``_parse_unary`` already covers; or any surface other than ``.runar.rb``.
"""
from __future__ import annotations

from runar_compiler.frontend.ast_nodes import BigIntLiteral, PrimitiveType, UnaryExpr
from runar_compiler.frontend.parser_ruby import parse_ruby


def test_bool_type_alias():
    source = "\n".join([
        "require 'runar'",
        "",
        "class Flag < Runar::SmartContract",
        "  prop :flag, Bool",
        "",
        "  runar_public",
        "  def check",
        "    assert @flag",
        "  end",
        "end",
        "",
    ])
    result = parse_ruby(source, "Flag.runar.rb")
    assert result.errors == [], f"errors: {result.errors}"
    assert result.contract is not None
    assert len(result.contract.properties) == 1
    prop_type = result.contract.properties[0].type
    assert isinstance(prop_type, PrimitiveType), f"expected PrimitiveType, got {prop_type!r}"
    assert prop_type.name == "boolean"


def test_default_negative_literal():
    source = "\n".join([
        "require 'runar'",
        "",
        "class DefaultNeg < Runar::SmartContract",
        "  prop :count, Bigint, default: -5",
        "",
        "  runar_public x: Bigint",
        "  def check(x)",
        "    assert x + @count == x - 5",
        "  end",
        "end",
        "",
    ])
    result = parse_ruby(source, "DefaultNeg.runar.rb")
    assert result.errors == [], f"errors: {result.errors}"
    assert result.contract is not None
    initializer = result.contract.properties[0].initializer
    assert isinstance(initializer, UnaryExpr), f"expected UnaryExpr, got {initializer!r}"
    assert initializer.op == "-"
    assert isinstance(initializer.operand, BigIntLiteral)
    assert initializer.operand.value == 5


def test_fixed_array_non_numeric_length_is_a_clean_diagnostic():
    source = "\n".join([
        "require 'runar'",
        "",
        "class FixedArrayBad < Runar::SmartContract",
        "  prop :arr, FixedArray[Int, N]",
        "",
        "  runar_public x: Bigint",
        "  def check(x)",
        "    assert x == 0",
        "  end",
        "end",
        "",
    ])
    # Must return a ParseResult with a diagnostic, never raise.
    result = parse_ruby(source, "FixedArrayBad.runar.rb")
    assert result.errors, "expected a diagnostic for a non-numeric FixedArray length"
    assert any("FixedArray" in str(e) or "number" in str(e) for e in result.errors), result.errors
