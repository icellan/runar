# Mirrors examples/go/go-dsl-bytestring-literal/GoDslBytestringLiteral.runar.go.
#
# The Go-DSL fixture exercises Go-only surface features (`runar.BigintBig`
# property type, `runar.ByteString("\x00\x6a")` literal). In Ruby the
# equivalent surface is plain `Bigint` / `ByteString` plus a single-quoted
# `'006a'` hex literal. Both lower to the same primitives in the AST.
require 'runar'

class GoDslBytestringLiteral < Runar::SmartContract
  prop :target, Bigint
  prop :expected, ByteString

  def initialize(target, expected)
    super(target, expected)
    @target = target
    @expected = expected
  end

  runar_public a: Bigint, b: Bigint
  def check(a, b)
    assert a + b == @target
    assert '006a' == @expected
  end
end
