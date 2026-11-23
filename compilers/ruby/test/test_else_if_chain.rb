# frozen_string_literal: true

require_relative 'test_helper'

# Frontend parity: `else if` in .runar.move is sugar for `else { if ... }`.
# The Ruby tier's Move parser refused it ("expected token kind 4, got 'if'"),
# while every other tier accepted it.
#
# Proves: a three-arm Move else-if chain (with and without a terminal else)
# parses without errors to the same method body as the nested form, source
# locations aside.
# Does not prove: the other tiers (pinned by conformance/tests/selector, whose
# nine sources all use the native chain form).
class TestElseIfChain < Minitest::Test
  def parse(source, file_name)
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def strip(v)
    case v
    when Array then v.map { |x| strip(x) }
    when Struct
      v.to_h.reject { |k, _| k == :source_location }.transform_values { |x| strip(x) }.merge(__class: v.class.name)
    else v
    end
  end

  def body(stmt)
    src = <<~MOVE
      module Sel {
          resource struct Sel { a: &mut bigint }
          public fun set(contract: &mut Sel, i: bigint, v: bigint) {
      #{stmt}
          }
      }
    MOVE
    result = parse(src, 'Sel.runar.move')
    assert_empty result.errors.map(&:format_message)
    strip(result.contract.methods.find { |m| m.name == 'set' }.body)
  end

  def test_move_else_if_chain_with_terminal_else
    chain = body(<<~S)
      if (i == 0) { contract.a = v; }
      else if (i == 1) { contract.a = v + 1; }
      else if (i == 2) { contract.a = v + 2; }
      else { assert!(false, 0); };
    S
    nested = body(<<~S)
      if (i == 0) { contract.a = v; }
      else { if (i == 1) { contract.a = v + 1; }
      else { if (i == 2) { contract.a = v + 2; }
      else { assert!(false, 0); } } };
    S
    assert_equal nested, chain
  end

  def test_move_else_if_chain_without_terminal_else
    chain = body(<<~S)
      if (i == 0) { contract.a = v; }
      else if (i == 1) { contract.a = v + 1; };
    S
    nested = body(<<~S)
      if (i == 0) { contract.a = v; }
      else { if (i == 1) { contract.a = v + 1; } };
    S
    assert_equal nested, chain
  end

  def test_move_else_if_is_located_at_its_if_keyword
    src = <<~MOVE
      module Sel {
          resource struct Sel { a: &mut bigint }
          public fun set(contract: &mut Sel, i: bigint, v: bigint) {
              if (i == 0) { contract.a = v; }
              else if (i == 1) { contract.a = v + 1; };
          }
      }
    MOVE
    result = parse(src, 'Sel.runar.move')
    assert_empty result.errors.map(&:format_message)
    outer = result.contract.methods.find { |m| m.name == 'set' }.body[0]
    want = src.lines.index { |l| l.include?('else if') } + 1
    assert_equal want, outer.else_[0].source_location.line
  end
end
