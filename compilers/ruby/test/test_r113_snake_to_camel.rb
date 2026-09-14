# frozen_string_literal: true

require_relative 'test_helper'
require 'runar_compiler/frontend/parser_ruby'
require 'runar_compiler/frontend/parser_move'
require 'runar_compiler/cli'

# R-113 — this tier carried FOUR hand-rolled copies of the old
# snake_case -> camelCase rule, `gsub(/_([a-z0-9])/)`, which uppercases only a
# lower-case letter or digit after the underscore and leaves `_` before a
# CAPITAL in place. The shared rule (`snakeToCamelCore` in TS,
# `rbConvertName` in Go, `snake_to_camel` in Rust, `snakeToCamel` in Zig)
# splits on `_` and capitalises the first character of every following part.
#
# The cross-tier proof lives in
# `packages/runar-compiler/src/__tests__/r113-cross-tier-snake-case.test.ts`,
# which compiles `total_A` / `total_b` / `total_1` through all seven compilers
# and compares the ARTIFACT PROPERTY NAMES (the script hex is byte-identical
# either way, which is why hex parity never caught this).
#
# This file pins the three Ruby-side helpers directly — including
# `CLI._snake_key`, the copy no cross-tier compile can reach because no ANF
# field name has an upper-case segment today.
class TestR113SnakeToCamel < Minitest::Test
  # `_` before an UPPER-CASE letter is the boundary the two rules disagree
  # about; the lower-case and digit cases are here so a fix cannot
  # over-correct them.
  BOUNDARY_CASES = {
    'total_A' => 'totalA',
    'total_b' => 'totalB',
    'total_1' => 'total1',
    'pub_key_hash' => 'pubKeyHash',
    'foo__bar' => 'fooBar',
    'count' => 'count',
  }.freeze

  def test_rb_parser_snake_to_camel_matches_the_shared_rule
    BOUNDARY_CASES.each do |input, expected|
      assert_equal expected, RunarCompiler::Frontend.snake_to_camel(input),
                   "parser_ruby.rb snake_to_camel(#{input.inspect})"
    end
  end

  def test_rb_parser_still_strips_leading_underscores
    assert_equal 'requireOwner',
                 RunarCompiler::Frontend.snake_to_camel('_require_owner')
    assert_equal 'ownerA', RunarCompiler::Frontend.snake_to_camel('_owner_A')
  end

  def test_move_parser_snake_to_camel_matches_the_shared_rule
    BOUNDARY_CASES.each do |input, expected|
      assert_equal expected, RunarCompiler::Frontend.move_snake_to_camel(input),
                   "parser_move.rb move_snake_to_camel(#{input.inspect})"
    end
  end

  # The old `gsub(/_([a-z0-9])/)` rule preserved `verifyECDSA_P256` by
  # ACCIDENT — it refused to uppercase after `_` unless the next character was
  # lower-case. Converging on the shared rule removes that accident, so the
  # name has to be anchored on the raw token, as TS (`preserved` in
  # 01-parse-move.ts) and Go (raw spellings in `moveBuiltinMap`) already do.
  # Without the anchor the p256-wallet / p384-wallet / r1-k1-wallet `.move`
  # fixtures stop compiling in this tier with "unknown function
  # 'verifyECDSAP256'".
  def test_move_anchors_builtins_with_an_underscore_before_a_capital
    %w[
      examples/move/p256-wallet/P256Wallet.runar.move
      examples/move/p384-wallet/P384Wallet.runar.move
      examples/move/r1-k1-wallet/R1K1Wallet.runar.move
    ].each do |rel|
      path = File.expand_path(File.join(__dir__, '..', '..', '..', rel))
      next unless File.exist?(path)

      # Asserted through the FULL frontend, because that is where the harm
      # showed up: the parser happily produced `verifyECDSAP256` and the type
      # checker then rejected it as an unknown function.
      RunarCompiler.compile_source_to_ir(path, disable_constant_folding: true)
    end
  end

  def test_cli_snake_key_matches_the_shared_rule
    BOUNDARY_CASES.each do |input, expected|
      next if RunarCompiler::CLI::FIELD_ALIASES.key?(input)
      next if RunarCompiler::CLI::SNAKE_WIRE_FIELDS.include?(input)

      assert_equal expected, RunarCompiler::CLI._snake_key(input),
                   "cli.rb _snake_key(#{input.inspect})"
    end
  end

  def test_cli_snake_key_still_honours_its_overrides
    # The shared rule is only the fallback — N-094's aliases and the
    # deliberately-snake wire fields still win.
    RunarCompiler::CLI::FIELD_ALIASES.each do |k, v|
      assert_equal v, RunarCompiler::CLI._snake_key(k)
    end
    RunarCompiler::CLI::SNAKE_WIRE_FIELDS.each do |k|
      assert_equal k, RunarCompiler::CLI._snake_key(k)
    end
  end
end
