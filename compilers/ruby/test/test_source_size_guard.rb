# frozen_string_literal: true

# BUG-008 follow-up: source-parser size-guard regression tests.

require_relative "test_helper"
require "runar_compiler/frontend/input_limits"
require "runar_compiler/compiler"
require "runar_compiler/frontend/parser_python"
require "runar_compiler/frontend/parser_ts"
require "runar_compiler/frontend/parser_sol"
require "runar_compiler/frontend/parser_move"
require "runar_compiler/frontend/parser_go"
require "runar_compiler/frontend/parser_rust"
require "runar_compiler/frontend/parser_ruby"
require "runar_compiler/frontend/parser_zig"
require "runar_compiler/frontend/parser_java"

class TestSourceSizeGuard < Minitest::Test
  MAX = RunarCompiler::Frontend::InputLimits::MAX_SOURCE_BYTES
  ERR = RunarCompiler::Frontend::InputLimits::SourceSizeExceededError

  def test_assert_source_bytes_under_limit_rejects_oversized
    oversized = " " * (MAX + 1)
    err = assert_raises(ERR) do
      RunarCompiler::Frontend::InputLimits.assert_source_bytes_under_limit(oversized)
    end
    assert_equal MAX, err.limit
    assert_equal MAX + 1, err.actual
    assert_match(/MAX_SOURCE_BYTES/, err.message)
  end

  def test_assert_source_bytes_under_limit_accepts_at_limit
    sized = " " * MAX
    RunarCompiler::Frontend::InputLimits.assert_source_bytes_under_limit(sized)
  end

  def test_compiler_parse_source_rejects_oversized_across_all_extensions
    oversized = " " * (MAX + 1)
    %w[
      .runar.ts .runar.sol .runar.move .runar.go .runar.py
      .runar.rs .runar.rb .runar.zig .runar.java
    ].each do |ext|
      assert_raises(ERR) do
        RunarCompiler.send(:_parse_source, oversized, "Counter#{ext}")
      end
    end
  end

  def test_normal_source_does_not_trip_size_guard
    src = <<~RUBY
      require "runar"

      class Counter < RunarLang::SmartContract
        readonly :x
        def initialize(x); super; @x = x; end
        def unlock; end
      end
    RUBY
    # The Ruby parser may produce diagnostics; the only assertion is the
    # size guard did NOT raise.
    refute_raises(ERR) do
      begin
        RunarCompiler.send(:_parse_source, src, "Counter.runar.rb")
      rescue ERR
        raise
      rescue StandardError
        # other parse errors are fine
      end
    end
  end

  # N-136: the nine per-format parse_* class methods are public API on
  # RunarCompiler::Frontend and callable directly (_parse_source dispatches
  # to them, but a caller can reach around the dispatcher exactly the way
  # R-146 found in TS and F-177 found in Go). Only _parse_source called
  # assert_source_bytes_under_limit; each per-format entry went straight to
  # its own tokenizer, so a caller invoking e.g. parse_java or parse_sol
  # directly got no DoS-bound rejection at all. This proves each of the 9
  # exported entries raises SourceSizeExceededError for a MAX+1 input; it
  # does not prove the guard runs before tokenization (code inspection only).
  PER_FORMAT_PARSERS = {
    "parse_python" => :parse_python,
    "parse_ts" => :parse_ts,
    "parse_sol" => :parse_sol,
    "parse_move" => :parse_move,
    "parse_go" => :parse_go,
    "parse_rust" => :parse_rust,
    "parse_ruby" => :parse_ruby,
    "parse_zig" => :parse_zig,
    "parse_java" => :parse_java,
  }.freeze

  def test_every_exported_per_format_parser_rejects_oversized_input
    oversized = " " * (MAX + 1)
    PER_FORMAT_PARSERS.each do |name, method|
      err = assert_raises(ERR) do
        RunarCompiler::Frontend.public_send(method, oversized, "Counter.runar.ts")
      end
      assert_equal MAX, err.limit, "#{name}: wrong limit"
      assert_equal MAX + 1, err.actual, "#{name}: wrong actual"
    end
  end

  # Control: small input, well under the cap, must not trip the guard on any
  # entry point. Each parser is free to fail afterwards for its own
  # syntactic reasons; this only asserts the size guard did not raise.
  def test_every_exported_per_format_parser_accepts_small_input_at_the_guard
    PER_FORMAT_PARSERS.each do |name, method|
      refute_raises(ERR) do
        begin
          RunarCompiler::Frontend.public_send(method, "", "Counter.runar.ts")
        rescue ERR
          raise
        rescue StandardError
          # other parse errors on empty input are fine; only the size
          # guard is asserted on here.
        end
      end
    end
  end

  private

  def refute_raises(klass)
    yield
  rescue klass => e
    flunk "expected NOT to raise #{klass}, but did: #{e.message}"
  end
end
