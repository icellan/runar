# frozen_string_literal: true

# BUG-008 follow-up: source-parser size-guard regression tests.

require_relative "test_helper"
require "runar_compiler/frontend/input_limits"
require "runar_compiler/compiler"

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

  private

  def refute_raises(klass)
    yield
  rescue klass => e
    flunk "expected NOT to raise #{klass}, but did: #{e.message}"
  end
end
