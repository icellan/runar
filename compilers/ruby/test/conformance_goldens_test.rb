# frozen_string_literal: true

# Byte-identical golden diff harness for the Ruby compiler.
#
# For every directory under `conformance/tests/`, this test:
#   1. Locates the Ruby-format source file (`*.runar.rb`)
#   2. Invokes the Ruby compiler CLI via subprocess
#   3. Canonicalizes the ANF IR JSON (sort keys, strip `sourceLoc`, 2-space indent)
#   4. Asserts byte-for-byte equality against `expected-ir.json` and `expected-script.hex`
#
# The canonicalization mirrors `conformance/runner/runner.ts::canonicalizeJson`.
# Failures are collected and the first 5 are reported with concrete diffs.
#
# The Ruby CLI is invoked via subprocess because the Ruby compiler's TS and Ruby
# parsers share a constant namespace; running them in the same process corrupts
# tokenization. The subprocess avoids that pre-existing constant collision.

require 'json'
require 'open3'
require_relative 'test_helper'

class ConformanceGoldensTest < Minitest::Test
  CONFORMANCE_DIR = File.expand_path('../../../conformance/tests', __dir__)
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby')

  # ------------------------------------------------------------------
  # Helpers
  # ------------------------------------------------------------------

  # Resolve the Ruby-format source file for a conformance fixture.
  #
  # Mirrors the TS runner (conformance/runner/runner.ts):
  #   1. If `source.json` exists and has a `.runar.rb` entry in `sources`,
  #      resolve it relative to the fixture directory. Use it if it exists.
  #   2. Otherwise fall back to the first `*.runar.rb` file in the fixture dir.
  def find_ruby_source(test_dir)
    config_path = File.join(test_dir, 'source.json')
    if File.exist?(config_path)
      begin
        cfg = JSON.parse(File.read(config_path))
        rel = cfg.dig('sources', '.runar.rb')
        if rel.is_a?(String)
          resolved = File.expand_path(rel, test_dir)
          return resolved if File.exist?(resolved)
        end
      rescue JSON::ParserError, StandardError
        # fall through to glob
      end
    end

    Dir.children(test_dir).sort.each do |name|
      path = File.join(test_dir, name)
      return path if File.file?(path) && name.end_with?('.runar.rb')
    end
    nil
  end

  # Recursively sort object keys and strip `sourceLoc`.
  def canonicalize(value)
    case value
    when Hash
      out = {}
      value.keys.sort.each do |k|
        next if k == 'sourceLoc'
        out[k] = canonicalize(value[k])
      end
      out
    when Array
      value.map { |v| canonicalize(v) }
    else
      value
    end
  end

  # Parse JSON, canonicalize, and re-serialize with 2-space indent.
  def canonicalize_json(str)
    JSON.pretty_generate(canonicalize(JSON.parse(str)), indent: '  ')
  end

  # Run the Ruby compiler CLI with the given flags.
  # Returns [stdout, stderr, exit_status] as strings.
  def run_compiler(source_path, flags)
    cmd = ['ruby', RUBY_CLI, '--source', source_path, *flags]
    stdout, stderr, status = Open3.capture3(*cmd, chdir: RUBY_COMPILER_DIR)
    [stdout, stderr, status]
  end

  # Produce a compact unified-diff style summary of two strings.
  def short_diff(expected, actual, limit: 12)
    exp_lines = expected.lines.map(&:chomp)
    act_lines = actual.lines.map(&:chomp)
    out = +''
    shown = 0
    max = [exp_lines.length, act_lines.length].max
    max.times do |i|
      e = exp_lines[i] || '<EOF>'
      a = act_lines[i] || '<EOF>'
      next if e == a
      out << "    line #{i + 1}:\n"
      out << "      - expected: #{e}\n"
      out << "      + actual:   #{a}\n"
      shown += 1
      break if shown >= limit
    end
    out << "    (strings differ but no line diff; likely trailing whitespace)\n" if out.empty?
    out
  end

  # ------------------------------------------------------------------
  # The single conformance test that walks all fixtures.
  # ------------------------------------------------------------------

  def test_conformance_goldens_ruby
    assert File.directory?(CONFORMANCE_DIR), "missing conformance dir: #{CONFORMANCE_DIR}"
    assert File.executable?(RUBY_CLI) || File.exist?(RUBY_CLI), "missing Ruby CLI: #{RUBY_CLI}"

    dirs = Dir.children(CONFORMANCE_DIR)
              .map { |n| File.join(CONFORMANCE_DIR, n) }
              .select { |p| File.directory?(p) }
              .sort

    passed = []
    missing = []
    failures = []  # each entry: [name, kind, expected, actual]

    dirs.each do |test_dir|
      name = File.basename(test_dir)
      source = find_ruby_source(test_dir)
      if source.nil?
        missing << name
        next
      end

      # Step 1: IR
      ir_stdout, ir_stderr, ir_status = run_compiler(source, ['--emit-ir', '--disable-constant-folding'])
      unless ir_status.success?
        failures << [name, 'compile-ir', '', (ir_stderr.empty? ? ir_stdout : ir_stderr).strip]
        next
      end

      # Step 2: script hex
      hex_stdout, hex_stderr, hex_status = run_compiler(source, ['--hex', '--disable-constant-folding'])
      unless hex_status.success?
        failures << [name, 'compile-hex', '', (hex_stderr.empty? ? hex_stdout : hex_stderr).strip]
        next
      end
      actual_hex = hex_stdout.gsub(/\s/, '').downcase

      # Step 3: canonicalize & compare
      begin
        actual_ir = canonicalize_json(ir_stdout)
      rescue JSON::ParserError, StandardError => e
        failures << [name, 'canonicalize-actual-ir', '', "#{e.message}\n-- raw --\n#{ir_stdout[0, 500]}"]
        next
      end

      expected_ir_path = File.join(test_dir, 'expected-ir.json')
      if File.exist?(expected_ir_path)
        expected_ir = canonicalize_json(File.read(expected_ir_path))
        if actual_ir != expected_ir
          failures << [name, 'ir-mismatch', expected_ir, actual_ir]
          next
        end
      end

      expected_hex_path = File.join(test_dir, 'expected-script.hex')
      if File.exist?(expected_hex_path)
        expected_hex = File.read(expected_hex_path).gsub(/\s/, '').downcase
        if actual_hex != expected_hex
          failures << [name, 'script-mismatch', expected_hex, actual_hex]
          next
        end
      end

      passed << name
    end

    total = dirs.length
    report = +''
    report << "\n=== Ruby conformance-goldens summary: #{passed.length} pass / "
    report << "#{failures.length} fail / #{missing.length} missing-source (of #{total} fixtures) ===\n"
    if missing.any?
      report << "Missing .runar.rb source files:\n"
      missing.each { |n| report << "  - #{n}\n" }
    end
    failures.first(5).each do |(name, kind, expected, actual)|
      report << "\n--- FAIL: #{name} (#{kind}) ---\n"
      case kind
      when 'ir-mismatch'
        report << "  expected #{expected.length} chars, actual #{actual.length} chars:\n"
        report << short_diff(expected, actual)
      when 'script-mismatch'
        min_len = [expected.length, actual.length].min
        first_diff = min_len
        (0...min_len).each do |i|
          if expected[i] != actual[i]
            first_diff = i
            break
          end
        end
        lo = [0, first_diff - 20].max
        exp_hi = [first_diff + 20, expected.length].min
        act_hi = [first_diff + 20, actual.length].min
        report << "  expected #{expected.length} hex chars, actual #{actual.length} hex chars\n"
        report << "  first diff at hex offset #{first_diff} (byte #{first_diff / 2})\n"
        report << "  expected: ...#{expected[lo...exp_hi]}...\n"
        report << "  actual:   ...#{actual[lo...act_hi]}...\n"
      else
        report << "  #{actual}\n"
      end
    end
    if failures.length > 5
      report << "\n... and #{failures.length - 5} more failures:\n"
      failures.drop(5).each { |(n, _k, _e, _a)| report << "  - #{n}\n" }
    end
    puts report

    assert failures.empty?,
           "#{failures.length} of #{total} fixtures failed conformance-goldens; see stdout for details"
  end
end
