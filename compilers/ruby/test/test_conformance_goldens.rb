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
require 'tmpdir'
require 'fileutils'
require_relative 'test_helper'

class ConformanceGoldensTest < Minitest::Test
  CONFORMANCE_DIR = File.expand_path('../../../conformance/tests', __dir__)
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby')

  # ------------------------------------------------------------------
  # Helpers
  # ------------------------------------------------------------------

  # Read the optional per-fixture `compilers` allowlist from source.json.
  #
  # Mirrors `conformance/runner/runner.ts::readFixtureCompilerAllowlist`:
  # when source.json declares a top-level "compilers" array, only the
  # listed tiers are required to produce byte-identical IR/hex for this
  # fixture (conformance/README.md "Per-fixture compiler allowlist"). A
  # fixture whose allowlist excludes "ruby" is legitimately out of scope
  # for this harness -- it may ship no .runar.rb source at all.
  #
  # Returns nil when the field is absent (= "all compilers"), else an
  # Array<String> of allowed compiler ids.
  def read_compiler_allowlist(test_dir)
    config_path = File.join(test_dir, 'source.json')
    return nil unless File.exist?(config_path)

    begin
      cfg = JSON.parse(File.read(config_path))
    rescue JSON::ParserError, StandardError
      return nil
    end

    list = cfg['compilers']
    list.is_a?(Array) ? list : nil
  end

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
  # Core scan: walk `dirs` (conformance fixture directories) and classify
  # each one. Extracted from the test body so the classification logic is
  # directly unit-testable against synthetic fixture directories (F-151),
  # without depending on or risking the real conformance corpus.
  #
  # Classification (F-151 fix):
  #   - A fixture whose source.json `compilers` allowlist excludes "ruby"
  #     is SKIPPED outright (ruby is not a required conformance target for
  #     it -- conformance/README.md "Per-fixture compiler allowlist").
  #   - Any other fixture with no resolvable .runar.rb source is a FAILURE.
  #   - A fixture whose source compiles but ships no expected-ir.json or
  #     no expected-script.hex is a FAILURE (this harness is the sole
  #     check of Ruby's output; unlike the TS runner -- which also relies
  #     on cross-tier comparison -- there is no other gate here).
  #
  # Returns { passed: [name...], skipped: [name...], failures: [[name, kind,
  # expected, actual], ...] }.
  # ------------------------------------------------------------------
  def scan_fixtures(dirs)
    passed = []
    skipped = []
    failures = []  # each entry: [name, kind, expected, actual]

    dirs.each do |test_dir|
      name = File.basename(test_dir)

      allowlist = read_compiler_allowlist(test_dir)
      if allowlist && !allowlist.include?('ruby')
        skipped << name
        next
      end

      source = find_ruby_source(test_dir)
      if source.nil?
        failures << [name, 'missing-source', '', "no .runar.rb source found for fixture '#{name}'"]
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
      unless File.exist?(expected_ir_path)
        failures << [name, 'missing-golden-ir', '', "expected-ir.json not found for fixture '#{name}'"]
        next
      end
      expected_ir = canonicalize_json(File.read(expected_ir_path))
      if actual_ir != expected_ir
        failures << [name, 'ir-mismatch', expected_ir, actual_ir]
        next
      end

      expected_hex_path = File.join(test_dir, 'expected-script.hex')
      unless File.exist?(expected_hex_path)
        failures << [name, 'missing-golden-hex', '', "expected-script.hex not found for fixture '#{name}'"]
        next
      end
      expected_hex = File.read(expected_hex_path).gsub(/\s/, '').downcase
      if actual_hex != expected_hex
        failures << [name, 'script-mismatch', expected_hex, actual_hex]
        next
      end

      passed << name
    end

    { passed: passed, skipped: skipped, failures: failures }
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

    result = scan_fixtures(dirs)
    passed = result[:passed]
    skipped = result[:skipped]
    failures = result[:failures]

    total = dirs.length
    report = +''
    report << "\n=== Ruby conformance-goldens summary: #{passed.length} pass / "
    report << "#{failures.length} fail / #{skipped.length} skipped (compilers allowlist excludes ruby) " \
              "(of #{total} fixtures) ===\n"
    if skipped.any?
      report << "Skipped (source.json \"compilers\" allowlist excludes ruby):\n"
      skipped.each { |n| report << "  - #{n}\n" }
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

  # ------------------------------------------------------------------
  # F-151: the harness must FAIL on a fixture with no resolvable .runar.rb
  # source and FAIL on a fixture with a missing golden, instead of
  # silently dropping both into an unasserted bucket. These exercise
  # `scan_fixtures` directly against synthetic, throwaway fixture
  # directories (via Dir.mktmpdir) so they do not touch the real
  # conformance corpus.
  #
  # What this proves: `scan_fixtures` classifies a missing-source fixture
  # and a missing-golden fixture as FAILURES, not as silent passes or an
  # unasserted "missing" bucket.
  #
  # What this does NOT prove: that the real conformance/tests corpus is
  # free of the gap today -- see test_conformance_goldens_ruby for that.
  # ------------------------------------------------------------------

  MINIMAL_RUBY_SOURCE = <<~RUBY
    require 'runar'

    class F151Probe < Runar::SmartContract
      prop :pub_key_hash, Addr

      def initialize(pub_key_hash)
        super(pub_key_hash)
        @pub_key_hash = pub_key_hash
      end

      runar_public sig: Sig, pub_key: PubKey
      def unlock(sig, pub_key)
        assert hash160(pub_key) == @pub_key_hash
        assert check_sig(sig, pub_key)
      end
    end
  RUBY

  def test_scan_fixtures_fails_on_missing_source
    Dir.mktmpdir do |root|
      fixture_dir = File.join(root, 'no-source-fixture')
      FileUtils.mkdir_p(fixture_dir)
      # No .runar.rb file and no source.json -> find_ruby_source returns nil.

      result = scan_fixtures([fixture_dir])

      failure = result[:failures].find { |(name, _k, _e, _a)| name == 'no-source-fixture' }
      refute_nil failure,
                 'a fixture with no .runar.rb source and no compilers allowlist must be ' \
                 "reported as a failure, not silently dropped (got: #{result.inspect})"
    end
  end

  def test_scan_fixtures_fails_on_missing_golden
    Dir.mktmpdir do |root|
      fixture_dir = File.join(root, 'no-golden-fixture')
      FileUtils.mkdir_p(fixture_dir)
      File.write(File.join(fixture_dir, 'Probe.runar.rb'), MINIMAL_RUBY_SOURCE)
      # Source compiles cleanly, but deliberately no expected-ir.json /
      # expected-script.hex.

      result = scan_fixtures([fixture_dir])

      failure = result[:failures].find { |(name, _k, _e, _a)| name == 'no-golden-fixture' }
      refute_nil failure,
                 'a fixture whose .runar.rb compiles but ships no expected-ir.json / ' \
                 "expected-script.hex must be reported as a failure (got: #{result.inspect})"
    end
  end

  def test_scan_fixtures_skips_allowlist_excluded_fixture_with_no_source
    Dir.mktmpdir do |root|
      fixture_dir = File.join(root, 'go-only-fixture')
      FileUtils.mkdir_p(fixture_dir)
      File.write(File.join(fixture_dir, 'source.json'), JSON.generate({ 'compilers' => ['go'] }))
      # No .runar.rb source -- legitimate, since the allowlist excludes ruby
      # for this fixture (conformance/README.md "Per-fixture compiler
      # allowlist").

      result = scan_fixtures([fixture_dir])

      assert_empty result[:failures],
                   "a ruby-excluded fixture must not be reported as a failure (got: #{result.inspect})"
      assert_includes result[:skipped], 'go-only-fixture'
    end
  end
end
