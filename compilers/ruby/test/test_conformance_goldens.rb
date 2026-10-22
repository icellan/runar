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

  # N-389 (R145, "named set, keep coverage"): fixtures Ruby is EXPECTED to
  # refuse. Ruby refuses the BN254 pairing family (bn254MultiPairing4) by
  # policy. A fixture is skipped only when it is named here AND its
  # source.json allowlist excludes ruby. Every other fixture, including the
  # Go-only ones Ruby compiles byte-identically today (babybear,
  # babybear-ext4, merkle-proof, state-covenant), is compiled and
  # byte-checked, and a refusal there is a failure. Mirrors the Python
  # harness's EXPECTED_NOT_PYTHON_COMPILABLE (N-387).
  EXPECTED_NOT_RUBY_COMPILABLE = %w[bn254-pairing].freeze

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

    # F-264: fail closed. A broad `rescue ... StandardError` here used to
    # swallow every failure reading source.json (permission errors,
    # directories where a file is expected, malformed JSON, ...) and
    # silently treat the fixture as having no allowlist at all. Let it
    # raise -- a malformed or unreadable config must surface, not be
    # misreported downstream as a generic "missing-source" failure.
    cfg = JSON.parse(File.read(config_path))

    return nil unless cfg.key?('compilers')

    # N-389: fail closed. A `compilers` value that is not a list of strings
    # used to be treated as "no allowlist" (nil), silently admitting the
    # fixture.
    list = cfg['compilers']
    unless list.is_a?(Array) && list.all? { |x| x.is_a?(String) }
      raise ArgumentError,
            "fixture '#{File.basename(test_dir)}': source.json 'compilers' must be a list of strings, got #{list.inspect}"
    end
    list
  end

  # Independent (raw source.json) check that the allowlist excludes ruby.
  # Deliberately does not go through read_compiler_allowlist.
  def excludes_ruby_raw?(test_dir)
    config_path = File.join(test_dir, 'source.json')
    return false unless File.exist?(config_path)

    list = JSON.parse(File.read(config_path))['compilers']
    !list.nil? && !list.include?('ruby')
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
      # F-264: fail closed (see read_compiler_allowlist above). A broad
      # `rescue ... StandardError` here used to swallow every failure
      # reading source.json and fall through to the *.runar.rb glob as if
      # no config existed, misreporting the real cause (e.g. a permission
      # error) as a plain "missing-source" failure.
      cfg = JSON.parse(File.read(config_path))
      rel = cfg.dig('sources', '.runar.rb')
      if rel.is_a?(String)
        resolved = File.expand_path(rel, test_dir)
        return resolved if File.exist?(resolved)
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
  #   - N-389 (R145): a fixture is SKIPPED only when it is named in
  #     `not_compilable` (default EXPECTED_NOT_RUBY_COMPILABLE) AND its
  #     source.json `compilers` allowlist excludes "ruby". A named fixture
  #     whose allowlist does not exclude ruby is a
  #     'stale-expected-not-compilable' FAILURE. An unnamed fixture is
  #     always compiled and byte-checked, even when its allowlist excludes
  #     ruby.
  #   - Any other fixture with no resolvable .runar.rb source is a FAILURE.
  #   - A fixture whose source compiles but ships no expected-ir.json or
  #     no expected-script.hex is a FAILURE (this harness is the sole
  #     check of Ruby's output; unlike the TS runner -- which also relies
  #     on cross-tier comparison -- there is no other gate here).
  #
  # Returns { passed: [name...], skipped: [name...], failures: [[name, kind,
  # expected, actual], ...] }.
  # ------------------------------------------------------------------
  def scan_fixtures(dirs, not_compilable = EXPECTED_NOT_RUBY_COMPILABLE)
    passed = []
    skipped = []
    failures = []  # each entry: [name, kind, expected, actual]

    dirs.each do |test_dir|
      name = File.basename(test_dir)

      allowlist = read_compiler_allowlist(test_dir)
      if not_compilable.include?(name)
        if allowlist && !allowlist.include?('ruby')
          skipped << name
        else
          failures << [name, 'stale-expected-not-compilable', '',
                       "fixture '#{name}' is named in EXPECTED_NOT_RUBY_COMPILABLE but its " \
                       'source.json allowlist does not exclude ruby']
        end
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

    # N-389: the skipped set must be exactly the named set; every named
    # entry must exist and really exclude ruby in its raw source.json.
    assert_equal EXPECTED_NOT_RUBY_COMPILABLE.sort, skipped
    EXPECTED_NOT_RUBY_COMPILABLE.each do |n|
      dir = File.join(CONFORMANCE_DIR, n)
      assert File.directory?(dir), "EXPECTED_NOT_RUBY_COMPILABLE names unknown fixture #{n.inspect}"
      assert excludes_ruby_raw?(dir), "#{n.inspect} allowlist does not exclude ruby"
    end
    assert_equal total, passed.length + skipped.length
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
      # for this fixture AND the fixture is named as expected-not-compilable
      # (N-389; conformance/README.md "Per-fixture compiler allowlist").

      result = scan_fixtures([fixture_dir], ['go-only-fixture'])

      assert_empty result[:failures],
                   "a ruby-excluded fixture must not be reported as a failure (got: #{result.inspect})"
      assert_includes result[:skipped], 'go-only-fixture'
    end
  end

  # ------------------------------------------------------------------
  # F-264: `read_compiler_allowlist` and `find_ruby_source` each wrapped
  # their `source.json` read in `rescue JSON::ParserError, StandardError`
  # -- the second clause is a superset of the first, so it swallows EVERY
  # failure (permission errors, a directory where a file is expected,
  # malformed JSON, ...), not just a genuinely absent/malformed config,
  # and silently falls through to "nil allowlist" / "glob for *.runar.rb"
  # as if source.json had never existed. A fixture whose source.json is
  # unreadable for an unrelated reason (e.g. EISDIR, EACCES) then gets
  # misclassified as a generic "missing-source" failure -- the operator
  # sees "no .runar.rb source found" and never learns the real cause.
  #
  # Project standing rule (fail-closed): a malformed config must surface,
  # not be swallowed -- mirrors F-225 (multi-format.test.ts), which
  # removed an identical swallow-to-empty-config try/catch.
  #
  # What this proves: a non-JSON::ParserError StandardError raised while
  # reading a fixture's source.json (here: EISDIR, because `source.json`
  # is a directory, not a file) propagates out of `scan_fixtures` instead
  # of being silently reclassified as "missing-source".
  #
  # What this does NOT prove: that the real conformance/tests corpus
  # contains such a fixture today -- it does not; this is a synthetic,
  # throwaway fixture (via Dir.mktmpdir) that exercises the swallow
  # directly.
  def test_scan_fixtures_surfaces_non_json_error_reading_source_json
    Dir.mktmpdir do |root|
      fixture_dir = File.join(root, 'source-json-is-a-dir')
      FileUtils.mkdir_p(fixture_dir)
      # A directory named `source.json` makes `File.read` raise
      # Errno::EISDIR (a StandardError, but never a JSON::ParserError).
      Dir.mkdir(File.join(fixture_dir, 'source.json'))

      error = assert_raises(SystemCallError) do
        scan_fixtures([fixture_dir])
      end
      assert_kind_of Errno::EISDIR, error
    end
  end

  # What this proves: malformed JSON in source.json (the canonical
  # "malformed config" case) also propagates rather than being silently
  # treated as "no config" -- closing both exception classes the old
  # `rescue JSON::ParserError, StandardError` clause caught.
  #
  # What this does NOT prove: anything about the TS runner's own
  # `readFixtureCompilerAllowlist`, which still swallows malformed JSON
  # to `null` (conformance/runner/runner.ts) -- a pre-existing,
  # out-of-scope inconsistency in that file, not mirrored here.
  def test_scan_fixtures_surfaces_malformed_json_in_source_json
    Dir.mktmpdir do |root|
      fixture_dir = File.join(root, 'malformed-source-json')
      FileUtils.mkdir_p(fixture_dir)
      File.write(File.join(fixture_dir, 'source.json'), '{not valid json')

      assert_raises(JSON::ParserError) do
        scan_fixtures([fixture_dir])
      end
    end
  end

  # ------------------------------------------------------------------
  # N-389 (R145): the sweep used to skip EVERY allowlist-excluded fixture,
  # dropping the byte check on Go-only fixtures Ruby compiles in agreement
  # with Go, and treated a non-list `compilers` value as "no allowlist".
  #
  # What this proves: an allowlist-excluded fixture that is NOT named in
  # the not-compilable set is attempted, not skipped (here it has no
  # source, so it surfaces as a 'missing-source' failure); a named fixture
  # whose allowlist does not exclude ruby is a stale-entry failure; and a
  # non-list `compilers` value raises.
  #
  # What this does NOT prove: the byte comparison for such a fixture (the
  # real-corpus sweep covers babybear, babybear-ext4, merkle-proof and
  # state-covenant); the corpus has no non-list `compilers` value today.
  # ------------------------------------------------------------------
  def test_scan_fixtures_compiles_excluded_but_unnamed_fixture
    Dir.mktmpdir do |root|
      fixture_dir = File.join(root, 'go-only-unnamed')
      FileUtils.mkdir_p(fixture_dir)
      File.write(File.join(fixture_dir, 'source.json'), JSON.generate({ 'compilers' => ['go'] }))

      result = scan_fixtures([fixture_dir], [])

      assert_empty result[:skipped]
      assert_equal ['missing-source'], result[:failures].map { |f| f[1] }
    end
  end

  def test_scan_fixtures_flags_stale_named_entry
    Dir.mktmpdir do |root|
      fixture_dir = File.join(root, 'stale-named')
      FileUtils.mkdir_p(fixture_dir)
      File.write(File.join(fixture_dir, 'source.json'), JSON.generate({ 'compilers' => %w[go ruby] }))

      result = scan_fixtures([fixture_dir], ['stale-named'])

      assert_empty result[:skipped]
      assert_equal ['stale-expected-not-compilable'], result[:failures].map { |f| f[1] }
    end
  end

  def test_scan_fixtures_raises_on_non_list_compilers
    Dir.mktmpdir do |root|
      fixture_dir = File.join(root, 'non-list-compilers')
      FileUtils.mkdir_p(fixture_dir)
      File.write(File.join(fixture_dir, 'source.json'), JSON.generate({ 'compilers' => 'go' }))

      error = assert_raises(ArgumentError) { scan_fixtures([fixture_dir], []) }
      assert_match(/must be a list of strings/, error.message)
    end
  end
end
