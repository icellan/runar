# frozen_string_literal: true

# CLI-mode tests for the Ruby compiler (GAP-m5).
#
# Exercises the two CLI entry points that previously had no dedicated
# per-tier test (the conformance runner exercised them only indirectly):
#
#   * --parse-only --source <file>  — universal frontend coverage mode
#   * --ir <path>                   — compile from ANF IR JSON to script
#
# Both are driven as real subprocesses via the committed `bin/` executable
# so a CLI flag rename or OptionParser regression fails locally instead of
# only surfacing in the conformance harness.

require 'open3'
require_relative 'test_helper'

class TestCli < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby')
  CONFORMANCE_DIR = File.expand_path('../../../conformance/tests', __dir__)
  REPO_ROOT = File.expand_path('../../..', __dir__)
  P2PKH_SOURCE = File.join(REPO_ROOT, 'examples/ruby/p2pkh/P2PKH.runar.rb')
  BASIC_P2PKH = File.join(CONFORMANCE_DIR, 'basic-p2pkh')

  def run_cli(*args)
    Open3.capture3('ruby', RUBY_CLI, *args, chdir: RUBY_COMPILER_DIR)
  end

  # --------------------------------------------------------------------
  # --parse-only
  # --------------------------------------------------------------------

  def test_parse_only_accepts_valid_source
    assert File.exist?(P2PKH_SOURCE), "missing fixture: #{P2PKH_SOURCE}"
    stdout, stderr, status = run_cli('--parse-only', '--source', P2PKH_SOURCE)
    assert status.success?, "--parse-only failed: #{stderr}"
    assert_equal 'parser ok', stdout.strip
  end

  def test_parse_only_requires_source
    _stdout, stderr, status = run_cli('--parse-only', '--ir', 'ignored.json')
    refute status.success?
    assert_includes stderr, '--parse-only requires --source'
  end

  def test_parse_only_rejects_missing_file
    _stdout, stderr, status = run_cli('--parse-only', '--source', '/nonexistent/Contract.runar.rb')
    refute status.success?
    assert_includes stderr.downcase, 'parse error'
  end

  # --------------------------------------------------------------------
  # --ir (compile from ANF IR JSON)
  # --------------------------------------------------------------------

  def test_ir_mode_compiles_to_byte_frozen_script
    ir_path = File.join(BASIC_P2PKH, 'expected-ir.json')
    golden_hex = File.read(File.join(BASIC_P2PKH, 'expected-script.hex')).strip
    assert File.exist?(ir_path), "missing fixture: #{ir_path}"

    stdout, stderr, status = run_cli('--ir', ir_path, '--hex', '--disable-constant-folding')
    assert status.success?, "--ir compile failed: #{stderr}"
    assert_equal golden_hex, stdout.strip
  end

  def test_no_input_flag_errors
    _stdout, stderr, status = run_cli
    refute status.success?
    assert_includes stderr, 'Usage:'
  end

  # --------------------------------------------------------------------
  # --emit-ir + --emit-source-map (F-255)
  #
  # The --emit-ir branch printed the IR JSON and `return`ed unconditionally,
  # before the code further down that services --emit-source-map ever ran.
  # `--source X --emit-ir --emit-source-map Y` exited 0 and Y was never
  # created — the request was silently dropped, not refused. Go had the
  # identical bug (F-183) and Java was always correct ("GAP-002:
  # --emit-source-map ... runs INDEPENDENTLY of --emit-ir"); this ports Go's
  # fix (fall through into the full compile so the source map gets
  # populated and written, then stop before the hex/artifact output) to the
  # Ruby tier.
  # --------------------------------------------------------------------

  def test_emit_ir_with_emit_source_map_writes_the_source_map_and_prints_only_ir
    assert File.exist?(P2PKH_SOURCE), "missing fixture: #{P2PKH_SOURCE}"
    require 'tmpdir'
    Dir.mktmpdir do |dir|
      sm_path = File.join(dir, 'source-map.json')
      refute File.exist?(sm_path), 'sanity: source map path must not pre-exist'

      stdout, stderr, status = run_cli(
        '--source', P2PKH_SOURCE,
        '--emit-ir',
        '--emit-source-map', sm_path
      )
      assert status.success?, "--emit-ir --emit-source-map must exit 0\nstdout: #{stdout}\nstderr: #{stderr}"

      # The finding itself: the file must actually be written.
      assert File.exist?(sm_path), "--emit-source-map file was never written (F-255 regression); stderr: #{stderr}"
      sm_json = JSON.parse(File.read(sm_path))
      assert sm_json.key?('mappings'), "source map JSON must carry a 'mappings' key, got: #{sm_json}"

      # --emit-ir's contract: stdout carries only the IR, never the full
      # artifact (which would carry a "script" field).
      stdout_json = JSON.parse(stdout)
      assert stdout_json.key?('contractName'), "stdout must be ANF IR (expected a contractName field), got: #{stdout}"
      refute stdout_json.key?('script'), "stdout must carry ONLY the IR, not the compiled artifact; got: #{stdout}"
    end
  end

  # --------------------------------------------------------------------
  # --source + --ir together (F-335)
  #
  # The dispatch at the bottom of CLI.run picked --source whenever both
  # --source and --ir were given, with no diagnostic (CL-GAP-054). The Go
  # tier already refuses this combination (F-183: "--source and --ir are
  # mutually exclusive; pass exactly one"); this ports the same refusal,
  # with the same message, to the Ruby tier.
  #
  # Proves: giving both flags is a usage error (non-zero exit, a stderr
  # diagnostic naming both flags), not a silent --source win.
  # Does not prove: that Python, Rust, Zig, or Java refuse the same
  # combination -- a repo-wide grep during this fix found none of them do;
  # only Go and (after this fix) Ruby refuse it. That is a latent gap in
  # those other tiers, out of scope for this Ruby-only item.
  # --------------------------------------------------------------------

  def test_source_and_ir_together_is_a_usage_error
    assert File.exist?(P2PKH_SOURCE), "missing fixture: #{P2PKH_SOURCE}"
    ir_path = File.join(BASIC_P2PKH, 'expected-ir.json')
    assert File.exist?(ir_path), "missing fixture: #{ir_path}"

    stdout, stderr, status = run_cli('--source', P2PKH_SOURCE, '--ir', ir_path)
    refute status.success?, "expected a non-zero exit, got stdout: #{stdout.inspect}"
    assert_includes stderr, '--source and --ir are mutually exclusive'
  end

  # --------------------------------------------------------------------
  # --output (CL-GAP-054: previously untested)
  #
  # Proves: --output writes the full artifact JSON to the given path
  # (not stdout), the artifact on disk is valid JSON carrying a "script"
  # field, and a confirmation line is printed to stderr.
  # Does not prove: --output's interaction with --hex/--asm beyond the
  # default (full-artifact) output mode.
  # --------------------------------------------------------------------

  def test_output_flag_writes_artifact_json_to_file
    assert File.exist?(P2PKH_SOURCE), "missing fixture: #{P2PKH_SOURCE}"
    require 'tmpdir'
    Dir.mktmpdir do |dir|
      out_path = File.join(dir, 'artifact.json')
      refute File.exist?(out_path), 'sanity: output path must not pre-exist'

      stdout, stderr, status = run_cli('--source', P2PKH_SOURCE, '--output', out_path)
      assert status.success?, "--output compile failed: #{stderr}"
      assert_equal '', stdout.strip, '--output must not also print the artifact to stdout'
      assert_includes stderr, "Output written to #{out_path}"

      assert File.exist?(out_path), '--output file was never written'
      artifact = JSON.parse(File.read(out_path))
      assert artifact.key?('script'), "written artifact must carry a script field, got: #{artifact.keys}"
    end
  end

  # --------------------------------------------------------------------
  # --asm (CL-GAP-054: previously untested)
  #
  # Proves: --asm prints human-readable opcode mnemonics (not JSON, not
  # the hex the same compile would produce with --hex).
  # Does not prove: full ASM grammar/formatting correctness -- only that
  # the flag selects the ASM output path and it differs from the other
  # two output modes.
  # --------------------------------------------------------------------

  def test_asm_flag_outputs_opcode_mnemonics
    assert File.exist?(P2PKH_SOURCE), "missing fixture: #{P2PKH_SOURCE}"

    asm_stdout, asm_stderr, asm_status = run_cli('--source', P2PKH_SOURCE, '--asm')
    assert asm_status.success?, "--asm compile failed: #{asm_stderr}"

    hex_stdout, _hex_stderr, hex_status = run_cli('--source', P2PKH_SOURCE, '--hex')
    assert hex_status.success?

    assert_includes asm_stdout, 'OP_', "expected opcode mnemonics in --asm output, got: #{asm_stdout}"
    refute_equal hex_stdout.strip, asm_stdout.strip, '--asm output must differ from --hex output'
    assert_raises(JSON::ParserError) { JSON.parse(asm_stdout) }
  end

  # --------------------------------------------------------------------
  # --emit-ir-to (CL-GAP-054: previously untested)
  #
  # Proves: --emit-ir-to writes the ANF IR JSON to the given path AND
  # (unlike --emit-ir) falls through to finish the normal compile, so
  # stdout still carries the requested --hex output in the same run.
  # Does not prove: that the written IR is byte-identical to --emit-ir's
  # stdout output (covered by other, pre-existing tests of
  # _anf_to_camel_dict).
  # --------------------------------------------------------------------

  def test_emit_ir_to_writes_ir_and_still_completes_the_compile
    assert File.exist?(P2PKH_SOURCE), "missing fixture: #{P2PKH_SOURCE}"
    require 'tmpdir'
    Dir.mktmpdir do |dir|
      ir_out_path = File.join(dir, 'program.json')
      refute File.exist?(ir_out_path), 'sanity: IR output path must not pre-exist'

      stdout, stderr, status = run_cli('--source', P2PKH_SOURCE, '--emit-ir-to', ir_out_path, '--hex')
      assert status.success?, "--emit-ir-to compile failed: #{stderr}"

      assert File.exist?(ir_out_path), '--emit-ir-to file was never written'
      ir_json = JSON.parse(File.read(ir_out_path))
      assert ir_json.key?('contractName'), "written IR must carry a contractName field, got: #{ir_json.keys}"

      # The compile fell through past --emit-ir-to and still produced the
      # --hex output on stdout (--emit-ir-to is NOT a stop-after-IR flag).
      refute_empty stdout.strip
      assert_match(/\A[0-9a-f]+\z/, stdout.strip, "stdout must be hex, got: #{stdout}")
    end
  end

  # --------------------------------------------------------------------
  # --emit-source-map on every output mode (N-186)
  #
  # Zig and the TS CLI dropped --emit-source-map under --hex and for an IR
  # input, exiting 0 with nothing written. This CLI already writes the map on
  # those paths; these tests pin that. For --ir there are no source
  # locations, so the map is the empty {"mappings": []} wrapper.
  # Proves: the file exists with that shape and stdout stays the requested
  # output. Does not prove: any other tier's CLI.
  # --------------------------------------------------------------------

  def run_with_source_map(*args)
    require 'tmpdir'
    Dir.mktmpdir do |dir|
      sm_path = File.join(dir, 'source-map.json')
      stdout, stderr, status = run_cli(*args, '--emit-source-map', sm_path)
      assert status.success?, "must exit 0: #{stderr}"
      assert File.exist?(sm_path), "--emit-source-map file was never written (N-186); stderr: #{stderr}"
      sm = JSON.parse(File.read(sm_path))
      assert sm.key?('mappings'), "source map must carry a mappings key, got: #{sm.keys}"
      return [stdout, sm]
    end
  end

  def test_hex_with_emit_source_map_writes_the_source_map
    stdout, sm = run_with_source_map('--source', P2PKH_SOURCE, '--hex')
    refute_empty sm['mappings'], 'a real source compile must carry mappings'
    assert_match(/\A[0-9a-f]+\z/, stdout.strip)
  end

  def test_ir_input_with_emit_source_map_writes_the_empty_source_map
    ir = File.join(BASIC_P2PKH, 'expected-ir.json')
    [[], ['--hex'], ['--asm']].each do |extra|
      _stdout, sm = run_with_source_map('--ir', ir, *extra)
      assert_equal [], sm['mappings'], "IR input has no source locations (#{extra.inspect})"
    end
  end
end
