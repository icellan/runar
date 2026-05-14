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
end
