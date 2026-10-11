# frozen_string_literal: true

# N-038 — a stateful `@sighash SINGLE|FORKID` method's continuation hashes only
# the method's own output (BIP-143 SINGLE commits hashOutputs to
# hash256(output[inputIndex]) alone), and the method takes no
# `_changePKH` / `_changeAmount` params.
#
# Proves: the Ruby compiler emits the TS reference's IR and script for the
# N-038 sdk-call pins (conformance/sdk-call/expected-{ir.json,script.hex}) byte for byte (fold OFF), the
# SINGLE method's ABI is exactly [txPreimage] and stays non-terminal, the ALL
# method in the same contract keeps its change params, and the `--ir`
# scaffolding check accepts the SINGLE shape (no change params required).
# Does not prove: on-chain acceptance (the sdk-call vector Spend replay and the TS SDK
# Spend tests do that).

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class TestN038SighashSingleContinuation < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby')
  REPO_ROOT = File.expand_path('../..', RUBY_COMPILER_DIR)
  FIXTURE = File.join(REPO_ROOT, 'conformance/sdk-call')
  SOURCE = File.join(REPO_ROOT, 'conformance/sdk-call/SingleCounter.runar.ts')

  def canonicalize(value)
    case value
    when Hash
      value.keys.sort.each_with_object({}) do |k, out|
        out[k] = canonicalize(value[k]) unless k == 'sourceLoc'
      end
    when Array then value.map { |v| canonicalize(v) }
    else value
    end
  end

  def canonical_json(str)
    JSON.pretty_generate(canonicalize(JSON.parse(str)), indent: '  ')
  end

  def run_cli(*args)
    Open3.capture3('ruby', RUBY_CLI, *args, chdir: RUBY_COMPILER_DIR)
  end

  def test_ir_matches_golden
    out, err, status = run_cli('--source', SOURCE, '--emit-ir', '--disable-constant-folding')
    assert status.success?, err
    assert_equal canonical_json(File.read(File.join(FIXTURE, 'expected-ir.json'))), canonical_json(out)
  end

  def test_script_matches_golden
    out, err, status = run_cli('--source', SOURCE, '--hex', '--disable-constant-folding')
    assert status.success?, err
    assert_equal File.read(File.join(FIXTURE, 'expected-script.hex')).split.join.downcase, out.split.join.downcase
  end

  def test_single_method_abi_has_no_change_params_and_is_not_terminal
    out, err, status = run_cli('--source', SOURCE, '--disable-constant-folding')
    assert status.success?, err
    methods = JSON.parse(out)['abi']['methods'].to_h { |m| [m['name'], m] }
    bump = methods.fetch('bump')
    assert_equal ['txPreimage'], bump['params'].map { |p| p['name'] }
    assert_equal 0x43, bump['sigHashType']
    refute bump['isTerminal']
    assert_equal %w[_changePKH _changeAmount _newAmount txPreimage],
                 methods.fetch('reset')['params'].map { |p| p['name'] }
  end

  def test_ir_scaffold_check_follows_the_single_shape
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'prog.json')
      File.write(path, File.read(File.join(FIXTURE, 'expected-ir.json')))
      _out, err, status = run_cli('--ir', path, '--hex')
      assert status.success?, err
    end
  end
end
