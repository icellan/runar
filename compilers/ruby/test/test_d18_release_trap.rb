# frozen_string_literal: true

# #199 (release-trap warning), D18 (dropped-continuation refusal), D27 (dead
# state write) and D26 (locktime domain, locktime-domain-cases.json).
# Port of packages/runar-compiler/src/passes/continuation-rules.ts.
# Corpora: conformance/negatives/release-trap-cases.json and
# conformance/negatives/dropped-continuation-cases.json.
#
# Proves: the Ruby CLI warns (stderr, exit 0) on every #199 warn shape and on
# no nowarn shape; refuses every D18 refuse shape with the shared text on the
# source path; compiles every D18 accept shape; and refuses the TS-lowered,
# typecheck-skipped ANF of the issue #180 Lock contract on the --ir path.
# Does not prove: the other six tiers, or byte parity (gk-frontend-parity.test.ts).

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class D18ReleaseTrapTest < Minitest::Test
  CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)
  NEG = File.expand_path('../../../conformance/negatives', __dir__)
  RELEASE = JSON.parse(File.read(File.join(NEG, 'release-trap-cases.json')))
  DROPPED = JSON.parse(File.read(File.join(NEG, 'dropped-continuation-cases.json')))
  LOCK_IR = File.expand_path('fixtures/d18_issue180_lock.ir.json', __dir__)
  LOCKTIME = JSON.parse(File.read(File.join(NEG, 'locktime-domain-cases.json')))

  def run_cli(*args)
    out, err, st = Open3.capture3(RbConfig.ruby, CLI, *args)
    [st.success?, out, err]
  end

  def cli(file, src)
    Dir.mktmpdir do |d|
      path = File.join(d, file)
      File.write(path, src)
      run_cli('--source', path, '--hex')
    end
  end

  RELEASE['warn'].each do |c|
    define_method("test_199_warns_#{c['name'].tr('-', '_')}") do
      ok, out, err = cli(c['file'], c['src'])
      assert ok, err
      refute_empty out.strip
      assert_includes err, c['warning']
    end
  end

  RELEASE['nowarn'].each do |c|
    define_method("test_199_no_warning_#{c['name'].tr('-', '_')}") do
      ok, out, err = cli(c['file'], c['src'])
      assert ok, err
      refute_includes "#{out}\n#{err}", c['warning_absent']
    end
  end

  DROPPED['refuse'].each do |c|
    define_method("test_d18_refuses_#{c['name'].tr('-', '_')}") do
      ok, out, err = cli(c['file'], c['src'])
      refute ok, "accepted #{c['name']}: #{out[0, 120]}"
      assert_includes "#{out}\n#{err}", c['error']
    end
  end

  DROPPED['accept'].each do |c|
    define_method("test_d18_accepts_#{c['name'].tr('-', '_')}") do
      ok, out, err = cli(c['file'], c['src'])
      assert ok, err
      refute_empty out.strip
    end
  end

  def test_d18_ir_path_refuses_issue180_lock
    ok, out, err = run_cli('--ir', LOCK_IR, '--hex')
    refute ok, "accepted the Lock IR: #{out[0, 120]}"
    diag = "#{out}\n#{err}"
    refute_match(/Traceback|\.rb:\d+:in /, diag)
    assert_includes diag, DROPPED['refuse'].find { |c| c['name'] == 'issue-180-lock' }['error']
  end

  # Per path: the TS ANF of terminal-branch-writes-nothing with an update_prop
  # added to its raw-output `if` arm (the IR ir-release-trap.test.ts hand-builds).
  def test_d18_ir_path_refuses_write_on_raw_branch
    ok, out, err = run_cli('--ir', File.expand_path('fixtures/d18_write_on_raw_branch.ir.json', __dir__), '--hex')
    refute ok, "accepted the write-on-raw-branch IR: #{out[0, 120]}"
    diag = "#{out}\n#{err}"
    refute_match(/Traceback|\.rb:\d+:in /, diag)
    assert_includes diag, DROPPED['refuse'].find { |c| c['name'] == 'write-on-raw-branch-sibling-add-output' }['error']
  end

  def test_d18_ir_path_accepts_terminal_branch_writes_nothing
    ok, out, err = run_cli('--ir', File.expand_path('fixtures/d18_terminal_branch_writes_nothing.ir.json', __dir__), '--hex')
    assert ok, err
    refute_empty out.strip
  end
  # D27: a state write after the path's last addOutput is dead on chain.
  DROPPED['refuse_after_last'].each do |c|
    define_method("test_d27_refuses_#{c['name'].tr('-', '_')}") do
      ok, out, err = cli(c['file'], c['src'])
      refute ok, "accepted #{c['name']}: #{out[0, 120]}"
      assert_includes "#{out}\n#{err}", c['error']
    end
  end

  # D26: a lower-bound locktime gate must pin the locktime domain on its path.
  LOCKTIME['refuse'].each do |c|
    define_method("test_d26_refuses_#{c['name'].tr('-', '_')}") do
      ok, out, err = cli(c['file'], c['src'])
      refute ok, "accepted #{c['name']}: #{out[0, 120]}"
      assert_includes "#{out}\n#{err}", c['error']
    end
  end

  LOCKTIME['accept'].each do |c|
    define_method("test_d26_accepts_#{c['name'].tr('-', '_')}") do
      ok, out, err = cli(c['file'], c['src'])
      assert ok, err
      refute_empty out.strip
    end
  end

  # N534 is both a D26 gate and a D14 unchecked-extractor refusal: both are reported.
  def test_d26_does_not_mask_d14
    ok, out, err = cli('N534.runar.ts', File.read(File.join(NEG, 'N534-ts-extractor-bytestring-property.runar.ts')))
    refute ok
    diag = "#{out}\n#{err}"
    assert_includes diag, 'extractLocktime() needs a checked SigHashPreimage'
    assert_includes diag, 'compares extractLocktime against a lower bound without pinning'
  end

  # --ir: the accepted height-gate-pinned ANF compiles; with its pin assert
  # removed it is refused with the shared text.
  def test_d26_ir_path_refuses_unpinned_gate
    c = LOCKTIME['accept'].find { |x| x['name'] == 'height-gate-pinned' }
    want = LOCKTIME['refuse'].find { |x| x['name'] == 'height-gate-property' }['error']
    Dir.mktmpdir do |d|
      src = File.join(d, c['file'])
      File.write(src, c['src'])
      ok, ir_json, err = run_cli('--source', src, '--emit-ir')
      assert ok, err
      ir = JSON.parse(ir_json)
      path = File.join(d, 'pinned.ir.json')
      File.write(path, JSON.generate(ir))
      ok, out, err = run_cli('--ir', path, '--hex')
      assert ok, err
      refute_empty out.strip

      body = ir['methods'].find { |m| m['name'] == 'unlock' }['body']
      pin = body.find { |b| b['value']['kind'] == 'bin_op' && b['value']['op'] == '<' }['name']
      body.reject! { |b| b['value']['kind'] == 'assert' && b['value']['value'] == pin }
      File.write(path, JSON.generate(ir))
      ok, out, err = run_cli('--ir', path, '--hex')
      refute ok, "accepted the unpinned IR: #{out[0, 120]}"
      diag = "#{out}\n#{err}"
      refute_match(/Traceback|\.rb:\d+:in /, diag)
      assert_includes diag, want
    end
  end
end
