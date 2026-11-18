# frozen_string_literal: true

# #199 (release-trap warning) and D18 (dropped-continuation refusal).
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
end
