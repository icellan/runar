# frozen_string_literal: true

# GK-BUG-015 -- a contract may not declare two methods with the same name.
#
# Every name-keyed later pass (side-effect summary, private-method lookup,
# stack lowering's private map, the affine consumption fixpoint) assumed one
# body per name and nothing enforced it: two public `withdraw` bodies both
# became spend entries, and two same-named privates with different Sig
# consumption could make the consumption fixpoint oscillate. The validator now
# refuses a repeated method name with the diagnostic every tier shares; the
# corpus is the cross-tier one in conformance/negatives/duplicate-method-cases.json.
#
# Proves: the CLI exits non-zero with the shared diagnostic for every corpus
# case (under a hard timeout, so a hang fails instead of wedging the suite),
# and each renamed twin compiles.
# Does not prove: anything about the other six tiers.

require 'json'
require 'open3'
require 'timeout'
require 'tmpdir'
require_relative 'test_helper'

class GK015DuplicateMethodTest < Minitest::Test
  RUBY_CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)
  CORPUS = JSON.parse(File.read(File.expand_path(
    '../../../conformance/negatives/duplicate-method-cases.json', __dir__
  )))['cases']

  def compile_hex(file, src)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file)
      File.write(path, src)
      Open3.popen3(RbConfig.ruby, RUBY_CLI, '--source', path, '--hex') do |stdin, stdout, stderr, wait|
        stdin.close
        unless wait.join(60)
          Process.kill('KILL', wait.pid)
          flunk "#{file}: compile did not finish within 60s"
        end
        out = stdout.read
        [wait.value.success?, out, "#{out}\n#{stderr.read}"]
      end
    end
  end

  CORPUS.each do |c|
    define_method("test_refuses_#{c['name'].tr('-', '_')}") do
      ok, out, diag = compile_hex(c['file'], c['src'])
      refute ok, "accepted #{c['name']}: #{out[0, 200]}"
      assert_includes diag, c['error']
    end

    define_method("test_twin_compiles_#{c['name'].tr('-', '_')}") do
      ok, out, diag = compile_hex(c['file'], c['twin'])
      assert ok, diag
      refute_empty out.strip
    end
  end
end
