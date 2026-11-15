# frozen_string_literal: true

# GK-GAP-010 -- a public method's SigHashPreimage parameter must reach
# checkPreimage() on every path (spec/type-system.md 4.2). The affine checker
# only refused a SECOND use, so a stateless method reading fields out of an
# unchecked (spender-chosen) preimage typechecked.
# Corpus: conformance/negatives/preimage-checked-cases.json.
#
# Proves: the CLI refuses each refused shape with the shared diagnostic and
# compiles each accepted shape.
# Does not prove: the other six tiers.

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class GK010PreimageCheckedTest < Minitest::Test
  CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)
  CORPUS = JSON.parse(File.read(File.expand_path(
    '../../../conformance/negatives/preimage-checked-cases.json', __dir__
  )))

  def cli(file, src)
    Dir.mktmpdir do |d|
      path = File.join(d, file)
      File.write(path, src)
      out, err, st = Open3.capture3(RbConfig.ruby, CLI, '--source', path, '--hex')
      [st.success?, out, "#{out}\n#{err}"]
    end
  end

  CORPUS['refuse'].each do |c|
    define_method("test_refuses_#{c['name'].tr('-', '_')}") do
      ok, out, diag = cli(c['file'], c['src'])
      refute ok, "accepted #{c['name']}: #{out[0, 120]}"
      assert_includes diag, c['error']
    end
  end

  CORPUS['accept'].each do |c|
    define_method("test_accepts_#{c['name'].tr('-', '_')}") do
      ok, out, diag = cli(c['file'], c['src'])
      assert ok, diag
      refute_empty out.strip
    end
  end
end
