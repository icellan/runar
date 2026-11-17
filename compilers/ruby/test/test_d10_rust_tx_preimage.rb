# frozen_string_literal: true

# D10 -- a stateless Rust-DSL contract cannot declare tx_preimage. In the Rust
# DSL that field is the implicit preimage of a stateful contract; this tier
# used to treat `tx_preimage` itself as a mutable field and so compiled a
# #[runar::contract] with no other state as stateful. A contract that resolves
# to stateless never checks the field, so every extractor read of it is
# unverified. Corpus: conformance/negatives/rust-tx-preimage-cases.json.
#
# Proves: the parser and the CLI refuse each stateless shape with the shared
# diagnostic; each stateful shape parses as StatefulSmartContract without a
# txPreimage property and compiles.
# Does not prove: the other six tiers.

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'test_helper'
require 'runar_compiler/frontend/parser_rust'

class D10RustTxPreimageTest < Minitest::Test
  CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)
  CORPUS = JSON.parse(File.read(File.expand_path(
    '../../../conformance/negatives/rust-tx-preimage-cases.json', __dir__
  )))

  def cli(file, src)
    Dir.mktmpdir do |d|
      path = File.join(d, file)
      File.write(path, src)
      out, err, st = Open3.capture3(RbConfig.ruby, CLI, '--source', path, '--hex')
      [st.success?, out, "#{out}\n#{err}"]
    end
  end

  def test_corpus_size
    assert_operator CORPUS['refuse'].size, :>=, 5
    assert_operator CORPUS['accept'].size, :>=, 3
  end

  CORPUS['refuse'].each do |c|
    define_method("test_refuses_#{c['name'].tr('-', '_')}") do
      parsed = RunarCompiler::Frontend.parse_rust(c['src'], c['file'])
      assert parsed.errors.any? { |e| e.to_s.include?(c['error']) }, parsed.errors.map(&:to_s).inspect
      ok, out, diag = cli(c['file'], c['src'])
      refute ok, "accepted #{c['name']}: #{out[0, 120]}"
      assert_includes diag, c['error']
    end
  end

  CORPUS['accept'].each do |c|
    define_method("test_accepts_#{c['name'].tr('-', '_')}") do
      parsed = RunarCompiler::Frontend.parse_rust(c['src'], c['file'])
      assert_empty parsed.errors.map(&:to_s)
      assert_equal 'StatefulSmartContract', parsed.contract.parent_class
      refute(parsed.contract.properties.any? { |p| p.name == 'txPreimage' })
      ok, out, diag = cli(c['file'], c['src'])
      assert ok, diag
      refute_empty out.strip
    end
  end
end
