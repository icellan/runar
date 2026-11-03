# frozen_string_literal: true

require 'spec_helper'
require 'runar/analyzer'

RSpec.describe 'Analyzer conformance' do
  # Local variables, not constants: `CONST = value` written directly inside
  # an RSpec.describe block binds a top-level Object constant (a block
  # opens no constant scope), which can collide with a same-named bare
  # constant in another spec file (N-269;
  # packages/runar-rb/spec/lint/bare_describe_constants_spec.rb guards
  # against it).
  fixtures = %w[
    basic-p2pkh
    escrow
    stateful-counter
    auction
    covenant-vault
    ec-demo
    schnorr-zkp
    if-else
  ].freeze

  repo_root = File.expand_path('../../../..', __dir__)

  fixtures.each do |fixture|
    it "produces byte-identical JSON for #{fixture}" do
      hex_path = File.join(repo_root, 'conformance', 'tests', fixture, 'expected-script.hex')
      golden_path = File.join(repo_root, 'conformance', 'analyzer', fixture, 'expected-analyzer-report.json')

      skip "missing hex: #{hex_path}" unless File.exist?(hex_path)
      skip "missing golden: #{golden_path}" unless File.exist?(golden_path)

      hex = File.read(hex_path).strip
      golden = File.read(golden_path)
      result = Runar::Analyzer.analyze_script(hex)
      actual = Runar::Analyzer.to_canonical_json(result)

      expect(actual).to eq(golden)
    end
  end
end
