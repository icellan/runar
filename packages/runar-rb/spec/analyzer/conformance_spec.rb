# frozen_string_literal: true

require 'spec_helper'
require 'runar/analyzer'

RSpec.describe 'Analyzer conformance' do
  FIXTURES = %w[
    basic-p2pkh
    escrow
    stateful-counter
    auction
    covenant-vault
    ec-demo
    schnorr-zkp
    if-else
  ].freeze

  REPO_ROOT = File.expand_path('../../../..', __dir__)

  FIXTURES.each do |fixture|
    it "produces byte-identical JSON for #{fixture}" do
      hex_path = File.join(REPO_ROOT, 'conformance', 'tests', fixture, 'expected-script.hex')
      golden_path = File.join(REPO_ROOT, 'conformance', 'analyzer', fixture, 'expected-analyzer-report.json')

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
