# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'

# N-075 -- the multi-output continuation path keeps the 1sat inscription
# envelope. +prepare_call(outputs: [...])+ built each output from the bare code
# script and dropped the envelope, while the single-output path
# (+get_locking_script+) kept it; the covenant's _codePart includes the
# envelope, so the multi-output spend's hashOutputs could never match.
#
# Proves: with an inscription attached, every multi-output script is
# byte-identical to the single-output locking script for the same state.
# Does NOT prove: a full spend validating under a script interpreter, nor the
# same fix in the other SDKs.
N075_ARTIFACT_JSON = JSON.generate(
  version:            '1.0',
  compilerVersion:    '0.1.0',
  contractName:       'Counter',
  abi:                {
    constructor: { params: [{ name: 'count', type: 'bigint' }] },
    methods:     [{ name: 'increment', params: [], isPublic: true }]
  },
  script:             'aabbcc',
  asm:                '',
  stateFields:        [{ name: 'count', type: 'bigint', index: 0 }],
  constructorSlots:   [],
  codeSeparatorIndex: 0
).freeze

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-075 multi-output continuation inscription envelope' do
  # rubocop:enable RSpec/DescribeClass
  let(:artifact) { Runar::SDK::RunarArtifact.from_json(N075_ARTIFACT_JSON) }
  let(:insc) { Runar::SDK::Inscription.new(content_type: 'text/plain', data: '68656c6c6f') }
  let(:address) { 'cd' * 20 }
  let(:signer) { Runar::SDK::MockSigner.new(pub_key_hex: "02#{'ab' * 32}", address: address) }

  it 'builds every output equal to the single-output locking script' do
    provider = Runar::SDK::MockProvider.new
    provider.add_utxo(address, Runar::SDK::Utxo.new(txid: 'aa' * 32, output_index: 0, satoshis: 1_000_000,
                                                    script: "76a914#{address}88ac"))
    contract = Runar::SDK::RunarContract.new(artifact, [0]).with_inscription(insc)
    utxo = Runar::SDK::Utxo.new(txid: 'cc' * 32, output_index: 0, satoshis: 10_000,
                                script: contract.get_locking_script)
    contract.instance_variable_set(:@current_utxo, utxo)

    opts = Runar::SDK::CallOptions.new(outputs: [
                                         Runar::SDK::OutputSpec.new(satoshis: 2000, state: { 'count' => 7 }),
                                         Runar::SDK::OutputSpec.new(satoshis: 2000, state: { 'count' => 9 })
                                       ])
    prepared = contract.prepare_call('increment', [], provider, signer, opts)

    expect(prepared.contract_outputs.length).to eq(2)
    [7, 9].each_with_index do |count, i|
      expected = Runar::SDK::RunarContract.new(artifact, [count]).with_inscription(insc).get_locking_script
      expect(prepared.contract_outputs[i][:script]).to eq(expected)
    end
  end
end
