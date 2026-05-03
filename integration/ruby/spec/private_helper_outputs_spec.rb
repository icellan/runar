# frozen_string_literal: true

# PrivateHelperOutputs integration test -- 2026-04-30 audit regression
# (F1 + F3).
#
# The contract delegates state mutation, addDataOutput, and addOutput to
# private helpers. Before the F1 fix the auto-injection was a shallow
# scan of the public method body, so these methods were silently
# classified as terminal and the deploy + call cycle would fail.
#
# Mirrors the TS / Go / Rust / Python integration tests for the same
# contract.

require 'spec_helper'

RSpec.describe 'PrivateHelperOutputs' do # rubocop:disable RSpec/DescribeClass
  let(:source_path) { 'examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts' }

  it 'chains three commit() calls — each spends the previous continuation UTXO' do
    # Failure here means the runtime hashOutputs hash didn't match the
    # compiled continuation, which is exactly what F1's shallow-scan
    # miss would produce for state-mutation routed through a private
    # helper.
    artifact = compile_contract(source_path)
    contract = Runar::SDK::RunarContract.new(artifact, [0])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    3.times do |i|
      txid, _state = contract.call(
        'commit', [], provider, wallet[:signer],
        Runar::SDK::CallOptions.new(new_state: { 'counter' => i + 1 })
      )
      expect(txid).to be_truthy, "commit ##{i + 1}: empty txid"
    end
  end

  it 'log() routes a data output through a private helper' do
    artifact = compile_contract(source_path)
    contract = Runar::SDK::RunarContract.new(artifact, [0])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # OP_RETURN-style payload (0x6a + 7-byte ASCII "hello!").
    payload = '6a0768656c6c6f21'
    txid, _state = contract.call(
      'log', [payload], provider, wallet[:signer],
    )
    expect(txid).to be_truthy
  end
end
