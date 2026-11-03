# frozen_string_literal: true

# F-245 — the typed wrapper Codegen.generate_ruby emits must not declare or
# forward the intent-intrinsic witness params (`_prevOutScript_<i>`,
# `_serialisedOutputs`). RunarContract#prepare_call supplies them from
# set_prev_out_script / set_serialised_outputs and excludes them from its
# arity check, so a wrapper that forwards them is rejected by arity.
#
# Proves: the generated wrapper, eval'd as-is, completes a deploy + stateful
# call through RunarContract#call on a MockProvider, passing only the user
# arg, with the witnesses set on the inner contract.
# Does not prove: on-chain validity of the spend (the artifact's script is a
# bare OP_TRUE; Ruby has no script interpreter to validate against).

require 'spec_helper'
require 'runar/sdk'

RSpec.describe 'F-245 — generated Ruby wrapper excludes intent witness params' do
  let(:mock_addr) { '00' * 20 }

  let(:artifact) do
    params = [
      { 'name' => 'amount', 'type' => 'bigint' },
      { 'name' => '_changePKH', 'type' => 'Ripemd160' },
      { 'name' => '_changeAmount', 'type' => 'bigint' },
      { 'name' => '_newAmount', 'type' => 'bigint' },
      { 'name' => 'txPreimage', 'type' => 'SigHashPreimage' },
      { 'name' => '_prevOutScript_0', 'type' => 'ByteString' },
      { 'name' => '_serialisedOutputs', 'type' => 'ByteString' },
    ]
    Runar::SDK::RunarArtifact.from_hash(
      'version' => 'runar-v0.1.0',
      'compilerVersion' => '0.1.0',
      'contractName' => 'F245IntentWitness',
      'script' => '51',
      'asm' => '',
      'abi' => {
        'constructor' => { 'params' => [{ 'name' => 'count', 'type' => 'bigint' }] },
        'methods' => [{ 'name' => 'advance', 'params' => params, 'isPublic' => true }],
      },
      'stateFields' => [{ 'name' => 'count', 'type' => 'bigint', 'index' => 0 }],
      'codeSeparatorIndex' => 0,
      'buildTimestamp' => '2026-05-18T00:00:00.000Z',
    )
  end

  it 'calls through the generated wrapper with only the user arg' do
    source = Runar::SDK::Codegen.generate_ruby(artifact)
    expect(source).not_to include('prev_out_script')
    expect(source).not_to include('serialised_outputs')

    eval(source, TOPLEVEL_BINDING) # rubocop:disable Security/Eval
    wrapper = Runar::Contracts::F245IntentWitnessContract.new(artifact, count: 0)

    signer = Runar::SDK::MockSigner.new(pub_key_hex: '02' + ('00' * 32), address: mock_addr)
    provider = Runar::SDK::MockProvider.new
    [['aa' * 32, 0], ['bb' * 32, 1]].each do |txid, idx|
      provider.add_utxo(mock_addr, Runar::SDK::Utxo.new(
        txid: txid, output_index: idx, satoshis: 100_000,
        script: '76a914' + ('00' * 20) + '88ac'
      ))
    end
    wrapper.connect(provider, signer)
    wrapper.deploy(options: Runar::SDK::DeployOptions.new(satoshis: 50_000))

    wrapper.contract.set_prev_out_script(0, 'aa')
    wrapper.contract.set_serialised_outputs('cc')

    opts = Runar::Contracts::F245IntentWitnessStatefulCallOptions.new(new_state: { 'count' => 1 })
    wrapper.advance(amount: 123, options: opts)
    expect(wrapper.contract.get_state['count']).to eq(1)
  end
end
