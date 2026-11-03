# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'

# N-038 — the Ruby SDK reproduces the cross-SDK SIGHASH_SINGLE stateful call
# vector (conformance/sdk-call/sighash-single-stateful.json).
#
# Under BIP-143 SINGLE the contract input commits hashOutputs to
# hash256(output[0]) only, so the input-0 unlocking bytes depend on the inputs
# and the continuation output, not on the change amount or fee policy. The
# SINGLE method's ABI declares no _changePKH / _changeAmount; the SDK must push
# none, still add a change output, and still track the new state.
#
# Proves: the Ruby SDK's call for the vector's inputs pushes byte-identical
# input-0 unlocking bytes to the TS reference (which
# conformance/sdk-call/sdk-call.test.ts replays through @bsv/sdk Spend: accept,
# and tampered output[0] reject), builds the same continuation output, keeps a
# change output, advances the state to count == 1, and the typed codegen treats
# the SINGLE method as non-terminal.
# Does not prove: script execution in this tier (Ruby has no ScriptVM); the
# on-chain verdict rests on the TS Spend replay of the identical bytes.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-038 — SIGHASH_SINGLE stateful call vector' do
  # rubocop:enable RSpec/DescribeClass
  N038_VECTOR = File.expand_path('../../../../conformance/sdk-call/sighash-single-stateful.json', __dir__)

  def n038_vector
    JSON.parse(File.read(N038_VECTOR))
  end

  def n038_utxo(h)
    Runar::SDK::Utxo.new(txid: h['txid'], output_index: h['outputIndex'], satoshis: h['satoshis'], script: h['script'])
  end

  # [unlocking scripts hex], [[satoshis, script hex]] of a raw tx.
  def n038_parse_tx(hex)
    b = [hex].pack('H*').bytes
    pos = 4
    varint = lambda do
      n = b[pos]
      pos += 1
      next n if n < 0xfd

      size = { 0xfd => 2, 0xfe => 4, 0xff => 8 }.fetch(n)
      v = b[pos, size].each_with_index.sum { |byte, i| byte << (8 * i) }
      pos += size
      v
    end
    unlocks = Array.new(varint.call) do
      pos += 36
      n = varint.call
      s = b[pos, n].pack('C*').unpack1('H*')
      pos += n + 4
      s
    end
    outs = Array.new(varint.call) do
      sats = b[pos, 8].each_with_index.sum { |byte, i| byte << (8 * i) }
      pos += 8
      n = varint.call
      s = b[pos, n].pack('C*').unpack1('H*')
      pos += n
      [sats, s]
    end
    [unlocks, outs]
  end

  it 'pushes the TS reference input-0 unlocking bytes, keeps the change output and tracks state' do
    v = n038_vector
    exp = v['expected']
    artifact = Runar::SDK::RunarArtifact.from_hash(v['artifact'])
    bump = artifact.abi.methods.find { |m| m.name == 'bump' }
    expect(bump.params.map(&:name)).to eq(exp['methodParams'])
    expect(exp['methodParams']).to eq(['txPreimage'])

    signer = Runar::SDK::LocalSigner.new(v['privKeyHex'])
    expect(signer.get_public_key).to eq(v['pubKeyHex'])
    provider = Runar::SDK::MockProvider.new(network: 'testnet')
    provider.add_utxo(signer.get_address, n038_utxo(v['fundingUtxo']))
    contract_utxo = n038_utxo(v['contractUtxo'])
    provider.add_contract_utxo(contract_utxo.script, contract_utxo)

    contract = Runar::SDK::RunarContract.from_utxo(artifact, contract_utxo)
    contract.call(v['method'], v['args'], provider, signer)
    unlocks, outs = n038_parse_tx(provider.get_broadcasted_txs.last)

    expect(unlocks[0]).to eq(exp['input0UnlockingHex'])
    expect(outs.length).to eq(exp['outputCount'])
    expect(outs[0]).to eq([exp['output0']['satoshis'], exp['output0']['scriptHex']])
    expect(outs[1][0]).to be > 0
    expect(contract.get_state['count']).to eq(Integer(exp['newCount']))
  end

  it 'typed codegen treats the SINGLE method (no _changePKH, no isTerminal) as non-terminal' do
    artifact = Runar::SDK::RunarArtifact.from_hash(n038_vector['artifact'])
    methods = artifact.abi.methods.to_h { |m| [m.name, m] }
    expect(methods['bump'].is_terminal).to be_nil
    expect(Runar::SDK::Codegen.send(:terminal_method?, methods['bump'], true)).to be(false)
    expect(Runar::SDK::Codegen.send(:terminal_method?, methods['reset'], true)).to be(false)
  end
end
