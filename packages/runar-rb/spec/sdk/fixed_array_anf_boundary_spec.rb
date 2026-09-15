# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# FixedArray state across the ANF-interpreter boundary (call path).
#
# Pass +03b-expand-fixed-arrays+ runs BEFORE ANF lowering, so the ANF program has
# no property called +table+ at all — it has +table__0+..+table__3+, and every
# +load_prop+ / +update_prop+ in the method body names one of those. The SDK's
# user-facing +@state+, by contrast, is keyed by the GROUPED name. Both directions
# of that boundary have to be bridged or the continuation output commits a state
# the method did not compute.
#
# The sharp probe is the RECONNECT path: +from_utxo+ sets +@state+ to exactly what
# +extract_state_from_script+ decodes, which for a FixedArray field is the grouped
# entry and nothing else — no synthetic leaves to mask an unbridged inbound
# boundary. Because +@table[i] += 1+ at a runtime index lowers to a per-leaf
# select, an absent property makes the interpreter fall back to each leaf's ANF
# +initialValue+ and rewrite ALL FOUR leaves from it, so the continuation commits
# the deploy-time array and the covenant's hashOutputs binding rejects the spend.
#
# Fixture: +examples/ruby/fixed-array-write/ArrayWrite.runar.rb+ —
# +table: FixedArray<bigint, 4> = [0,0,0,0]+, +bump(i)+ doing +@table[i] += 1+.
# Checked in at +spec/fixtures/arraywrite-artifact.json+, compiled with +--ir+ so
# the artifact carries the ANF the call path needs.
#
# Every example runs on the DEFAULT validating MockProvider with a real
# LocalSigner. The Ruby tier ships no Script VM (root CLAUDE.md, "Off-chain Script
# VM"), so the load-bearing assertion is the continuation BYTES: the 32-byte state
# section the next spend is bound to.
#
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'FixedArray state across the ANF-interpreter boundary' do
  # rubocop:enable RSpec/DescribeClass

  DEPLOYER_KEY = "#{'00' * 31}07"

  def load_artifact
    path = File.expand_path('../fixtures/arraywrite-artifact.json', __dir__)
    artifact = Runar::SDK::RunarArtifact.from_json(File.read(path))
    # Without ANF the call path never reaches the interpreter and this whole
    # file would be vacuous.
    raise 'ArrayWrite artifact carries no ANF' if artifact.anf.nil?

    artifact
  end

  # Little-endian 8-byte words, one per leaf — the contract's state bytes.
  def le_hex(*vals)
    vals.map { |v| [v].pack('q<').unpack1('H*') }.join
  end

  # The 32-byte state section after the final OP_RETURN of a locking script.
  def state_tail_hex(script_hex)
    nibbles = 4 * 8 * 2
    expect(script_hex.length).to be > nibbles + 2
    sep = script_hex[-(nibbles + 2), 2]
    expect(sep).to eq('6a')
    script_hex[-nibbles, nibbles]
  end

  def grouped_table(state)
    raw = state['table']
    expect(raw).to be_a(Array), "state has no grouped `table` array: #{raw.inspect}"
    raw.map { |v| v.is_a?(String) ? v.delete_suffix('n').to_i : v.to_i }
  end

  def deploy_array_write
    signer   = Runar::SDK::LocalSigner.new(DEPLOYER_KEY)
    provider = Runar::SDK::MockProvider.new
    provider.add_utxo(
      signer.get_address,
      Runar::SDK::Utxo.new(
        txid: 'aa' * 32, output_index: 0, satoshis: 1_000_000,
        script: Runar::SDK.build_p2pkh_script(signer.get_address)
      )
    )
    contract = Runar::SDK::RunarContract.new(load_artifact, [])
    contract.connect(provider, signer)
    contract.deploy(nil, nil, Runar::SDK::DeployOptions.new(satoshis: 50_000))
    [contract, provider, signer]
  end

  it 'OUTBOUND: the continuation and the grouped entry both carry the computed state' do
    contract, = deploy_array_write

    expect(state_tail_hex(contract.get_utxo.script)).to eq(le_hex(0, 0, 0, 0))

    contract.call('bump', [0])

    expect(state_tail_hex(contract.get_utxo.script)).to eq(le_hex(1, 0, 0, 0))
    expect(grouped_table(contract.get_state)).to eq([1, 0, 0, 0])
  end

  it 'INBOUND: repeated bumps of one slot accumulate' do
    contract, = deploy_array_write

    (1..3).each do |n|
      contract.call('bump', [0])
      expect(state_tail_hex(contract.get_utxo.script)).to eq(le_hex(n, 0, 0, 0))
      expect(grouped_table(contract.get_state)).to eq([n, 0, 0, 0])
    end
  end

  it 'INBOUND: a contract reconnected with from_utxo commits the restored state' do
    contract, provider, signer = deploy_array_write

    # Real on-chain history: table -> [0,2,0,0].
    contract.call('bump', [1])
    contract.call('bump', [1])
    on_chain = contract.get_utxo
    expect(state_tail_hex(on_chain.script)).to eq(le_hex(0, 2, 0, 0))

    # A fresh process that only ever sees the deployed script.
    restored = Runar::SDK::RunarContract.from_utxo(load_artifact, on_chain)
    expect(restored.get_state).not_to have_key('table__1')
    expect(grouped_table(restored.get_state)).to eq([0, 2, 0, 0])

    restored.connect(provider, signer)
    restored.call('bump', [1])

    expect(state_tail_hex(restored.get_utxo.script)).to eq(le_hex(0, 3, 0, 0))
    expect(grouped_table(restored.get_state)).to eq([0, 3, 0, 0])
  end
end
