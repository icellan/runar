# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# F-247 (CL-BUG-136, MEDIUM/P2): +finalize_call+ broadcasts a 72-byte
# all-zero placeholder when a declared +sig_indices+ slot is left unfilled.
#
# +prepare_call+ stubs every auto-signed +Sig+ param with a 72-zero-byte
# placeholder and records its arg index in +sig_indices+. +finalize_call+
# only overwrote +resolved_args[idx]+ for the indices actually present in
# the caller-supplied +signatures+ hash — nothing checked that every entry
# in +prepared.sig_indices+ was covered before the primary unlocking script
# was assembled and handed to +provider.broadcast+. Ported from the TS fix
# (+contract.ts+'s finalizeCall).
#
# This spec deliberately avoids MockProvider's always-ack constructor /
# validation toggle (which would need an +always_ack_allowlist.json+ entry,
# and the default validating MockProvider would mask the bug by rejecting
# the placeholder-signed broadcast for the WRONG reason — script invalidity
# caught AT broadcast time — rather than showing whether finalize_call
# refuses BEFORE calling provider.broadcast at all). Instead it hand-rolls a
# minimal Provider subclass whose +broadcast+ acks anything, like a real
# network node that does not pre-validate scripts. Mirrors the synthetic
# (non-compiled) artifact pattern used by c19_prepared_sighash_spec.rb.
SIGNER_KEY_F247 = (('00' * 31) + '0b').freeze

# Delegates every read to an underlying MockProvider but broadcast acks
# unconditionally — no script validation.
class F247AckAnythingProvider < Runar::SDK::Provider
  attr_reader :broadcasted_txs

  def initialize(inner)
    super()
    @inner = inner
    @broadcasted_txs = []
  end

  def get_transaction(txid)
    @inner.get_transaction(txid)
  end

  def get_raw_transaction(txid)
    @inner.get_raw_transaction(txid)
  end

  def broadcast(raw_tx)
    @broadcasted_txs << raw_tx
    format('%064x', @broadcasted_txs.length)
  end

  def get_utxos(address)
    @inner.get_utxos(address)
  end

  def get_contract_utxo(script_hash)
    @inner.get_contract_utxo(script_hash)
  end

  def get_network
    @inner.get_network
  end

  def get_fee_rate
    @inner.get_fee_rate
  end
end

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'F-247 — finalize_call must refuse a missing sig_indices slot' do
  # rubocop:enable RSpec/DescribeClass
  def artifact
    Runar::SDK::RunarArtifact.from_hash(
      'version' => 'runar-v0.1.0',
      'contractName' => 'F247SigCheck',
      'script' => '51',
      'abi' => {
        'constructor' => { 'params' => [] },
        'methods' => [{
          'name' => 'unlock',
          'isPublic' => true,
          'params' => [
            { 'name' => 'sig', 'type' => 'Sig' }
          ]
        }]
      }
    )
  end

  def deploy
    signer = Runar::SDK::LocalSigner.new(SIGNER_KEY_F247)
    mock = Runar::SDK::MockProvider.new(network: 'testnet')
    script = Runar::SDK.build_p2pkh_script(signer.get_address)
    mock.add_utxo(signer.get_address, Runar::SDK::Utxo.new(
                                         txid: 'ee' * 32, output_index: 0,
                                         satoshis: 500_000, script: script
                                       ))
    provider = F247AckAnythingProvider.new(mock)
    contract = Runar::SDK::RunarContract.new(artifact, [])
    contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 50_000))
    [contract, provider, signer]
  end

  it 'refuses instead of broadcasting when the one declared sig slot is left unfilled' do
    contract, provider, signer = deploy
    prepared = contract.prepare_call('unlock', [nil], provider, signer)
    expect(prepared.sig_indices).to eq([0])

    broadcast_count_before = provider.broadcasted_txs.length

    # Caller forgets the one declared signature slot entirely.
    expect do
      contract.finalize_call(prepared, {}, provider)
    end.to raise_error(/sig/i)

    expect(provider.broadcasted_txs.length).to eq(broadcast_count_before)
  end
end
