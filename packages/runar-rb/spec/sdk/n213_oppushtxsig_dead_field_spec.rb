# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'runar/ecdsa'
require 'digest'

# N-213 — the Ruby half of "remove the dead PreparedCall.opPushTxSig field
# (and its wasted ECDSA sign per stateful call) from
# Go/Rust/Python/Ruby/Zig SDKs, as F-369 did for TS".
#
# Since BUG-100 the unlocking script carries no spender-supplied OP_PUSH_TX
# signature: +RunarContract#build_stateful_prefix+'s first parameter is
# accepted for call-site compatibility but ignored (see its leading
# <tt>_ = op_sig_hex</tt> discard). +op_push_tx_sig+ was documented public
# surface on +PreparedCall+ that backed nothing a caller could use.
#
# +PreparedCall+ is a keyword-init +Struct+, so field absence is checked via
# +Struct#members+ (and +respond_to?+ on a live instance) — the Ruby analogue
# of the Go sibling test's JSON-key check and the TS reference test's
# +'opPushTxSig' in prepared+.
#
# Reuses the minimal hand-built SigCounter artifact fixture from
# c19_prepared_sighash_spec.rb (script '51' / OP_TRUE — enough structure to
# exercise prepare_call/finalize_call's codepaths without a real compiler).
#
# This spec does not prove anything about the other four SDKs in scope for
# N-213 (Go/Rust/Python/Zig — each gets its own language-appropriate
# field-absence test) or a real on-chain broadcast.
SIGNER_KEY_N213 = (('00' * 31) + '03').freeze

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-213 — PreparedCall has no op_push_tx_sig field' do
  # rubocop:enable RSpec/DescribeClass
  def artifact
    Runar::SDK::RunarArtifact.from_hash(
      'version' => 'runar-v0.1.0',
      'contractName' => 'SigCounter',
      'script' => '51',
      'stateFields' => [{ 'name' => 'count', 'type' => 'bigint', 'index' => 0 }],
      'codeSeparatorIndex' => 0,
      'abi' => {
        'constructor' => { 'params' => [{ 'name' => 'count', 'type' => 'bigint' }] },
        'methods' => [{
          'name' => 'inc',
          'isPublic' => true,
          'params' => [
            { 'name' => 'sig', 'type' => 'Sig' },
            { 'name' => '_changePKH', 'type' => 'Ripemd160' },
            { 'name' => '_changeAmount', 'type' => 'bigint' },
            { 'name' => 'txPreimage', 'type' => 'SigHashPreimage' }
          ]
        }]
      }
    )
  end

  def deploy
    signer   = Runar::SDK::LocalSigner.new(SIGNER_KEY_N213)
    provider = Runar::SDK::MockProvider.new(network: 'testnet')
    script   = Runar::SDK.build_p2pkh_script(signer.get_address)
    provider.add_utxo(signer.get_address, Runar::SDK::Utxo.new(
                                            txid: 'aa' * 32, output_index: 0,
                                            satoshis: 500_000, script: script
                                          ))
    contract = Runar::SDK::RunarContract.new(artifact, [0])
    contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 50_000))
    provider.add_utxo(signer.get_address, Runar::SDK::Utxo.new(
                                            txid: 'bb' * 32, output_index: 1,
                                            satoshis: 500_000, script: script
                                          ))
    [contract, provider, signer]
  end

  def sha256d(bytes)
    Digest::SHA256.digest(Digest::SHA256.digest(bytes))
  end

  it 'PreparedCall declares no op_push_tx_sig member' do
    expect(Runar::SDK::PreparedCall.members).not_to include(:op_push_tx_sig)
  end

  it 'a live PreparedCall instance does not respond to op_push_tx_sig' do
    contract, provider, signer = deploy
    prepared = contract.prepare_call('inc', [nil], provider, signer)

    expect(prepared.respond_to?(:op_push_tx_sig)).to be false
  end

  it 'the external sign_hash wallet flow still works end-to-end without the field' do
    contract, provider, signer = deploy
    prepared = contract.prepare_call('inc', [nil], provider, signer)

    expect(prepared.sig_indices).to eq([0])

    # Exactly what WalletSigner#sign_hash does: ECDSA-sign the handed-over
    # 32 bytes, no further hashing.
    sig = Runar::ECDSA.ecdsa_sign(SIGNER_KEY_N213.to_i(16), [prepared.sighash].pack('H*'))

    real_digest = sha256d([prepared.preimage].pack('H*'))
    pubkey      = [signer.get_public_key].pack('H*')
    expect(Runar::ECDSA.ecdsa_verify(sig, pubkey, real_digest)).to be true

    sig_hex = "#{sig.unpack1('H*')}41" # ALL | FORKID
    contract.finalize_call(prepared, { 0 => sig_hex }, provider)

    txs = provider.get_broadcasted_txs
    expect(txs.length).to eq(2) # deploy + call
    expect(txs[1]).to include(sig_hex)
  end
end
