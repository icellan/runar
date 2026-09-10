# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'runar/ecdsa'
require 'digest'

# Deep-review finding C19 (P1) — +PreparedCall#sighash+ must be the true
# BIP-143 digest +hash256(preimage)+ = +sha256(sha256(preimage))+, NOT the
# intermediate +sha256(preimage)+.
#
# +PreparedCall#sighash+ is handed to an EXTERNAL signer — a BRC-100-style
# +WalletSigner#sign_hash(digest)+ wallet (see lib/runar/sdk/wallet.rb, which
# forwards it as +hash_to_sign:+) or a hardware device — that ECDSA-signs those
# 32 bytes DIRECTLY, with no further hashing. Storing the single-hashed value
# makes such a wallet sign the wrong message and the node's real +OP_CHECKSIG+
# rejects the spend.
#
# The default +call+ path hides the bug: it never reads +PreparedCall#sighash+.
# It re-derives the digest inside +LocalSigner#sign+ (BIP143.bip143_sighash ->
# double SHA-256), which is correct by construction. Only the documented
# multi-signer +prepare_call+ / +finalize_call+ path is affected.
#
# C19 was fixed in the TS, Go, Rust, Python, Zig and Java tiers; the Ruby tier
# was missed. Ported from the TS reference fix
# (+computeBip143Sighash+ in packages/runar-sdk/src/contract.ts).
#
SIGNER_KEY_C19 = (('00' * 31) + '03').freeze

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'C19 — PreparedCall#sighash is the double-SHA256 BIP-143 digest' do
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
    signer   = Runar::SDK::LocalSigner.new(SIGNER_KEY_C19)
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

  let(:prepared) do
    contract, provider, signer = deploy
    @signer = signer
    contract.prepare_call('inc', [nil], provider, signer)
  end

  it 'stores hash256(preimage), never the intermediate sha256(preimage)' do
    expect(prepared.preimage).not_to be_empty

    preimage     = [prepared.preimage].pack('H*')
    want         = sha256d(preimage).unpack1('H*')
    wrong_single = Digest::SHA256.hexdigest(preimage)

    expect(prepared.sighash).not_to eq(wrong_single)
    expect(prepared.sighash).to eq(want)
  end

  it 'an external sign_hash wallet signing it directly produces a signature OP_CHECKSIG accepts' do
    # Exactly what WalletSigner#sign_hash does: ECDSA-sign the handed-over
    # 32 bytes, no further hashing.
    sig = Runar::ECDSA.ecdsa_sign(SIGNER_KEY_C19.to_i(16), [prepared.sighash].pack('H*'))

    # Exactly what the node's OP_CHECKSIG verifies against: the real BIP-143
    # digest of the spending input, hash256(preimage).
    real_digest = sha256d([prepared.preimage].pack('H*'))
    pubkey      = [@signer.get_public_key].pack('H*')

    expect(Runar::ECDSA.ecdsa_verify(sig, pubkey, real_digest)).to be true
  end
end
