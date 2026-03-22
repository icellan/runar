# frozen_string_literal: true

# P2PKH integration test -- stateless contract with checkSig.
#
# P2PKH locks funds to a public key hash. Spending requires a valid signature
# and the matching public key. The SDK auto-computes Sig params when nil is passed.

require 'spec_helper'

RSpec.describe 'P2PKH' do # rubocop:disable RSpec/DescribeClass
  it 'compiles and deploys with a valid pubKeyHash' do
    artifact = compile_contract('examples/ts/p2pkh/P2PKH.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('P2PKH')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash]])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys and spends with unlock(sig, pubKey) — Sig auto-computed' do
    artifact = compile_contract('examples/ts/p2pkh/P2PKH.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash]])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # nil Sig and PubKey args are auto-computed by the SDK
    call_txid, _count = contract.call('unlock', [nil, nil], provider, wallet[:signer])
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'deploys with a different wallet pubKeyHash as the lock target' do
    artifact = compile_contract('examples/ts/p2pkh/P2PKH.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)
    other    = create_wallet

    contract = Runar::SDK::RunarContract.new(artifact, [other[:pub_key_hash]])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'rejects unlock with wrong signer' do
    artifact = compile_contract('examples/ts/p2pkh/P2PKH.runar.ts')

    provider = create_provider
    wallet_a = create_funded_wallet(provider)
    wallet_b = create_funded_wallet(provider)

    # Lock to wallet_a's pubKeyHash
    contract = Runar::SDK::RunarContract.new(artifact, [wallet_a[:pub_key_hash]])
    contract.deploy(provider, wallet_a[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # Try to unlock with wallet_b's signer
    expect do
      contract.call('unlock', [nil, nil], provider, wallet_b[:signer])
    end.to raise_error(StandardError)
  end
end
