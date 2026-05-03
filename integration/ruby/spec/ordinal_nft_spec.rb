# frozen_string_literal: true

# OrdinalNFT integration spec — exercises the 1Sat ordinal NFT contract
# end-to-end on regtest. Ported from integration/ts/ordinal-nft.test.ts.
#
# The OrdinalNFT contract is a P2PKH-style locking script wrapping a
# 1Sat ordinal inscription. The spec verifies the locked UTXO is
# spendable by the holder of the matching pubkey.

require 'spec_helper'

RSpec.describe 'OrdinalNFT' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the OrdinalNFT contract' do
    artifact = compile_contract('examples/ts/ordinal-nft/OrdinalNFT.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('OrdinalNFT')
    expect(artifact.script.length).to be > 0
  end

  it 'deploys with a pubKeyHash' do
    artifact = compile_contract('examples/ts/ordinal-nft/OrdinalNFT.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash]])
    # 1Sat ordinals are typically locked to a single satoshi.
    txid, _count = contract.deploy(
      provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 1)
    )
    expect(txid).to be_truthy
    expect(txid.length).to eq(64)
  end

  it 'deploys and transfers via unlock(sig, pubKey)' do
    artifact = compile_contract('examples/ts/ordinal-nft/OrdinalNFT.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash]])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 1))

    call_txid, _ = contract.call('unlock', [nil, nil], provider, wallet[:signer])
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end
end
