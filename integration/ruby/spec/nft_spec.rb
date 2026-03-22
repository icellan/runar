# frozen_string_literal: true

# SimpleNFT integration test -- stateful contract with addOutput.
#
# SimpleNFT is a StatefulSmartContract with properties:
#   - owner:    PubKey (mutable)
#   - tokenId:  ByteString (readonly)
#   - metadata: ByteString (readonly)
#
# The SDK auto-computes Sig params when nil is passed.

require 'spec_helper'

RSpec.describe 'SimpleNFT' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the SimpleNFT contract' do
    artifact = compile_contract('examples/ts/token-nft/NFTExample.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('SimpleNFT')
  end

  it 'deploys with owner, tokenId, and metadata' do
    artifact = compile_contract('examples/ts/token-nft/NFTExample.runar.ts')

    provider     = create_provider
    owner        = create_wallet
    wallet       = create_funded_wallet(provider)
    token_id_hex = 'NFT-001'.unpack1('H*')
    metadata_hex = 'My First NFT'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex],
      token_id_hex,
      metadata_hex
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys two NFTs with different owners and produces distinct txids' do
    artifact = compile_contract('examples/ts/token-nft/NFTExample.runar.ts')

    provider     = create_provider
    owner1       = create_wallet
    owner2       = create_wallet
    wallet       = create_funded_wallet(provider)
    token_id_hex = 'NFT-MULTI'.unpack1('H*')
    metadata_hex = 'Unique Art Piece'.unpack1('H*')

    contract1 = Runar::SDK::RunarContract.new(artifact, [
      owner1[:pub_key_hex], token_id_hex, metadata_hex
    ])
    txid1, _count = contract1.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid1).to be_truthy

    contract2 = Runar::SDK::RunarContract.new(artifact, [
      owner2[:pub_key_hex], token_id_hex, metadata_hex
    ])
    txid2, _count = contract2.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid2).to be_truthy

    expect(txid1).not_to eq(txid2)
  end

  it 'deploys with 256 bytes of metadata' do
    artifact = compile_contract('examples/ts/token-nft/NFTExample.runar.ts')

    provider     = create_provider
    owner        = create_wallet
    wallet       = create_funded_wallet(provider)
    token_id_hex = 'NFT-LONG-META'.unpack1('H*')
    metadata_hex = ('A' * 256).unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex], token_id_hex, metadata_hex
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'deploys and transfers NFT to a new owner' do
    artifact = compile_contract('examples/ts/token-nft/NFTExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    new_owner    = create_wallet
    token_id_hex = 'NFT-XFER'.unpack1('H*')
    metadata_hex = 'Transfer Test'.unpack1('H*')

    # Owner is the funded signer
    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex],
      token_id_hex,
      metadata_hex
    ])

    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # transfer: sig=nil (auto), newOwner, outputSatoshis
    # transfer uses addOutput, so we need outputs (not new_state)
    call_txid, _count = contract.call(
      'transfer',
      [nil, new_owner[:pub_key_hex], 4500],
      provider, owner_wallet[:signer],
      Runar::SDK::CallOptions.new(outputs: [
        { 'satoshis' => 4500, 'state' => {
          'owner' => new_owner[:pub_key_hex],
          'tokenId' => token_id_hex,
          'metadata' => metadata_hex
        } }
      ])
    )
    expect(call_txid).to be_truthy
  end

  it 'deploys and burns an NFT' do
    artifact = compile_contract('examples/ts/token-nft/NFTExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    token_id_hex = 'NFT-BURN'.unpack1('H*')
    metadata_hex = 'Burn Test'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex],
      token_id_hex,
      metadata_hex
    ])

    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # burn: sig=nil (auto), no state continuation
    call_txid, _count = contract.call('burn', [nil], provider, owner_wallet[:signer])
    expect(call_txid).to be_truthy
  end

  it 'rejects transfer with wrong signer (not the owner)' do
    artifact = compile_contract('examples/ts/token-nft/NFTExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    wrong_wallet = create_funded_wallet(provider)
    new_owner    = create_wallet
    token_id_hex = 'NFT-REJECT'.unpack1('H*')
    metadata_hex = 'Reject Test'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex],
      token_id_hex,
      metadata_hex
    ])

    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call(
        'transfer',
        [nil, new_owner[:pub_key_hex], 5000],
        provider, wrong_wallet[:signer],
        Runar::SDK::CallOptions.new(new_state: { 'owner' => new_owner[:pub_key_hex] })
      )
    end.to raise_error(StandardError)
  end
end
