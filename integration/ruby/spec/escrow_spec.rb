# frozen_string_literal: true

# Escrow integration test -- stateless contract with dual-signature checkSig.
#
# Escrow locks funds and allows release or refund via two methods, each
# requiring signatures from two parties (dual-sig):
#   - release(sellerSig, arbiterSig) -- seller + arbiter must both sign
#   - refund(buyerSig, arbiterSig)   -- buyer + arbiter must both sign
#
# The SDK auto-computes Sig params when nil is passed. We use the same key
# for both required roles so both auto-computed signatures match.

require 'spec_helper'

RSpec.describe 'Escrow' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the Escrow contract' do
    artifact = compile_contract('examples/ts/escrow/Escrow.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('Escrow')
  end

  it 'deploys with three distinct pubkeys (buyer, seller, arbiter)' do
    artifact = compile_contract('examples/ts/escrow/Escrow.runar.ts')

    provider = create_provider
    buyer    = create_wallet
    seller   = create_wallet
    arbiter  = create_wallet
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      buyer[:pub_key_hex],
      seller[:pub_key_hex],
      arbiter[:pub_key_hex]
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys with the same key as both buyer and arbiter' do
    artifact = compile_contract('examples/ts/escrow/Escrow.runar.ts')

    provider           = create_provider
    buyer_and_arbiter  = create_wallet
    seller             = create_wallet
    wallet             = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      buyer_and_arbiter[:pub_key_hex],
      seller[:pub_key_hex],
      buyer_and_arbiter[:pub_key_hex]
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'deploys and spends via release(sellerSig, arbiterSig) with auto-computed Sigs' do
    artifact = compile_contract('examples/ts/escrow/Escrow.runar.ts')

    provider      = create_provider
    buyer         = create_wallet
    # Signer is both seller and arbiter
    signer_wallet = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      buyer[:pub_key_hex],
      signer_wallet[:pub_key_hex],
      signer_wallet[:pub_key_hex]
    ])

    contract.deploy(provider, signer_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # release(sellerSig=nil, arbiterSig=nil) — both auto-computed from signer
    call_txid, _count = contract.call('release', [nil, nil], provider, signer_wallet[:signer])
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'deploys and spends via refund(buyerSig, arbiterSig) with auto-computed Sigs' do
    artifact = compile_contract('examples/ts/escrow/Escrow.runar.ts')

    provider      = create_provider
    seller        = create_wallet
    # Signer is both buyer and arbiter
    signer_wallet = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      signer_wallet[:pub_key_hex],
      seller[:pub_key_hex],
      signer_wallet[:pub_key_hex]
    ])

    contract.deploy(provider, signer_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # refund(buyerSig=nil, arbiterSig=nil)
    call_txid, _count = contract.call('refund', [nil, nil], provider, signer_wallet[:signer])
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects release with wrong signer (checkSig fails)' do
    artifact = compile_contract('examples/ts/escrow/Escrow.runar.ts')

    provider = create_provider
    buyer    = create_wallet
    # Deploy with seller=arbiter=wallet_a
    wallet_a = create_funded_wallet(provider)
    wallet_b = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      buyer[:pub_key_hex],
      wallet_a[:pub_key_hex],
      wallet_a[:pub_key_hex]
    ])

    contract.deploy(provider, wallet_a[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call('release', [nil, nil], provider, wallet_b[:signer])
    end.to raise_error(StandardError)
  end

  it 'rejects refund with wrong signer (checkSig fails)' do
    artifact = compile_contract('examples/ts/escrow/Escrow.runar.ts')

    provider = create_provider
    seller   = create_wallet
    # Deploy with buyer=arbiter=wallet_a
    wallet_a = create_funded_wallet(provider)
    wallet_b = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      wallet_a[:pub_key_hex],
      seller[:pub_key_hex],
      wallet_a[:pub_key_hex]
    ])

    contract.deploy(provider, wallet_a[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call('refund', [nil, nil], provider, wallet_b[:signer])
    end.to raise_error(StandardError)
  end
end
