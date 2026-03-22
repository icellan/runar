# frozen_string_literal: true

# FunctionPatterns integration test -- stateful contract demonstrating private
# methods, built-in functions, and method composition.
#
# FunctionPatterns is a StatefulSmartContract with properties:
#   - owner:   PubKey (readonly)
#   - balance: bigint (mutable)
#
# The SDK auto-computes Sig params when nil is passed.

require 'spec_helper'

RSpec.describe 'FunctionPatterns' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the FunctionPatterns contract' do
    artifact = compile_contract('examples/ts/function-patterns/FunctionPatterns.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('FunctionPatterns')
  end

  it 'deploys with owner and initial balance of 1000' do
    artifact = compile_contract('examples/ts/function-patterns/FunctionPatterns.runar.ts')

    provider = create_provider
    owner    = create_wallet
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex],
      1000
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys with zero initial balance' do
    artifact = compile_contract('examples/ts/function-patterns/FunctionPatterns.runar.ts')

    provider = create_provider
    owner    = create_wallet
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex],
      0
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))
    expect(txid).to be_truthy
  end

  it 'deploys with a large initial balance' do
    artifact = compile_contract('examples/ts/function-patterns/FunctionPatterns.runar.ts')

    provider = create_provider
    owner    = create_wallet
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex],
      999_999_999
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))
    expect(txid).to be_truthy
  end

  it 'produces distinct txids for two instances with different owners' do
    artifact = compile_contract('examples/ts/function-patterns/FunctionPatterns.runar.ts')

    provider = create_provider
    owner1   = create_wallet
    owner2   = create_wallet
    wallet   = create_funded_wallet(provider)

    contract1 = Runar::SDK::RunarContract.new(artifact, [owner1[:pub_key_hex], 100])
    txid1, _count = contract1.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))

    contract2 = Runar::SDK::RunarContract.new(artifact, [owner2[:pub_key_hex], 200])
    txid2, _count = contract2.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))

    expect(txid1).to be_truthy
    expect(txid2).to be_truthy
    expect(txid1).not_to eq(txid2)
  end

  it 'deploys and deposits funds with auto-computed Sig' do
    artifact = compile_contract('examples/ts/function-patterns/FunctionPatterns.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)

    # Owner is the funded signer
    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex],
      100
    ])

    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))

    # deposit: sig=nil (auto), amount=50
    call_txid, _count = contract.call(
      'deposit',
      [nil, 50],
      provider, owner_wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'balance' => 150 })
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'chains deposit then withdraw' do
    artifact = compile_contract('examples/ts/function-patterns/FunctionPatterns.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex],
      1000
    ])

    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))

    # deposit(sig=nil, amount=500) -> balance = 1500
    contract.call(
      'deposit',
      [nil, 500],
      provider, owner_wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'balance' => 1500 })
    )

    # withdraw(sig=nil, amount=200, feeBps=100) -> fee=2, balance=1298
    contract.call(
      'withdraw',
      [nil, 200, 100],
      provider, owner_wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'balance' => 1298 })
    )
  end

  it 'rejects deposit with wrong signer (not the owner)' do
    artifact = compile_contract('examples/ts/function-patterns/FunctionPatterns.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    wrong_wallet = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex],
      100
    ])

    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))

    expect do
      contract.call(
        'deposit',
        [nil, 50],
        provider, wrong_wallet[:signer],
        Runar::SDK::CallOptions.new(new_state: { 'balance' => 150 })
      )
    end.to raise_error(StandardError)
  end
end
