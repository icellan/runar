# frozen_string_literal: true

# CovenantVault integration test -- stateless contract with checkSig + checkPreimage.
#
# CovenantVault demonstrates a covenant pattern: it constrains HOW funds can be
# spent, not just WHO can spend them. The contract checks:
#   1. The owner's ECDSA signature (authentication via checkSig)
#   2. The transaction preimage (via checkPreimage / OP_PUSH_TX)
#   3. That transaction outputs match the expected P2PKH script to the recipient
#      with amount >= minAmount (enforced by comparing hash256(expectedOutput)
#      against extractOutputHash(txPreimage))
#
# Constructor
#   - owner:     PubKey -- the ECDSA public key that must sign to spend
#   - recipient: Addr   -- the hash160 of the authorised recipient's public key
#   - minAmount: bigint -- minimum satoshis that must be sent to the recipient
#
# Method: spend(sig: Sig, txPreimage: SigHashPreimage)
#   The compiler inserts an implicit _opPushTxSig parameter before the declared params.
#   The full unlocking script order is: <opPushTxSig> <sig> <txPreimage>
#
# Spending Limitation
#   Covenant spending requires constructing a transaction whose outputs exactly match
#   what the contract expects. The SDK's generic call() creates default outputs that
#   don't match. For real applications, developers use the SDK's raw transaction builder.

require 'spec_helper'

RSpec.describe 'CovenantVault' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the CovenantVault contract' do
    artifact = compile_contract('examples/ts/covenant-vault/CovenantVault.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('CovenantVault')
  end

  it 'deploys with owner, recipient, and minAmount' do
    artifact = compile_contract('examples/ts/covenant-vault/CovenantVault.runar.ts')

    provider  = create_provider
    owner     = create_wallet
    recipient = create_wallet
    wallet    = create_funded_wallet(provider)

    # Constructor: (owner: PubKey, recipient: Addr, minAmount: bigint)
    # Addr is a pubKeyHash (20-byte hash160)
    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex],
      recipient[:pub_key_hash],
      1000
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys with zero minAmount' do
    artifact = compile_contract('examples/ts/covenant-vault/CovenantVault.runar.ts')

    provider  = create_provider
    owner     = create_wallet
    recipient = create_wallet
    wallet    = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex],
      recipient[:pub_key_hash],
      0
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'deploys with large minAmount (1 BTC in satoshis)' do
    artifact = compile_contract('examples/ts/covenant-vault/CovenantVault.runar.ts')

    provider  = create_provider
    owner     = create_wallet
    recipient = create_wallet
    wallet    = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex],
      recipient[:pub_key_hash],
      100_000_000
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'deploys with the same key as owner and recipient' do
    artifact = compile_contract('examples/ts/covenant-vault/CovenantVault.runar.ts')

    provider = create_provider
    both     = create_wallet
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      both[:pub_key_hex],
      both[:pub_key_hash],
      500
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'rejects spend with wrong signer (checkSig fails before covenant check)' do
    artifact = compile_contract('examples/ts/covenant-vault/CovenantVault.runar.ts')

    provider      = create_provider
    recipient     = create_wallet
    # Deploy with owner=owner_wallet
    owner_wallet  = create_funded_wallet(provider)
    wrong_wallet  = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex],
      recipient[:pub_key_hash],
      1000
    ])

    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # Call spend with wrong_wallet -- checkSig will fail on-chain
    expect do
      contract.call('spend', [nil, nil], provider, wrong_wallet[:signer])
    end.to raise_error(StandardError)
  end
end
