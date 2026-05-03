# frozen_string_literal: true

# P256Wallet integration spec — Hybrid ECDSA + NIST P-256 contract.
#
# Ported from integration/ts/p256-wallet.test.ts. The full spend path
# requires raw-transaction construction with both an ECDSA signature
# and a P-256 signature; this spec covers the compile-and-deploy half
# so a regression in the P-256 codegen module is caught at the SDK
# level.

require 'spec_helper'

RSpec.describe 'P256Wallet' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the P256Wallet contract' do
    artifact = compile_contract('examples/ts/p256-wallet/P256Wallet.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('P256Wallet')
    expect(artifact.script.length).to be > 0
  end

  it 'has a hybrid ECDSA+P-256 verification script in the expected size band' do
    artifact     = compile_contract('examples/ts/p256-wallet/P256Wallet.runar.ts')
    script_bytes = artifact.script.length / 2
    expect(script_bytes).to be > 1_000
    expect(script_bytes).to be < 200_000
  end

  it 'deploys with ECDSA pubkey hash + P-256 pubkey hash' do
    artifact = compile_contract('examples/ts/p256-wallet/P256Wallet.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    # 20-byte hash placeholder — the regtest node only validates the
    # locking script bytes, not the P-256 signature, until a spend.
    p256_pk_hash = '11' * 20

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash], p256_pk_hash])

    txid, _count = contract.deploy(
      provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000)
    )
    expect(txid).to be_truthy
    expect(txid.length).to eq(64)
  end

  it 'deploys and verifies UTXO exists (full spend requires raw tx construction)' do
    # The hybrid spend pattern requires:
    #   1. Build unsigned spending transaction
    #   2. ECDSA-sign the transaction input
    #   3. P-256-sign the ECDSA signature bytes
    #   4. Construct unlocking script: <p256Sig> <p256PK> <ecdsaSig> <ecdsaPubKey>
    #
    # This two-pass signing pattern is fully tested in the Go integration
    # suite which uses raw transaction construction.
    artifact = compile_contract('examples/ts/p256-wallet/P256Wallet.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    p256_pk_hash = '22' * 20

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash], p256_pk_hash])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))

    expect(contract.get_utxo).not_to be_nil
  end
end
