# frozen_string_literal: true

# P384Wallet integration spec — Hybrid ECDSA + NIST P-384 contract.
#
# Ported from integration/ts/p384-wallet.test.ts. The full spend path
# requires raw-transaction construction with both an ECDSA signature
# and a P-384 signature; this spec covers the compile-and-deploy half
# so a regression in the P-384 codegen module is caught at the SDK
# level.

require 'spec_helper'

RSpec.describe 'P384Wallet' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the P384Wallet contract' do
    artifact = compile_contract('examples/ts/p384-wallet/P384Wallet.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('P384Wallet')
    expect(artifact.script.length).to be > 0
  end

  it 'has a hybrid ECDSA+P-384 verification script in the expected size band' do
    # Hybrid ECDSA+P-384 scripts compile to ~1-2 MB depending on the
    # peephole pass; this is an order-of-magnitude bound matching the Python
    # reference (integration/python/test_p384_wallet.py).
    artifact     = compile_contract('examples/ts/p384-wallet/P384Wallet.runar.ts')
    script_bytes = artifact.script.length / 2
    expect(script_bytes).to be > 100_000
    expect(script_bytes).to be < 3_000_000
  end

  it 'deploys with ECDSA pubkey hash + P-384 pubkey hash' do
    artifact = compile_contract('examples/ts/p384-wallet/P384Wallet.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    p384_pk_hash = '11' * 20

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash], p384_pk_hash])

    txid, _count = contract.deploy(
      provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000)
    )
    expect(txid).to be_truthy
    expect(txid.length).to eq(64)
  end

  it 'deploys and verifies UTXO exists (full spend requires raw tx construction)' do
    artifact = compile_contract('examples/ts/p384-wallet/P384Wallet.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    p384_pk_hash = '22' * 20

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash], p384_pk_hash])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))

    expect(contract.get_utxo).not_to be_nil
  end
end
