# frozen_string_literal: true

# BSV21Token integration spec — exercises the BSV-21 fungible token
# contract end-to-end on regtest. Ported from
# integration/ts/bsv21-token.test.ts.

require 'spec_helper'

RSpec.describe 'BSV21Token' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the BSV21Token contract' do
    artifact = compile_contract('examples/ts/bsv21-token/BSV21Token.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('BSV21Token')
    expect(artifact.script.length).to be > 0
  end

  it 'deploys with a pubKeyHash' do
    artifact = compile_contract('examples/ts/bsv21-token/BSV21Token.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash]])
    txid, _count = contract.deploy(
      provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000)
    )
    expect(txid).to be_truthy
    expect(txid.length).to eq(64)
  end

  it 'deploys and spends with unlock(sig, pubKey)' do
    artifact = compile_contract('examples/ts/bsv21-token/BSV21Token.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash]])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    call_txid, _ = contract.call('unlock', [nil, nil], provider, wallet[:signer])
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end
end
