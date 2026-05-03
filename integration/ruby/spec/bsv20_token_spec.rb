# frozen_string_literal: true

# BSV20Token integration spec — exercises the BSV-20 fungible token
# contract end-to-end on regtest. Ported from
# integration/ts/bsv20-token.test.ts.
#
# The BSV-20 contract is a P2PKH-style locking script extended with the
# ordinals envelope (inscription metadata in OP_RETURN). The contract
# itself is structurally identical to P2PKH, so the spec verifies the
# locked UTXO is a valid spend target.

require 'spec_helper'

RSpec.describe 'BSV20Token' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the BSV20Token contract' do
    artifact = compile_contract('examples/ts/bsv20-token/BSV20Token.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('BSV20Token')
    expect(artifact.script.length).to be > 0
  end

  it 'deploys with a pubKeyHash' do
    artifact = compile_contract('examples/ts/bsv20-token/BSV20Token.runar.ts')

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
    artifact = compile_contract('examples/ts/bsv20-token/BSV20Token.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash]])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    call_txid, _ = contract.call('unlock', [nil, nil], provider, wallet[:signer])
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end
end
