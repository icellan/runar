# frozen_string_literal: true

# FungibleToken integration test -- stateful contract with addOutput.
#
# FungibleToken is a StatefulSmartContract with properties:
#   - owner:        PubKey (mutable)
#   - balance:      bigint (mutable)
#   - tokenId:      ByteString (readonly)
#
# The SDK auto-computes Sig params when nil is passed.

require 'spec_helper'

RSpec.describe 'FungibleToken' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the FungibleToken contract' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('FungibleToken')
  end

  it 'deploys with owner and initial balance of 1000' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner        = create_wallet
    wallet       = create_funded_wallet(provider)
    token_id_hex = 'TEST-TOKEN-001'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex],
      1000,
      0,
      token_id_hex
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys with zero initial balance' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner        = create_wallet
    wallet       = create_funded_wallet(provider)
    token_id_hex = 'ZERO-BAL-TOKEN'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex],
      0,
      0,
      token_id_hex
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'deploys with a very large balance (21M BTC in satoshis)' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner        = create_wallet
    wallet       = create_funded_wallet(provider)
    token_id_hex = 'BIG-TOKEN'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner[:pub_key_hex],
      2_100_000_000_000_000,
      0,
      token_id_hex
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'deploys and sends entire balance to a recipient' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    recipient    = create_wallet
    token_id_hex = 'SEND-TOKEN'.unpack1('H*')

    # Owner is the funded signer
    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex],
      1000,
      0,
      token_id_hex
    ])

    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # send: sig=nil (auto), to=recipient, outputSatoshis=5000
    # send uses addOutput, so we need outputs (not new_state)
    call_txid, _count = contract.call(
      'send',
      [nil, recipient[:pub_key_hex], 5000],
      provider, owner_wallet[:signer],
      Runar::SDK::CallOptions.new(outputs: [
        { 'satoshis' => 5000, 'state' => { 'owner' => recipient[:pub_key_hex], 'balance' => 1000, 'mergeBalance' => 0 } }
      ])
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects send with wrong signer (not the owner)' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    wrong_wallet = create_funded_wallet(provider)
    recipient    = create_wallet
    token_id_hex = 'REJECT-TOKEN'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex],
      1000,
      0,
      token_id_hex
    ])

    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call(
        'send',
        [nil, recipient[:pub_key_hex], 5000],
        provider, wrong_wallet[:signer],
        Runar::SDK::CallOptions.new(outputs: [
          { 'satoshis' => 5000, 'state' => { 'owner' => recipient[:pub_key_hex], 'balance' => 1000, 'mergeBalance' => 0 } }
        ])
      )
    end.to raise_error(StandardError)
  end

  it 'transfers using SDK multi-output support: splits 1 UTXO into 2 outputs' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    recipient    = create_wallet
    token_id_hex = 'TRANSFER-TOKEN'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex], 1000, 0, token_id_hex
    ])
    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # transfer(sig, to, amount, outputSatoshis) — 2 outputs
    call_txid, _count = contract.call(
      'transfer',
      [nil, recipient[:pub_key_hex], 300, 2000],
      provider, owner_wallet[:signer],
      Runar::SDK::CallOptions.new(outputs: [
        { 'satoshis' => 2000, 'state' => { 'owner' => recipient[:pub_key_hex], 'balance' => 300, 'mergeBalance' => 0 } },
        { 'satoshis' => 2000, 'state' => { 'owner' => owner_wallet[:pub_key_hex], 'balance' => 700, 'mergeBalance' => 0 } }
      ])
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'merges using SDK additional-contract-input support: consolidates 2 UTXOs into 1' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    token_id_hex = 'MERGE-SDK-TOKEN'.unpack1('H*')

    contract1 = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 400, 0, token_id_hex])
    contract1.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract2 = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 600, 0, token_id_hex])
    contract2.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    utxo2 = contract2.get_utxo
    call_txid, _count = contract1.call(
      'merge',
      [nil, 600, nil, 4000],
      provider, owner_wallet[:signer],
      Runar::SDK::CallOptions.new(
        additional_contract_inputs: [utxo2],
        additional_contract_input_args: [[nil, 400, nil, 4000]],
        outputs: [{ 'satoshis' => 4000, 'state' => { 'owner' => owner_wallet[:pub_key_hex], 'balance' => 400, 'mergeBalance' => 600 } }]
      )
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects merge with inflated total (hashOutputs mismatch)' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    token_id_hex = 'MERGE-INFLATE'.unpack1('H*')

    contract1 = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 400, 0, token_id_hex])
    contract1.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract2 = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 600, 0, token_id_hex])
    contract2.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    utxo2 = contract2.get_utxo

    expect do
      contract1.call(
        'merge',
        [nil, 1600, nil, 4000],
        provider, owner_wallet[:signer],
        Runar::SDK::CallOptions.new(
          additional_contract_inputs: [utxo2],
          additional_contract_input_args: [[nil, 1400, nil, 4000]],
          outputs: [{ 'satoshis' => 4000, 'state' => { 'owner' => owner_wallet[:pub_key_hex], 'balance' => 400, 'mergeBalance' => 1600 } }]
        )
      )
    end.to raise_error(StandardError)
  end

  it 'rejects merge with deflated total (negative otherBalance fails assert)' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    token_id_hex = 'MERGE-DEFLATE'.unpack1('H*')

    contract1 = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 400, 0, token_id_hex])
    contract1.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract2 = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 600, 0, token_id_hex])
    contract2.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    utxo2 = contract2.get_utxo

    expect do
      contract1.call(
        'merge',
        [nil, 100, nil, 4000],
        provider, owner_wallet[:signer],
        Runar::SDK::CallOptions.new(
          additional_contract_inputs: [utxo2],
          additional_contract_input_args: [[nil, -100, nil, 4000]],
          outputs: [{ 'satoshis' => 4000, 'state' => { 'owner' => owner_wallet[:pub_key_hex], 'balance' => 400, 'mergeBalance' => 100 } }]
        )
      )
    end.to raise_error(StandardError)
  end

  it 'merges edge case: zero-balance UTXO with a non-zero UTXO' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    token_id_hex = 'MERGE-ZERO'.unpack1('H*')

    contract1 = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 0, 0, token_id_hex])
    contract1.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract2 = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 500, 0, token_id_hex])
    contract2.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    utxo2 = contract2.get_utxo

    call_txid, _count = contract1.call(
      'merge',
      [nil, 500, nil, 4000],
      provider, owner_wallet[:signer],
      Runar::SDK::CallOptions.new(
        additional_contract_inputs: [utxo2],
        additional_contract_input_args: [[nil, 0, nil, 4000]],
        outputs: [{ 'satoshis' => 4000, 'state' => { 'owner' => owner_wallet[:pub_key_hex], 'balance' => 0, 'mergeBalance' => 500 } }]
      )
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects merge with wrong signer (checkSig fails)' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    wrong_wallet = create_funded_wallet(provider)
    token_id_hex = 'MERGE-WRONG'.unpack1('H*')

    contract1 = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 400, 0, token_id_hex])
    contract1.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract2 = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 600, 0, token_id_hex])
    contract2.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    utxo2 = contract2.get_utxo

    expect do
      contract1.call(
        'merge',
        [nil, 600, nil, 4000],
        provider, wrong_wallet[:signer],
        Runar::SDK::CallOptions.new(
          additional_contract_inputs: [utxo2],
          additional_contract_input_args: [[nil, 400, nil, 4000]],
          outputs: [{ 'satoshis' => 4000, 'state' => { 'owner' => owner_wallet[:pub_key_hex], 'balance' => 400, 'mergeBalance' => 600 } }]
        )
      )
    end.to raise_error(StandardError)
  end

  it 'transfers exact balance to recipient (1 output, no change)' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    recipient    = create_wallet
    token_id_hex = 'XFER-EXACT'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex], 1000, 0, token_id_hex
    ])
    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    call_txid, _count = contract.call(
      'transfer',
      [nil, recipient[:pub_key_hex], 1000, 2000],
      provider, owner_wallet[:signer],
      Runar::SDK::CallOptions.new(outputs: [
        { 'satoshis' => 2000, 'state' => { 'owner' => recipient[:pub_key_hex], 'balance' => 1000, 'mergeBalance' => 0 } }
      ])
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects transfer with inflated output balances beyond input' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    recipient    = create_wallet
    token_id_hex = 'XFER-INFLATE'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex], 1000, 0, token_id_hex
    ])
    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # Claim recipient gets 800, sender keeps 500 = 1300 total (inflated from 1000)
    expect do
      contract.call(
        'transfer',
        [nil, recipient[:pub_key_hex], 800, 2000],
        provider, owner_wallet[:signer],
        Runar::SDK::CallOptions.new(outputs: [
          { 'satoshis' => 2000, 'state' => { 'owner' => recipient[:pub_key_hex], 'balance' => 800, 'mergeBalance' => 0 } },
          { 'satoshis' => 2000, 'state' => { 'owner' => owner_wallet[:pub_key_hex], 'balance' => 500, 'mergeBalance' => 0 } }
        ])
      )
    end.to raise_error(StandardError)
  end

  it 'rejects transfer with deflated output balances' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    recipient    = create_wallet
    token_id_hex = 'XFER-DEFLATE'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex], 1000, 0, token_id_hex
    ])
    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # Claim recipient gets 300, sender keeps 200 = 500 total (deflated from 1000)
    expect do
      contract.call(
        'transfer',
        [nil, recipient[:pub_key_hex], 300, 2000],
        provider, owner_wallet[:signer],
        Runar::SDK::CallOptions.new(outputs: [
          { 'satoshis' => 2000, 'state' => { 'owner' => recipient[:pub_key_hex], 'balance' => 300, 'mergeBalance' => 0 } },
          { 'satoshis' => 2000, 'state' => { 'owner' => owner_wallet[:pub_key_hex], 'balance' => 200, 'mergeBalance' => 0 } }
        ])
      )
    end.to raise_error(StandardError)
  end

  it 'rejects transfer of zero amount (fails assert amount > 0)' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    recipient    = create_wallet
    token_id_hex = 'XFER-ZERO'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex], 1000, 0, token_id_hex
    ])
    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call(
        'transfer',
        [nil, recipient[:pub_key_hex], 0, 2000],
        provider, owner_wallet[:signer],
        Runar::SDK::CallOptions.new(outputs: [
          { 'satoshis' => 2000, 'state' => { 'owner' => recipient[:pub_key_hex], 'balance' => 0, 'mergeBalance' => 0 } },
          { 'satoshis' => 2000, 'state' => { 'owner' => owner_wallet[:pub_key_hex], 'balance' => 1000, 'mergeBalance' => 0 } }
        ])
      )
    end.to raise_error(StandardError)
  end

  it 'rejects transfer exceeding balance (fails assert amount <= totalBalance)' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    recipient    = create_wallet
    token_id_hex = 'XFER-EXCEED'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [
      owner_wallet[:pub_key_hex], 1000, 0, token_id_hex
    ])
    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call(
        'transfer',
        [nil, recipient[:pub_key_hex], 2000, 2000],
        provider, owner_wallet[:signer],
        Runar::SDK::CallOptions.new(outputs: [
          { 'satoshis' => 2000, 'state' => { 'owner' => recipient[:pub_key_hex], 'balance' => 2000, 'mergeBalance' => 0 } }
        ])
      )
    end.to raise_error(StandardError)
  end

  it 'rejects transfer with wrong signer (checkSig fails)' do
    artifact = compile_contract('examples/ts/token-ft/FungibleTokenExample.runar.ts')

    provider     = create_provider
    owner_wallet = create_funded_wallet(provider)
    wrong_wallet = create_funded_wallet(provider)
    recipient    = create_wallet
    token_id_hex = 'XFER-WRONG'.unpack1('H*')

    contract = Runar::SDK::RunarContract.new(artifact, [owner_wallet[:pub_key_hex], 1000, 0, token_id_hex])
    contract.deploy(provider, owner_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call(
        'transfer',
        [nil, recipient[:pub_key_hex], 300, 2000],
        provider, wrong_wallet[:signer],
        Runar::SDK::CallOptions.new(outputs: [
          { 'satoshis' => 2000, 'state' => { 'owner' => recipient[:pub_key_hex], 'balance' => 300, 'mergeBalance' => 0 } },
          { 'satoshis' => 2000, 'state' => { 'owner' => owner_wallet[:pub_key_hex], 'balance' => 700, 'mergeBalance' => 0 } }
        ])
      )
    end.to raise_error(StandardError)
  end
end
