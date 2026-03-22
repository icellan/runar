# frozen_string_literal: true

# Counter integration test -- stateful contract (SDK Deploy/Call path).
#
# Counter is a StatefulSmartContract with a single mutable property +count+.
# Methods: increment(), decrement().

require 'spec_helper'

RSpec.describe 'Counter' do # rubocop:disable RSpec/DescribeClass
  it 'deploys with count=0, calls increment, verifies count=1' do
    artifact = compile_contract('examples/ts/stateful-counter/Counter.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [0])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
    expect(txid.length).to eq(64)

    call_txid, _count = contract.call(
      'increment', [], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'count' => 1 })
    )
    expect(call_txid).to be_truthy
  end

  it 'chains increments: 0 -> 1 -> 2' do
    artifact = compile_contract('examples/ts/stateful-counter/Counter.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [0])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract.call(
      'increment', [], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'count' => 1 })
    )

    contract.call(
      'increment', [], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'count' => 2 })
    )
  end

  it 'increments then decrements: 0 -> 1 -> 0' do
    artifact = compile_contract('examples/ts/stateful-counter/Counter.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [0])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract.call(
      'increment', [], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'count' => 1 })
    )

    contract.call(
      'decrement', [], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'count' => 0 })
    )
  end

  it 'rejects claiming count=99 instead of 1 after increment' do
    artifact = compile_contract('examples/ts/stateful-counter/Counter.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [0])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call(
        'increment', [], provider, wallet[:signer],
        Runar::SDK::CallOptions.new(new_state: { 'count' => 99 })
      )
    end.to raise_error(StandardError)
  end

  it 'rejects decrement from 0 (assert count > 0)' do
    artifact = compile_contract('examples/ts/stateful-counter/Counter.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [0])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call(
        'decrement', [], provider, wallet[:signer],
        Runar::SDK::CallOptions.new(new_state: { 'count' => -1 })
      )
    end.to raise_error(StandardError)
  end
end
