# frozen_string_literal: true

# MathDemo integration test -- stateful contract exercising built-in math functions.
#
# MathDemo is a StatefulSmartContract with a single mutable property +value+.
# Methods: divideBy(n), clampValue(lo, hi), squareRoot(), exponentiate(n),
#          reduceGcd(n), computeLog2(), scaleByRatio(num, den), normalize().

require 'spec_helper'

RSpec.describe 'MathDemo' do # rubocop:disable RSpec/DescribeClass
  it 'deploys with initial value 1000' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [1000])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'divides 1000 / 10 = 100' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [1000])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    txid, _count = contract.call(
      'divideBy', [10], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 100 })
    )
    expect(txid).to be_truthy
  end

  it 'divides then clamps: 1000 -> 100 (divideBy 10) -> 50 (clamp 0..50)' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [1000])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract.call(
      'divideBy', [10], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 100 })
    )

    contract.call(
      'clampValue', [0, 50], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 50 })
    )
  end

  it 'computes sqrt(49) = 7' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [49])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    txid, _count = contract.call(
      'squareRoot', [], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 7 })
    )
    expect(txid).to be_truthy
  end

  it 'exponentiates 2^10 = 1024' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [2])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    txid, _count = contract.call(
      'exponentiate', [10], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 1024 })
    )
    expect(txid).to be_truthy
  end

  it 'reduces gcd(100, 75) = 25' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [100])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    txid, _count = contract.call(
      'reduceGcd', [75], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 25 })
    )
    expect(txid).to be_truthy
  end

  it 'computes log2(1024) = 10' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [1024])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    txid, _count = contract.call(
      'computeLog2', [], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 10 })
    )
    expect(txid).to be_truthy
  end

  it 'scales by ratio: 100 * 3 / 4 = 75' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [100])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    txid, _count = contract.call(
      'scaleByRatio', [3, 4], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 75 })
    )
    expect(txid).to be_truthy
  end

  it 'rejects divideBy(0)' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [1000])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call(
        'divideBy', [0], provider, wallet[:signer],
        Runar::SDK::CallOptions.new(new_state: { 'value' => 0 })
      )
    end.to raise_error(StandardError)
  end

  it 'rejects claiming value=999 instead of 100 after divideBy(10)' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [1000])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call(
        'divideBy', [10], provider, wallet[:signer],
        Runar::SDK::CallOptions.new(new_state: { 'value' => 999 })
      )
    end.to raise_error(StandardError)
  end

  it 'normalises: sign(-42) = -1' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [-42])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    txid, _count = contract.call(
      'normalize', [], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => -1 })
    )
    expect(txid).to be_truthy
  end

  it 'chains operations: 1000 -> divideBy(10)=100 -> squareRoot()=10 -> scaleByRatio(5,1)=50' do
    artifact = compile_contract('examples/ts/math-demo/MathDemo.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [1000])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract.call(
      'divideBy', [10], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 100 })
    )

    contract.call(
      'squareRoot', [], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 10 })
    )

    contract.call(
      'scaleByRatio', [5, 1], provider, wallet[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'value' => 50 })
    )
  end
end
