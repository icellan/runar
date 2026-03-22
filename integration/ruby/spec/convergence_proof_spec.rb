# frozen_string_literal: true

# ConvergenceProof integration test -- stateless contract using EC point operations.
#
# The contract verifies that R_A - R_B = deltaO * G on secp256k1, proving two
# OPRF submissions share the same underlying token without revealing it.
#
# We verify compilation, deployment, and spending (valid + invalid deltaO).

require 'spec_helper'

def generate_convergence_test_data
  a = 12_345
  b = 6_789
  delta_o = ((a - b) % IntegrationHelpers::EC_N + IntegrationHelpers::EC_N) % IntegrationHelpers::EC_N

  ra_x, ra_y = ec_mul_gen(a)
  rb_x, rb_y = ec_mul_gen(b)

  {
    r_a: encode_point(ra_x, ra_y),
    r_b: encode_point(rb_x, rb_y),
    delta_o: delta_o,
    wrong_delta: ((a - b + 1) % IntegrationHelpers::EC_N + IntegrationHelpers::EC_N) % IntegrationHelpers::EC_N
  }
end

RSpec.describe 'ConvergenceProof' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the ConvergenceProof contract' do
    artifact = compile_contract('examples/ts/convergence-proof/ConvergenceProof.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('ConvergenceProof')
  end

  it 'deploys with valid EC points' do
    artifact  = compile_contract('examples/ts/convergence-proof/ConvergenceProof.runar.ts')
    test_data = generate_convergence_test_data

    contract = Runar::SDK::RunarContract.new(artifact, [test_data[:r_a], test_data[:r_b]])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
    expect(txid.length).to eq(64)
  end

  it 'deploys and spends with valid deltaO' do
    artifact  = compile_contract('examples/ts/convergence-proof/ConvergenceProof.runar.ts')
    test_data = generate_convergence_test_data

    contract = Runar::SDK::RunarContract.new(artifact, [test_data[:r_a], test_data[:r_b]])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    call_txid, _count = contract.call(
      'proveConvergence',
      [test_data[:delta_o]],
      provider, wallet[:signer]
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects invalid deltaO' do
    artifact  = compile_contract('examples/ts/convergence-proof/ConvergenceProof.runar.ts')
    test_data = generate_convergence_test_data

    contract = Runar::SDK::RunarContract.new(artifact, [test_data[:r_a], test_data[:r_b]])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    expect do
      contract.call(
        'proveConvergence',
        [test_data[:wrong_delta]],
        provider, wallet[:signer]
      )
    end.to raise_error(StandardError)
  end
end
