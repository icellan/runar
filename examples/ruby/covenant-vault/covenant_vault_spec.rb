# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'CovenantVault.runar'

RSpec.describe CovenantVault do
  # The covenant rule (hash256(output) == extract_output_hash(tx_preimage))
  # requires a real sighash preimage with matching hashOutputs. The mock
  # preimage doesn't produce a meaningful hashOutputs, so we only verify
  # instantiation. The contract logic is fully verified by the TS test
  # suite and conformance golden files.
  it 'instantiates with valid constructor arguments' do
    c = CovenantVault.new(mock_pub_key, hash160(mock_pub_key), 1000)
    expect(c.owner).not_to be_nil
    expect(c.min_amount).to eq(1000)
  end
end
