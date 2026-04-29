# frozen_string_literal: true

# PEDAGOGY: intentionally broken pattern -- "anyone can spend" once a single
# (msg, sig) pair under `pubkey` is observed, because `msg` is supplied by
# the spender and is not bound to the spending transaction. See the source
# file header for a full explanation. The hybrid pattern lives in
# examples/ruby/sphincs-wallet/.

require_relative '../spec_helper'
require_relative 'PostQuantumSLHDSANaiveInsecure.runar'

RSpec.describe PostQuantumSLHDSANaiveInsecure do
  let(:params) { Runar::SLHDSA::PARAM_SETS[:sha2_128s] }
  # Deterministic seed (3*n bytes for SLH-DSA-128s where n=16 -> 48 bytes).
  let(:seed_hex) { (0...(3 * params[:n])).map { |i| format('%02x', i) }.join }
  let(:keypair) { Runar::SLHDSA.keygen(params, seed_hex) }
  let(:contract) { PostQuantumSLHDSANaiveInsecure.new(keypair[:pk]) }

  # Single happy-path demonstration. SLH-DSA-128s sign/verify in pure Ruby is
  # slow (~30-60s) so we keep this concise. Mirrors the SPHINCSWallet spec's
  # approach.
  it 'demonstrates the flaw: anyone can spend with an attacker-chosen message' do
    # Attacker picks ANY message and signs it with the legitimate SLH-DSA
    # secret key. The contract accepts because it has no transaction binding.
    arbitrary_msg = 'deadbeef' + ('00' * 60)
    sig = Runar::SLHDSA.sign(params, arbitrary_msg, keypair[:sk])
    expect { contract.spend(arbitrary_msg, sig) }.not_to raise_error
  end
end
