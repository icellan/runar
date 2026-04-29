# frozen_string_literal: true

# PEDAGOGY: intentionally broken pattern -- "anyone can spend" once a single
# (msg, sig) pair under `pubkey` is observed, because `msg` is supplied by
# the spender and is not bound to the spending transaction. See the source
# file header for a full explanation. The hybrid pattern lives in
# examples/ruby/post-quantum-wallet/.

require_relative '../spec_helper'
require_relative 'PostQuantumWOTSNaiveInsecure.runar'

RSpec.describe PostQuantumWOTSNaiveInsecure do
  let(:keypair) { Runar::WOTS.keygen(seed_hex: '42' * 32, pub_seed_hex: '13' * 32) }
  let(:contract) { PostQuantumWOTSNaiveInsecure.new(keypair[:pk]) }

  it 'demonstrates the flaw: anyone can spend with an arbitrary attacker-chosen message' do
    # Attacker picks ANY message and signs it with the legitimate WOTS+ secret
    # key. The contract has no transaction binding, so it accepts. In a real
    # attack the same (msg, sig) could just be replayed from a single observed
    # spend.
    arbitrary_msg = 'deadbeef' + ('00' * 28)
    sig = Runar::WOTS.sign(arbitrary_msg, keypair[:sk], keypair[:pub_seed])
    expect { contract.spend(arbitrary_msg, sig) }.not_to raise_error

    # And a totally different attacker-chosen message also passes:
    other_msg = 'ff' * 32
    other_sig = Runar::WOTS.sign(other_msg, keypair[:sk], keypair[:pub_seed])
    expect { contract.spend(other_msg, other_sig) }.not_to raise_error
  end

  it 'still rejects a clearly invalid signature' do
    # Sanity check: the verifier itself works -- it's the contract's lack of
    # transaction binding that is the bug, not the underlying primitive.
    bogus_sig = '00' * (Runar::WOTS::LEN * Runar::WOTS::N)
    expect {
      contract.spend('deadbeef' + ('00' * 28), bogus_sig)
    }.to raise_error(RuntimeError, /assertion failed/)
  end
end
