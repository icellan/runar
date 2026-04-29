# frozen_string_literal: true

require_relative '../spec_helper'
require 'runar/test_keys'
require_relative 'SPHINCSWallet.runar'

# SPHINCSWallet is an ECDSA + SLH-DSA combo wallet:
#   1. ECDSA signature commits to the spending transaction.
#   2. SLH-DSA signs the ECDSA signature bytes, proving the ECDSA sig was
#      authorized by the SLH-DSA key holder.
#
# These tests use the sha2_128s parameter set (matching the contract's
# verify_slh_dsa_sha2_128s call). SLH-DSA-128s signing is slow in pure Ruby
# (~30-60s); the spec is therefore concise. Mirrors
# examples/go/sphincs-wallet/SPHINCSWallet_test.go.
RSpec.describe SPHINCSWallet do
  let(:alice)              { Runar::TestKeys::ALICE }
  let(:ecdsa_pub_key)      { alice.pub_key }
  let(:ecdsa_pub_key_hash) { alice.pub_key_hash }

  let(:params)             { Runar::SLHDSA::PARAM_SETS[:sha2_128s] }
  # Deterministic seed (3*n bytes for SLH-DSA-128s where n=16 → 48 bytes).
  let(:seed_hex)           { (0...(3 * params[:n])).map { |i| format('%02x', i) }.join }
  let(:keypair)            { Runar::SLHDSA.keygen(params, seed_hex) }
  let(:slhdsa_pub_key_hash) { hash160(keypair[:pk]) }

  # Real ECDSA signature; SLH-DSA signs those bytes as its message.
  let(:ecdsa_sig)          { Runar::ECDSA.sign_test_message(alice.priv_key) }
  let(:slhdsa_sig)         { Runar::SLHDSA.sign(params, ecdsa_sig, keypair[:sk]) }

  def flip_first_byte(sig_hex)
    flipped = (sig_hex[0, 2].to_i(16) ^ 0xff).to_s(16).rjust(2, '0')
    flipped + sig_hex[2..]
  end

  it 'spends with a valid SLH-DSA signature' do
    c = SPHINCSWallet.new(ecdsa_pub_key_hash, slhdsa_pub_key_hash)
    expect { c.spend(slhdsa_sig, keypair[:pk], ecdsa_sig, ecdsa_pub_key) }.not_to raise_error
  end

  it 'rejects a tampered SLH-DSA signature' do
    bad_sig = flip_first_byte(slhdsa_sig)
    c = SPHINCSWallet.new(ecdsa_pub_key_hash, slhdsa_pub_key_hash)
    expect {
      c.spend(bad_sig, keypair[:pk], ecdsa_sig, ecdsa_pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end
end
