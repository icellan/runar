# frozen_string_literal: true

require_relative '../spec_helper'
require 'runar/test_keys'
require_relative 'PostQuantumWallet.runar'

# PostQuantumWallet is an ECDSA + WOTS+ combo wallet:
#   1. ECDSA signature commits to the spending transaction (BIP-143 sighash).
#   2. WOTS+ signs the ECDSA signature bytes, proving the ECDSA sig was
#      authorized by the WOTS+ key holder.
#
# These tests mirror examples/go/post-quantum-wallet/PostQuantumWallet_test.go.
RSpec.describe PostQuantumWallet do
  let(:alice)              { Runar::TestKeys::ALICE }
  let(:ecdsa_pub_key)      { alice.pub_key }
  let(:ecdsa_pub_key_hash) { alice.pub_key_hash }

  let(:seed_hex)           { '42' * 32 }
  let(:pub_seed_hex)       { '13' * 32 }
  let(:keypair)            { Runar::WOTS.keygen(seed_hex: seed_hex, pub_seed_hex: pub_seed_hex) }
  let(:wots_pub_key_hash)  { hash160(keypair[:pk]) }

  # Real ECDSA signature over the fixed TEST_MESSAGE_DIGEST. WOTS+ then signs
  # those signature bytes as its message.
  let(:ecdsa_sig)          { Runar::ECDSA.sign_test_message(alice.priv_key) }
  let(:wots_sig)           { Runar::WOTS.sign(ecdsa_sig, keypair[:sk], keypair[:pub_seed]) }

  # Flip the first byte of a hex-encoded signature.
  def flip_first_byte(sig_hex)
    flipped = (sig_hex[0, 2].to_i(16) ^ 0xff).to_s(16).rjust(2, '0')
    flipped + sig_hex[2..]
  end

  it 'spends with a valid WOTS+ signature' do
    c = PostQuantumWallet.new(ecdsa_pub_key_hash, wots_pub_key_hash)
    expect { c.spend(wots_sig, keypair[:pk], ecdsa_sig, ecdsa_pub_key) }.not_to raise_error
  end

  it 'rejects a tampered WOTS+ signature' do
    bad_wots_sig = flip_first_byte(wots_sig)
    c = PostQuantumWallet.new(ecdsa_pub_key_hash, wots_pub_key_hash)
    expect {
      c.spend(bad_wots_sig, keypair[:pk], ecdsa_sig, ecdsa_pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'rejects a signature against a different public key' do
    # Generate a different WOTS keypair; commit the contract to its hash, then
    # try to spend with a WOTS sig produced by the original keypair. The
    # hash160(wots_pub_key) check inside the contract must fail.
    wrong_kp = Runar::WOTS.keygen(seed_hex: 'aa' * 32, pub_seed_hex: 'bb' * 32)
    c = PostQuantumWallet.new(ecdsa_pub_key_hash, hash160(wrong_kp[:pk]))
    expect {
      c.spend(wots_sig, keypair[:pk], ecdsa_sig, ecdsa_pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end
end
