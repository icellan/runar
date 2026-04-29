# frozen_string_literal: true

require_relative '../spec_helper'
require 'runar/test_keys'
require 'runar/nist_ecdsa'
require_relative 'P384Wallet.runar'

# P384Wallet is a hybrid secp256k1 + P-384 ECDSA wallet:
#   1. secp256k1 ECDSA signature commits to the spending transaction (sighash).
#   2. P-384 ECDSA signs the secp256k1 signature bytes, proving the secp256k1
#      sig was authorized by the P-384 (FIPS-grade HSM) key holder.
#
# Mirrors examples/python/p384-wallet/test_p384_wallet.py and
# examples/ts/p384-wallet/P384Wallet.test.ts.
RSpec.describe P384Wallet do
  let(:alice)              { Runar::TestKeys::ALICE }
  let(:ecdsa_pub_key)      { alice.pub_key }
  let(:ecdsa_pub_key_hash) { alice.pub_key_hash }

  let(:ecdsa_sig)          { Runar::ECDSA.sign_test_message(alice.priv_key) }

  let(:kp)                 { Runar::NistECDSA.p384_keygen }
  let(:p384_pub_key_hash)  { hash160(kp[:pk_compressed]) }
  let(:p384_sig)           { Runar::NistECDSA.p384_sign(ecdsa_sig, kp[:sk]) }

  it 'spends with a valid hybrid signature pair' do
    c = P384Wallet.new(ecdsa_pub_key_hash, p384_pub_key_hash)
    expect { c.spend(p384_sig, kp[:pk_compressed], ecdsa_sig, ecdsa_pub_key) }.not_to raise_error
  end

  it 'rejects a spend with the wrong secp256k1 public key' do
    bob = Runar::TestKeys::BOB
    c = P384Wallet.new(ecdsa_pub_key_hash, p384_pub_key_hash)
    expect {
      c.spend(p384_sig, kp[:pk_compressed], ecdsa_sig, bob.pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'rejects a spend with the wrong P-384 public key' do
    wrong_kp = Runar::NistECDSA.p384_keygen
    wrong_p384_sig = Runar::NistECDSA.p384_sign(ecdsa_sig, wrong_kp[:sk])
    c = P384Wallet.new(ecdsa_pub_key_hash, p384_pub_key_hash)
    expect {
      c.spend(wrong_p384_sig, wrong_kp[:pk_compressed], ecdsa_sig, ecdsa_pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'rejects a tampered P-384 signature' do
    bad_sig_hex = (p384_sig[0, 2].to_i(16) ^ 0xff).to_s(16).rjust(2, '0') + p384_sig[2..]
    c = P384Wallet.new(ecdsa_pub_key_hash, p384_pub_key_hash)
    expect {
      c.spend(bad_sig_hex, kp[:pk_compressed], ecdsa_sig, ecdsa_pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'rejects a P-384 signature over the wrong message' do
    fake_msg = ('00' * 72)
    sig_over_wrong_msg = Runar::NistECDSA.p384_sign(fake_msg, kp[:sk])
    c = P384Wallet.new(ecdsa_pub_key_hash, p384_pub_key_hash)
    expect {
      c.spend(sig_over_wrong_msg, kp[:pk_compressed], ecdsa_sig, ecdsa_pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end
end
