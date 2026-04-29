# frozen_string_literal: true

require_relative '../spec_helper'
require 'runar/test_keys'
require 'runar/nist_ecdsa'
require_relative 'P256Wallet.runar'

# P256Wallet is a hybrid secp256k1 + P-256 ECDSA wallet:
#   1. secp256k1 ECDSA signature commits to the spending transaction (sighash).
#   2. P-256 ECDSA signs the secp256k1 signature bytes, proving the secp256k1
#      sig was authorized by the P-256 (NIST / WebAuthn / TPM) key holder.
#
# Mirrors examples/python/p256-wallet/test_p256_wallet.py and
# examples/ts/p256-wallet/P256Wallet.test.ts.
RSpec.describe P256Wallet do
  let(:alice)              { Runar::TestKeys::ALICE }
  let(:ecdsa_pub_key)      { alice.pub_key }
  let(:ecdsa_pub_key_hash) { alice.pub_key_hash }

  # Real secp256k1 ECDSA signature; P-256 signs those bytes as its message.
  let(:ecdsa_sig)          { Runar::ECDSA.sign_test_message(alice.priv_key) }

  # Fresh P-256 key pair for each example.
  let(:kp)                 { Runar::NistECDSA.p256_keygen }
  let(:p256_pub_key_hash)  { hash160(kp[:pk_compressed]) }
  let(:p256_sig)           { Runar::NistECDSA.p256_sign(ecdsa_sig, kp[:sk]) }

  it 'spends with a valid hybrid signature pair' do
    c = P256Wallet.new(ecdsa_pub_key_hash, p256_pub_key_hash)
    expect { c.spend(p256_sig, kp[:pk_compressed], ecdsa_sig, ecdsa_pub_key) }.not_to raise_error
  end

  it 'rejects a spend with the wrong secp256k1 public key' do
    bob = Runar::TestKeys::BOB
    c = P256Wallet.new(ecdsa_pub_key_hash, p256_pub_key_hash)
    # bob.pub_key.hash160 != alice.pub_key_hash, so the inner P2PKH check fails
    expect {
      c.spend(p256_sig, kp[:pk_compressed], ecdsa_sig, bob.pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'rejects a spend with the wrong P-256 public key' do
    wrong_kp = Runar::NistECDSA.p256_keygen
    wrong_p256_sig = Runar::NistECDSA.p256_sign(ecdsa_sig, wrong_kp[:sk])
    # Contract is committed to the original keypair's hash; a different one fails.
    c = P256Wallet.new(ecdsa_pub_key_hash, p256_pub_key_hash)
    expect {
      c.spend(wrong_p256_sig, wrong_kp[:pk_compressed], ecdsa_sig, ecdsa_pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'rejects a tampered P-256 signature' do
    bad_sig_hex = (p256_sig[0, 2].to_i(16) ^ 0xff).to_s(16).rjust(2, '0') + p256_sig[2..]
    c = P256Wallet.new(ecdsa_pub_key_hash, p256_pub_key_hash)
    expect {
      c.spend(bad_sig_hex, kp[:pk_compressed], ecdsa_sig, ecdsa_pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'rejects a P-256 signature over the wrong message' do
    fake_msg = ('00' * 72)
    sig_over_wrong_msg = Runar::NistECDSA.p256_sign(fake_msg, kp[:sk])
    c = P256Wallet.new(ecdsa_pub_key_hash, p256_pub_key_hash)
    # The contract hands the real ecdsa_sig to verify_ecdsa_p256, but the
    # signature was produced over fake_msg — verification must fail.
    expect {
      c.spend(sig_over_wrong_msg, kp[:pk_compressed], ecdsa_sig, ecdsa_pub_key)
    }.to raise_error(RuntimeError, /assertion failed/)
  end
end
