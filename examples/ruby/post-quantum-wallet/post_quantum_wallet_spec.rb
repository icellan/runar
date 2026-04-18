# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'PostQuantumWallet.runar'

RSpec.describe PostQuantumWallet do
  let(:seed_hex)     { '42' * 32 }
  let(:pub_seed_hex) { '13' * 32 }
  let(:keypair)      { Runar::WOTS.keygen(seed_hex: seed_hex, pub_seed_hex: pub_seed_hex) }

  it 'spends with a valid WOTS+ signature' do
    msg = '00' * 5
    sig = Runar::WOTS.sign(msg, keypair[:sk], keypair[:pub_seed])
    c = PostQuantumWallet.new(keypair[:pk])
    expect { c.spend(msg, sig) }.not_to raise_error
  end

  it 'rejects a tampered WOTS+ signature' do
    msg = '00' * 5
    sig = Runar::WOTS.sign(msg, keypair[:sk], keypair[:pub_seed])
    # Flip the first byte of the signature
    bad_sig = (sig[0, 2].to_i(16) ^ 0xff).to_s(16).rjust(2, '0') + sig[2..]
    c = PostQuantumWallet.new(keypair[:pk])
    expect { c.spend(msg, bad_sig) }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'rejects a signature against a different public key' do
    msg = '00' * 5
    sig = Runar::WOTS.sign(msg, keypair[:sk], keypair[:pub_seed])
    wrong_kp = Runar::WOTS.keygen(seed_hex: 'aa' * 32, pub_seed_hex: 'bb' * 32)
    c = PostQuantumWallet.new(wrong_kp[:pk])
    expect { c.spend(msg, sig) }.to raise_error(RuntimeError, /assertion failed/)
  end
end
