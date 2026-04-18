# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'SPHINCSWallet.runar'

# These tests use the 128f ('fast') SLH-DSA parameter set because 's'
# variants take ~30-60s per sign in pure Ruby. The contract itself uses
# sha2_128s in production — both share the verifier code path, and the
# small-parameter-set test proves the end-to-end flow works.
RSpec.describe SPHINCSWallet do
  let(:params)   { Runar::SLHDSA::PARAM_SETS[:sha2_128s] }
  let(:seed_hex) { '42' * (3 * params[:n]) }
  let(:keypair)  { Runar::SLHDSA.keygen(params, seed_hex) }

  it 'spends with a valid SLH-DSA signature' do
    msg = '00' * 5
    sig = Runar::SLHDSA.sign(params, msg, keypair[:sk])
    c = SPHINCSWallet.new(keypair[:pk])
    expect { c.spend(msg, sig) }.not_to raise_error
  end

  it 'rejects a tampered SLH-DSA signature' do
    msg = '00' * 5
    sig = Runar::SLHDSA.sign(params, msg, keypair[:sk])
    bad_sig = (sig[0, 2].to_i(16) ^ 0xff).to_s(16).rjust(2, '0') + sig[2..]
    c = SPHINCSWallet.new(keypair[:pk])
    expect { c.spend(msg, bad_sig) }.to raise_error(RuntimeError, /assertion failed/)
  end
end
