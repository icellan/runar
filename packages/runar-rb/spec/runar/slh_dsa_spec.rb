# frozen_string_literal: true

require 'spec_helper'

# These specs exercise the real SLH-DSA verifier exposed through
# Runar::Builtins#verify_slh_dsa_sha2_*. They start from the observation that
# the mocked implementations returned true for _every_ input, including
# obvious garbage. A real verifier must reject invalid signatures.
#
# Full keygen + sign + verify for the 's' parameter sets of SLH-DSA is slow
# (tens of seconds in pure Ruby). We use the 'f' ('fast') 128-bit variant
# for round-trip tests; the remaining parameter sets get reject-only checks
# which run in milliseconds.

RSpec.describe 'SLH-DSA verification via Runar::Builtins' do
  let(:ctx) { Object.new.extend(Runar::Builtins) }

  ALL_METHODS = %i[
    verify_slh_dsa_sha2_128s verify_slh_dsa_sha2_128f
    verify_slh_dsa_sha2_192s verify_slh_dsa_sha2_192f
    verify_slh_dsa_sha2_256s verify_slh_dsa_sha2_256f
  ].freeze

  describe 'rejection of obviously invalid signatures (was the mock bug)' do
    # Core TDD guard: the mocked impl returned true for every one of these.
    # A real verifier must return false.
    ALL_METHODS.each do |m|
      it "#{m} returns false for short-hex garbage" do
        expect(ctx.send(m, 'a', 'b', 'c')).to be false
      end

      it "#{m} returns false when pk is the wrong length" do
        expect(ctx.send(m, '00' * 32, '00' * 100, '00' * 2)).to be false
      end

      it "#{m} returns false for a signature of plausible but wrong length" do
        # pk of the right length but sig is all zeros
        # e.g. verify_slh_dsa_sha2_128s -> :sha2_128s
        param_key = m.to_s.sub('verify_slh_dsa_', '').to_sym
        params = Runar::SLHDSA::PARAM_SETS[param_key]
        pk_hex = '00' * (2 * params[:n])
        expect(ctx.send(m, '00' * 32, '00' * 10, pk_hex)).to be false
      end
    end
  end

  describe 'round-trip: sign-then-verify using SLH-DSA-SHA2-128f' do
    # This is the fastest parameter set — ~0.5s for a full keygen + sign + verify
    # in pure Ruby. Don't try 's' variants here; they take a minute each.

    let(:params) { Runar::SLHDSA::PARAM_SETS[:sha2_128f] }
    let(:seed_hex) do
      # 3 * n = 48 bytes
      '42' * (3 * params[:n])
    end
    let(:msg_hex) { '68656c6c6f20534c482d445341' } # "hello SLH-DSA"

    it 'accepts a signature it produced' do
      kp = Runar::SLHDSA.keygen(params, seed_hex)
      sig = Runar::SLHDSA.sign(params, msg_hex, kp[:sk])
      expect(ctx.verify_slh_dsa_sha2_128f(msg_hex, sig, kp[:pk])).to be true
    end

    it 'rejects a tampered message' do
      kp = Runar::SLHDSA.keygen(params, seed_hex)
      sig = Runar::SLHDSA.sign(params, msg_hex, kp[:sk])
      # flip the first byte of the message
      tampered_hex = (msg_hex[0, 2].to_i(16) ^ 0xff).to_s(16).rjust(2, '0') + msg_hex[2..]
      expect(ctx.verify_slh_dsa_sha2_128f(tampered_hex, sig, kp[:pk])).to be false
    end

    it 'rejects a signature verified under a different public key' do
      kp1 = Runar::SLHDSA.keygen(params, seed_hex)
      kp2 = Runar::SLHDSA.keygen(params, '01' * (3 * params[:n]))
      sig = Runar::SLHDSA.sign(params, msg_hex, kp1[:sk])
      expect(ctx.verify_slh_dsa_sha2_128f(msg_hex, sig, kp2[:pk])).to be false
    end

    it 'rejects a signature with a flipped byte' do
      kp = Runar::SLHDSA.keygen(params, seed_hex)
      sig = Runar::SLHDSA.sign(params, msg_hex, kp[:sk])
      # Flip the first byte of the signature
      bad_sig = (sig[0, 2].to_i(16) ^ 0xff).to_s(16).rjust(2, '0') + sig[2..]
      expect(ctx.verify_slh_dsa_sha2_128f(msg_hex, bad_sig, kp[:pk])).to be false
    end
  end
end

RSpec.describe Runar::SLHDSA do
  describe '.PARAM_SETS' do
    it 'defines all 6 SHA-2 parameter sets with the expected n values' do
      expect(described_class::PARAM_SETS[:sha2_128s][:n]).to eq(16)
      expect(described_class::PARAM_SETS[:sha2_128f][:n]).to eq(16)
      expect(described_class::PARAM_SETS[:sha2_192s][:n]).to eq(24)
      expect(described_class::PARAM_SETS[:sha2_192f][:n]).to eq(24)
      expect(described_class::PARAM_SETS[:sha2_256s][:n]).to eq(32)
      expect(described_class::PARAM_SETS[:sha2_256f][:n]).to eq(32)
    end

    it 'computes the correct WOTS chain count (len) per FIPS 205' do
      # For w=16, len = 2*n + 3
      expect(described_class::PARAM_SETS[:sha2_128s][:len]).to eq(35)
      expect(described_class::PARAM_SETS[:sha2_192s][:len]).to eq(51)
      expect(described_class::PARAM_SETS[:sha2_256s][:len]).to eq(67)
    end
  end

  describe 'keygen produces correct sizes' do
    it 'sk is 4*n bytes and pk is 2*n bytes' do
      params = described_class::PARAM_SETS[:sha2_128f]
      kp = described_class.keygen(params, '42' * (3 * params[:n]))
      expect(kp[:sk].length).to eq(4 * params[:n] * 2) # hex chars
      expect(kp[:pk].length).to eq(2 * params[:n] * 2) # hex chars
      # pk should be the last 2n bytes of sk
      expect(kp[:pk]).to eq(kp[:sk][2 * params[:n] * 2, 2 * params[:n] * 2])
    end
  end
end
