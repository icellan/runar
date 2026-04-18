# frozen_string_literal: true

require 'spec_helper'

# These specs exercise the real WOTS+ verifier exposed through
# Runar::Builtins#verify_wots. They start from the observation that the
# mocked implementation returned true for _every_ input, including obvious
# garbage. A real verifier must reject invalid signatures.

RSpec.describe 'WOTS+ verification via Runar::Builtins#verify_wots' do
  let(:ctx) { Object.new.extend(Runar::Builtins) }

  # Seed material for deterministic keygen across the suite.
  let(:seed)     { '42' * 32 } # 32 bytes
  let(:pub_seed) { '13' * 32 } # 32 bytes

  # Generate a keypair + sig via the pure-Ruby WOTS reference, using hex I/O
  # to match the Builtins interface.
  def make_sig(msg_hex, seed_hex, pub_seed_hex)
    kp = Runar::WOTS.keygen(seed_hex: seed_hex, pub_seed_hex: pub_seed_hex)
    sig = Runar::WOTS.sign(msg_hex, kp[:sk], kp[:pub_seed])
    [sig, kp[:pk]]
  end

  describe 'with a valid signature' do
    it 'accepts a sig signed for the given message/pubkey' do
      msg = 'deadbeef'
      sig, pk = make_sig(msg, seed, pub_seed)
      expect(ctx.verify_wots(msg, sig, pk)).to be true
    end
  end

  describe 'with invalid inputs' do
    # This is the core TDD guard: the mocked implementation returned true
    # here. The real implementation must return false.
    it 'rejects arbitrary short-hex garbage (was the mock bug)' do
      expect(ctx.verify_wots('a', 'b', 'c')).to be false
    end

    it 'rejects a signature verified against a different message' do
      msg       = 'deadbeef'
      other_msg = 'cafebabe'
      sig, pk   = make_sig(msg, seed, pub_seed)
      expect(ctx.verify_wots(other_msg, sig, pk)).to be false
    end

    it 'rejects a signature with a flipped byte' do
      msg     = 'deadbeef'
      sig, pk = make_sig(msg, seed, pub_seed)
      # Flip the top nibble of the first byte of the signature.
      bad_sig = (sig[0].to_i(16) ^ 0xf).to_s(16).rjust(1, '0') + sig[1..]
      expect(ctx.verify_wots(msg, bad_sig, pk)).to be false
    end

    it 'rejects a signature against a different keypair' do
      msg      = 'deadbeef'
      sig, _pk = make_sig(msg, seed, pub_seed)
      _sig2, pk2 = make_sig(msg, 'aa' * 32, 'bb' * 32)
      expect(ctx.verify_wots(msg, sig, pk2)).to be false
    end

    it 'rejects a signature of the wrong length' do
      msg     = 'deadbeef'
      _sig, pk = make_sig(msg, seed, pub_seed)
      expect(ctx.verify_wots(msg, '00' * 100, pk)).to be false
    end

    it 'rejects a public key of the wrong length' do
      msg     = 'deadbeef'
      sig, _pk = make_sig(msg, seed, pub_seed)
      expect(ctx.verify_wots(msg, sig, '00' * 32)).to be false
    end
  end
end

RSpec.describe Runar::WOTS do
  describe '.keygen' do
    it 'is deterministic when given the same seeds' do
      kp1 = described_class.keygen(seed_hex: '01' * 32, pub_seed_hex: '02' * 32)
      kp2 = described_class.keygen(seed_hex: '01' * 32, pub_seed_hex: '02' * 32)
      expect(kp1[:sk]).to eq(kp2[:sk])
      expect(kp1[:pk]).to eq(kp2[:pk])
      expect(kp1[:pub_seed]).to eq(kp2[:pub_seed])
    end

    it 'produces the expected sizes' do
      kp = described_class.keygen(seed_hex: '01' * 32, pub_seed_hex: '02' * 32)
      expect(kp[:sk].length).to eq(67)
      kp[:sk].each { |elem| expect(elem.length).to eq(64) } # 32 bytes = 64 hex chars
      expect(kp[:pk].length).to eq(128)                      # 64 bytes
      expect(kp[:pub_seed].length).to eq(64)                 # 32 bytes
    end

    it 'places pub_seed at the start of pk' do
      kp = described_class.keygen(seed_hex: '01' * 32, pub_seed_hex: '02' * 32)
      expect(kp[:pk][0, 64]).to eq(kp[:pub_seed])
    end
  end

  describe '.sign / .verify round-trip' do
    it 'produces a signature that verifies' do
      kp = described_class.keygen(seed_hex: '42' * 32, pub_seed_hex: '13' * 32)
      sig = described_class.sign('68656c6c6f', kp[:sk], kp[:pub_seed]) # "hello" hex
      expect(sig.length).to eq(67 * 64) # 67 chains * 32 bytes * 2 hex chars
      expect(described_class.verify('68656c6c6f', sig, kp[:pk])).to be true
    end
  end

  describe 'helper: digit extraction + checksum' do
    it 'extract_digits produces 64 nibbles from a 32-byte hash' do
      digits = described_class.send(:extract_digits, '00' * 32)
      expect(digits.length).to eq(64)
      expect(digits).to all(eq(0))
    end

    it 'checksum_digits for all-zero message digits' do
      msg_digits = Array.new(64, 0)
      # total = 64 * 15 = 960; base-16 digits (MSB first): 960 = 3*256 + C*16 + 0
      expect(described_class.send(:checksum_digits, msg_digits)).to eq([3, 12, 0])
    end
  end
end
