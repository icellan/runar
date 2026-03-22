# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Runar::Builtins do
  # Create a test harness that includes the builtins
  let(:ctx) { Object.new.extend(Runar::Builtins) }

  describe 'real ECDSA verification' do
    it 'check_sig returns true for ALICE real sig and pub_key' do
      sig = Runar::TestKeys::ALICE.test_sig
      pk  = Runar::TestKeys::ALICE.pub_key
      expect(ctx.check_sig(sig, pk)).to be true
    end

    it 'check_sig returns false for fabricated sig and pub_key' do
      expect(ctx.check_sig('aa', 'bb')).to be false
    end

    it 'check_multi_sig returns true for empty sig/pk lists' do
      expect(ctx.check_multi_sig([], [])).to be true
    end

    it 'check_multi_sig returns true when all sigs verify in order' do
      alice_sig = Runar::TestKeys::ALICE.test_sig
      alice_pk  = Runar::TestKeys::ALICE.pub_key
      bob_sig   = Runar::TestKeys::BOB.test_sig
      bob_pk    = Runar::TestKeys::BOB.pub_key
      expect(ctx.check_multi_sig([alice_sig, bob_sig], [alice_pk, bob_pk])).to be true
    end

    it 'check_multi_sig returns false when more sigs than pks' do
      alice_sig = Runar::TestKeys::ALICE.test_sig
      alice_pk  = Runar::TestKeys::ALICE.pub_key
      expect(ctx.check_multi_sig([alice_sig, alice_sig], [alice_pk])).to be false
    end

    it 'check_multi_sig allows a subset of pks to be unused' do
      alice_sig = Runar::TestKeys::ALICE.test_sig
      alice_pk  = Runar::TestKeys::ALICE.pub_key
      bob_pk    = Runar::TestKeys::BOB.pub_key
      # Alice's sig matches the first pk; bob_pk is unused — still valid
      expect(ctx.check_multi_sig([alice_sig], [alice_pk, bob_pk])).to be true
    end

    it 'check_preimage returns true' do
      expect(ctx.check_preimage('00')).to be true
    end

    it 'verify_rabin_sig returns false for arbitrary invalid inputs' do
      expect(ctx.verify_rabin_sig('a', 'b', 'c', 'd')).to be false
    end

    it 'verify_wots returns true' do
      expect(ctx.verify_wots('a', 'b', 'c')).to be true
    end

    it 'SLH-DSA variants all return true' do
      %i[
        verify_slh_dsa_sha2_128s verify_slh_dsa_sha2_128f
        verify_slh_dsa_sha2_192s verify_slh_dsa_sha2_192f
        verify_slh_dsa_sha2_256s verify_slh_dsa_sha2_256f
      ].each do |method|
        expect(ctx.send(method, 'a', 'b', 'c')).to be true
      end
    end

    it 'blake3_compress returns 64-char hex string of zeros' do
      result = ctx.blake3_compress('00' * 32, '00' * 64)
      expect(result).to eq('00' * 32)
      expect(result.length).to eq(64)
    end

    it 'blake3_compress accepts arbitrary hex input' do
      result = ctx.blake3_compress('ab' * 32, 'cd' * 64)
      expect(result).to eq('00' * 32)
    end

    it 'blake3_hash returns 64-char hex string of zeros' do
      result = ctx.blake3_hash('deadbeef')
      expect(result).to eq('00' * 32)
      expect(result.length).to eq(64)
    end

    it 'blake3_hash accepts arbitrary hex input' do
      result = ctx.blake3_hash('ff' * 64)
      expect(result).to eq('00' * 32)
    end
  end

  describe 'hash functions' do
    it 'sha256 produces correct output for known input' do
      # SHA256 of empty string
      result = ctx.sha256('')
      expect(result).to eq('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    end

    it 'sha256 operates on hex-encoded input' do
      # SHA256 of the single byte 0xAB
      result = ctx.sha256('ab')
      expect(result.length).to eq(64) # 32 bytes = 64 hex chars
    end

    it 'ripemd160 produces correct output' do
      # RIPEMD160 of empty string
      result = ctx.ripemd160('')
      expect(result).to eq('9c1185a5c5e9fc54612808977ee8f548b2258d31')
    end

    it 'hash160 computes RIPEMD160(SHA256(data))' do
      # hash160 of empty data
      sha_empty = ctx.sha256('')
      expected = ctx.ripemd160(sha_empty)
      expect(ctx.hash160('')).to eq(expected)
    end

    it 'hash256 computes SHA256(SHA256(data))' do
      sha_empty = ctx.sha256('')
      expected = ctx.sha256(sha_empty)
      expect(ctx.hash256('')).to eq(expected)
    end
  end

  describe 'math functions' do
    it 'safediv truncates toward zero' do
      expect(ctx.safediv(7, 2)).to eq(3)
      expect(ctx.safediv(-7, 2)).to eq(-3)
      expect(ctx.safediv(7, -2)).to eq(-3)
      expect(ctx.safediv(0, 5)).to eq(0)
      expect(ctx.safediv(5, 0)).to eq(0)
    end

    it 'safemod matches Bitcoin Script behaviour' do
      expect(ctx.safemod(7, 3)).to eq(1)
      expect(ctx.safemod(-7, 3)).to eq(-1)
      expect(ctx.safemod(7, 0)).to eq(0)
    end

    it 'clamp constrains values' do
      expect(ctx.clamp(5, 0, 10)).to eq(5)
      expect(ctx.clamp(-1, 0, 10)).to eq(0)
      expect(ctx.clamp(15, 0, 10)).to eq(10)
    end

    it 'sign_ returns -1, 0, or 1' do
      expect(ctx.sign_(5)).to eq(1)
      expect(ctx.sign_(0)).to eq(0)
      expect(ctx.sign_(-3)).to eq(-1)
    end

    it 'pow_ computes exponentiation' do
      expect(ctx.pow_(2, 10)).to eq(1024)
    end

    it 'sqrt_ computes integer square root' do
      expect(ctx.sqrt_(0)).to eq(0)
      expect(ctx.sqrt_(1)).to eq(1)
      expect(ctx.sqrt_(4)).to eq(2)
      expect(ctx.sqrt_(10)).to eq(3)
    end

    it 'gcd_ computes greatest common divisor' do
      expect(ctx.gcd_(12, 8)).to eq(4)
      expect(ctx.gcd_(-12, 8)).to eq(4)
    end

    it 'within checks half-open range' do
      expect(ctx.within(5, 0, 10)).to be true
      expect(ctx.within(10, 0, 10)).to be false
      expect(ctx.within(-1, 0, 10)).to be false
    end

    it 'bool_cast returns true for non-zero' do
      expect(ctx.bool_cast(1)).to be true
      expect(ctx.bool_cast(0)).to be false
      expect(ctx.bool_cast(-1)).to be true
    end
  end

  describe 'num2bin / bin2num' do
    it 'round-trips positive integers' do
      hex = ctx.num2bin(42, 4)
      expect(ctx.bin2num(hex)).to eq(42)
    end

    it 'round-trips negative integers' do
      hex = ctx.num2bin(-42, 4)
      expect(ctx.bin2num(hex)).to eq(-42)
    end

    it 'round-trips zero' do
      hex = ctx.num2bin(0, 4)
      expect(ctx.bin2num(hex)).to eq(0)
    end

    it 'produces correct byte length' do
      hex = ctx.num2bin(1, 8)
      expect(hex.length).to eq(16) # 8 bytes = 16 hex chars
    end

    it 'encodes in little-endian format' do
      # 256 = 0x0100 in big-endian = 0x0001 in little-endian
      hex = ctx.num2bin(256, 2)
      expect(hex).to eq('0001')
    end

    # Edge cases for sign-bit handling (Bitcoin Script number encoding).
    # The sign bit always lives in the MSB of the last byte.

    it 'num2bin(0, 1) produces a single zero byte' do
      expect(ctx.num2bin(0, 1)).to eq('00')
    end

    it 'num2bin(1, 1) produces 01' do
      expect(ctx.num2bin(1, 1)).to eq('01')
    end

    it 'num2bin(-1, 1) sets the sign bit in the only byte' do
      # 1 with sign bit set in the sole byte: 0x81
      expect(ctx.num2bin(-1, 1)).to eq('81')
    end

    it 'num2bin(-1, 2) pads correctly with sign-bit in last byte' do
      # -1 in 2 bytes: magnitude byte 0x01, sign-only byte 0x80
      expect(ctx.num2bin(-1, 2)).to eq('0180')
    end

    it 'num2bin(127, 1) encodes the largest positive 1-byte value' do
      # 0x7F -- MSB is 0, so no extra byte needed
      expect(ctx.num2bin(127, 1)).to eq('7f')
    end

    it 'num2bin(128, 2) requires a second byte to avoid sign-bit collision' do
      # 0x80 would collide with the sign bit in a single byte, so: 0x80 0x00
      expect(ctx.num2bin(128, 2)).to eq('8000')
    end

    it 'num2bin(-128, 2) sets sign bit on the extra byte' do
      # magnitude 0x80 needs its own byte; sign byte becomes 0x80 => 0x80 0x80
      expect(ctx.num2bin(-128, 2)).to eq('8080')
    end

    it 'num2bin(-128, 3) pads to requested length with sign bit in last byte' do
      # magnitude 0x80, one zero pad byte, sign-only last byte 0x80
      expect(ctx.num2bin(-128, 3)).to eq('800080')
    end

    it 'num2bin(255, 2) encodes 0xFF with a zero sign byte' do
      # 0xFF needs sign-bit space: 0xFF 0x00
      expect(ctx.num2bin(255, 2)).to eq('ff00')
    end

    it 'num2bin(-255, 2) encodes 0xFF with sign bit in last byte' do
      # 0xFF magnitude, sign bit set in last byte: 0xFF 0x80
      expect(ctx.num2bin(-255, 2)).to eq('ff80')
    end

    it 'num2bin(0, 4) pads zero to requested length' do
      expect(ctx.num2bin(0, 4)).to eq('00000000')
    end

    it 'num2bin(127, 3) pads positive 1-byte value with zero bytes' do
      expect(ctx.num2bin(127, 3)).to eq('7f0000')
    end
  end

  describe 'byte operations' do
    it 'len_ returns byte length of hex string' do
      expect(ctx.len_('aabb')).to eq(2)
      expect(ctx.len_('aabbcc')).to eq(3)
    end

    it 'cat concatenates hex strings' do
      expect(ctx.cat('aabb', 'ccdd')).to eq('aabbccdd')
    end

    it 'substr extracts byte range from hex string' do
      expect(ctx.substr('aabbccdd', 1, 2)).to eq('bbcc')
    end

    it 'left returns leftmost bytes' do
      expect(ctx.left('aabbccdd', 2)).to eq('aabb')
    end

    it 'right returns rightmost bytes' do
      expect(ctx.right('aabbccdd', 2)).to eq('ccdd')
    end

    it 'reverse_bytes reverses byte order' do
      expect(ctx.reverse_bytes('aabbccdd')).to eq('ddccbbaa')
    end
  end

  describe 'preimage extraction' do
    it 'extract_output_hash returns first 32 bytes when preimage is long enough' do
      # hash256 produces 32 bytes (64 hex chars) -- long enough to extract from
      preimage = ctx.hash256('deadbeef')
      result = ctx.extract_output_hash(preimage)
      expect(result.length).to eq(64)
      expect(result).to eq(preimage[0, 64])
    end

    it 'extract_output_hash returns 32 zero bytes when preimage is too short' do
      expect(ctx.extract_output_hash('')).to eq('00' * 32)
      expect(ctx.extract_output_hash('aabb')).to eq('00' * 32) # 2 bytes = too short
    end

    it 'extract_output_hash handles nil by treating it as empty string' do
      expect(ctx.extract_output_hash(nil)).to eq('00' * 32)
    end

    it 'extract_hash_prevouts returns hash256 of 72 zero bytes' do
      expected = ctx.hash256('00' * 72)
      expect(ctx.extract_hash_prevouts('anything')).to eq(expected)
      expect(ctx.extract_hash_prevouts('').length).to eq(64)
    end

    it 'extract_outpoint returns 36 zero bytes as hex' do
      result = ctx.extract_outpoint('anything')
      expect(result).to eq('00' * 36)
      expect(result.length).to eq(72) # 36 bytes = 72 hex chars
    end
  end

  describe 'assert' do
    it 'passes on truthy values' do
      expect { ctx.assert(true) }.not_to raise_error
      expect { ctx.assert(1) }.not_to raise_error
    end

    it 'raises on falsey values' do
      expect { ctx.assert(false) }.to raise_error(RuntimeError, 'runar: assertion failed')
      expect { ctx.assert(nil) }.to raise_error(RuntimeError, 'runar: assertion failed')
    end
  end

  describe 'test helpers' do
    it 'mock_sig returns ALICE real DER signature as hex' do
      sig = ctx.mock_sig
      expect(sig).to eq(Runar::TestKeys::ALICE.test_sig)
      expect(sig[0, 2]).to eq('30') # DER sequence tag
    end

    it 'mock_pub_key returns ALICE real compressed pub key as hex' do
      pk = ctx.mock_pub_key
      expect(pk).to eq(Runar::TestKeys::ALICE.pub_key)
      expect(pk.length).to eq(66) # 33 bytes = 66 hex chars
      expect(%w[02 03]).to include(pk[0, 2])
    end

    it 'check_sig(mock_sig, mock_pub_key) returns true' do
      expect(ctx.check_sig(ctx.mock_sig, ctx.mock_pub_key)).to be true
    end

    it 'mock_preimage returns 181 zero bytes as hex' do
      pre = ctx.mock_preimage
      expect(pre.length).to eq(362)
    end
  end
end
