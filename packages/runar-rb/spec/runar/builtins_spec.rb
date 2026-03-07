# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Runar::Builtins do
  # Create a test harness that includes the builtins
  let(:ctx) { Object.new.extend(Runar::Builtins) }

  describe 'mock crypto' do
    it 'check_sig returns true' do
      expect(ctx.check_sig('aa', 'bb')).to be true
    end

    it 'check_multi_sig returns true' do
      expect(ctx.check_multi_sig([], [])).to be true
    end

    it 'check_preimage returns true' do
      expect(ctx.check_preimage('00')).to be true
    end

    it 'verify_rabin_sig returns true' do
      expect(ctx.verify_rabin_sig('a', 'b', 'c', 'd')).to be true
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
    it 'mock_sig returns 72 zero bytes as hex' do
      sig = ctx.mock_sig
      expect(sig.length).to eq(144)
      expect(sig).to eq('00' * 72)
    end

    it 'mock_pub_key returns 33 bytes with 02 prefix as hex' do
      pk = ctx.mock_pub_key
      expect(pk.length).to eq(66)
      expect(pk[0, 2]).to eq('02')
    end

    it 'mock_preimage returns 181 zero bytes as hex' do
      pre = ctx.mock_preimage
      expect(pre.length).to eq(362)
    end
  end
end
