# frozen_string_literal: true

require 'spec_helper'

# Test vectors:
#
# Modulus n = 209 (= 11 * 19, both primes ≡ 3 mod 4)
# Message: "hello" (hex: 68656c6c6f)
# SHA256("hello") as unsigned LE integer mod 209 = 100
#
# Valid vector (padding = 0):
#   sig_int = 10  because 10^2 mod 209 = 100
#   sig_hex (4-byte LE)     = "0a000000"
#   padding_hex (4-byte LE) = "00000000"
#   pubkey_hex (4-byte LE)  = "d1000000"

MSG_HEX     = '68656c6c6f'
SIG_HEX     = '0a000000'
PADDING_HEX = '00000000'
PUBKEY_HEX  = 'd1000000'

RSpec.describe Runar::RabinSig do
  describe '.rabin_verify' do
    context 'with a valid signature' do
      it 'returns true' do
        expect(described_class.rabin_verify(MSG_HEX, SIG_HEX, PADDING_HEX, PUBKEY_HEX)).to be true
      end
    end

    context 'with an invalid signature' do
      it 'returns false when sig is wrong' do
        # sig_int = 11, 11^2 mod 209 = 121 != 100
        bad_sig = '0b000000'
        expect(described_class.rabin_verify(MSG_HEX, bad_sig, PADDING_HEX, PUBKEY_HEX)).to be false
      end

      it 'returns false when pubkey is zero' do
        zero_pubkey = '00000000'
        expect(described_class.rabin_verify(MSG_HEX, SIG_HEX, PADDING_HEX, zero_pubkey)).to be false
      end

      it 'returns false when msg is tampered' do
        # Change one byte of the message
        tampered_msg = '68656c6c6e' # last byte: 'o' -> 'n'
        expect(described_class.rabin_verify(tampered_msg, SIG_HEX, PADDING_HEX, PUBKEY_HEX)).to be false
      end
    end

    context 'with non-zero padding' do
      # Use sig_int = 0: 0^2 = 0; we need padding ≡ 100 (mod 209).
      # padding = 100 in 4-byte LE = "64000000"
      it 'returns true when sig^2 + padding matches hash' do
        sig_zero    = '00000000'
        padding_100 = '64000000'
        expect(described_class.rabin_verify(MSG_HEX, sig_zero, padding_100, PUBKEY_HEX)).to be true
      end

      it 'returns false when padding is wrong' do
        sig_zero     = '00000000'
        wrong_padding = '65000000' # 101, not 100
        expect(described_class.rabin_verify(MSG_HEX, sig_zero, wrong_padding, PUBKEY_HEX)).to be false
      end
    end

    context 'edge cases' do
      it 'returns false for an empty (zero-byte) pubkey' do
        expect(described_class.rabin_verify(MSG_HEX, SIG_HEX, PADDING_HEX, '')).to be false
      end

      it 'handles a large modulus without overflow (Ruby arbitrary-precision integers)' do
        # Use a large prime product; just verify the equation holds
        # n = a 256-bit number; Ruby Integer handles this natively
        large_n = (2**128 - 159) * (2**64 - 59)
        large_n_le_hex = large_n.to_s(16).rjust(52 * 2, '0').scan(/../).reverse.join
        # sig = 1, padding = 0: lhs = 1; rhs = SHA256(msg) % large_n (almost certainly != 1)
        sig_one = '01' + '00' * 3
        expect(described_class.rabin_verify(MSG_HEX, sig_one, '00000000', large_n_le_hex)).to be false
      end
    end
  end
end
