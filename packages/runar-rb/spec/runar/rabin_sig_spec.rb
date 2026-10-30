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

    context 'padding bound (mirrors on-chain OP_WITHIN 0..65536)' do
      # Universal forgery: set sig = 0 and padding = SHA256(msg). Then
      # (0^2 + SHA256(msg)) mod n == SHA256(msg) mod n is trivially true for
      # ANY message/key. The on-chain script rejects this via OP_WITHIN, and so
      # must the off-chain verifier. SHA256(msg) as an LE integer is ~256 bits,
      # far above the 65536 limit.
      it 'rejects the sig=0 / padding=SHA256(msg) forgery' do
        sig_zero = '00000000'
        # SHA256("hello") bytes, as the LE-interpreted padding integer.
        forged_padding = Digest::SHA256.digest(['68656c6c6f'].pack('H*')).unpack1('H*')
        expect(described_class.rabin_verify(MSG_HEX, sig_zero, forged_padding, PUBKEY_HEX)).to be false
      end

      it 'still accepts an honest signature with in-bounds padding' do
        # Same valid vector as above: sig_int = 10, padding = 0, n = 209.
        expect(described_class.rabin_verify(MSG_HEX, SIG_HEX, PADDING_HEX, PUBKEY_HEX)).to be true
      end
    end

    # N-380 (F-368 follow-up): the script asserts sig < n, so sig + k*n aborts on
    # chain. Proves: sig = 10 and the second root n - sig = 199 verify; sig + n
    # (219) and sig + 2n (428) with the same padding are rejected. Does not prove
    # the verdict equals the consensus interpreter's (conformance/negatives/f368).
    context 'with a non-canonical sig >= n (N-380)' do
      it 'accepts the canonical sig and the second root n - sig' do
        expect(described_class.rabin_verify(MSG_HEX, SIG_HEX, PADDING_HEX, PUBKEY_HEX)).to be true
        expect(described_class.rabin_verify(MSG_HEX, 'c7000000', PADDING_HEX, PUBKEY_HEX)).to be true
      end

      it 'rejects sig + n and sig + 2n' do
        expect(described_class.rabin_verify(MSG_HEX, 'db000000', PADDING_HEX, PUBKEY_HEX)).to be false
        expect(described_class.rabin_verify(MSG_HEX, 'ac010000', PADDING_HEX, PUBKEY_HEX)).to be false
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
