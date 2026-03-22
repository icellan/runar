# frozen_string_literal: true

require 'spec_helper'

# Test vectors generated from the Python reference implementation (runar/ecdsa.py).
# All expected values were produced by running packages/runar-py with the same keys.
ALICE_PRIV_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
BOB_PRIV_HEX   = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'

ALICE_PUB_HEX  = '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd'
BOB_PUB_HEX    = '03d6bfe100d1600c0d8f769501676fc74c3809500bd131c8a549f88cf616c21f35'

# SHA256("runar-test-message-v1")
TEST_DIGEST_HEX = 'ee5e6c74a298854942a9eadd789f2812b38936691230134ad50b884cc1f119fa'

# Alice's deterministic (RFC 6979) signature over TEST_DIGEST with ALICE_PRIV
ALICE_SIG_HEX = '3045022100e2aa1265ce57f54b981ffc6a5f3d229e908d7772fceb75a50c8c2d6076313df0' \
                '0220607dbca2f9f695438b49eefea4e445664c740163af8b62b1373f87d50eb64417'

# High-S variant of Alice's signature (s replaced with N - s)
ALICE_HIGH_S_SIG_HEX = '3046022100e2aa1265ce57f54b981ffc6a5f3d229e908d7772fceb75a50c8c2d607631' \
                        '3df00221009f82435d06096abc74b611015b1bba986e3adb82ffbd3d8a8892d6b7c17ffd2a'

# Alice's uncompressed public key (04 || x || y)
ALICE_UNCOMPRESSED_PUB_HEX = '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd' \
                              '5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235'

# rubocop:disable Metrics/BlockLength
RSpec.describe Runar::ECDSA do
  # -------------------------------------------------------------------------
  # DER signature parsing
  # -------------------------------------------------------------------------
  describe '.parse_der_signature' do
    it 'parses a valid DER signature into [r, s]' do
      result = described_class.parse_der_signature(ALICE_SIG_HEX)
      expect(result).to be_an(Array)
      expect(result.length).to eq(2)
      expect(result[0]).to be_a(Integer)
      expect(result[1]).to be_a(Integer)
    end

    it 'returns the correct r value' do
      r, = described_class.parse_der_signature(ALICE_SIG_HEX)
      expect(r).to eq(0xe2aa1265ce57f54b981ffc6a5f3d229e908d7772fceb75a50c8c2d6076313df0)
    end

    it 'returns the correct s value' do
      _, s = described_class.parse_der_signature(ALICE_SIG_HEX)
      expect(s).to eq(0x607dbca2f9f695438b49eefea4e445664c740163af8b62b1373f87d50eb64417)
    end

    it 'strips a trailing sighash byte (Bitcoin OP_CHECKSIG convention)' do
      sig_with_sighash = "#{ALICE_SIG_HEX}41"
      result = described_class.parse_der_signature(sig_with_sighash)
      expect(result).not_to be_nil
      expect(result).to eq(described_class.parse_der_signature(ALICE_SIG_HEX))
    end

    it 'returns nil for a signature that is too short' do
      expect(described_class.parse_der_signature('30060201010201')).to be_nil
    end

    it 'returns nil when the outer tag is not 0x30' do
      expect(described_class.parse_der_signature('3106020101020101')).to be_nil
    end

    it 'returns nil for an empty string' do
      expect(described_class.parse_der_signature('')).to be_nil
    end

    # --- Issue #54: zero-length r or s component ---

    it 'returns nil when r has zero length' do
      # 0x30 0x06 0x02 0x00 0x02 0x02 0x01 0x01  (8 bytes, passes minimum-length guard)
      # Sequence len=6: r-tag, r-len=0, s-tag, s-len=2, s=[0x01,0x01]
      expect(described_class.parse_der_signature('3006020002020101')).to be_nil
    end

    it 'returns nil when s has zero length' do
      # 0x30 0x06 0x02 0x02 0x01 0x01 0x02 0x00  (8 bytes, passes minimum-length guard)
      # Sequence len=6: r-tag, r-len=2, r=[0x01,0x01], s-tag, s-len=0
      expect(described_class.parse_der_signature('3006020201010200')).to be_nil
    end

    # --- Issue #55: non-minimal DER encoding ---

    it 'returns nil when r has a non-minimal leading 0x00 (high bit not set on next byte)' do
      # r = 0x0001 encoded as 02 02 00 01 — non-minimal; 02 01 01 would be correct
      # 0x30 0x07 0x02 0x02 0x00 0x01 0x02 0x01 0x01  (sequence len=7, total 9 bytes)
      expect(described_class.parse_der_signature('300702020001020101')).to be_nil
    end

    it 'returns nil when s has a non-minimal leading 0x00 (high bit not set on next byte)' do
      # s = 0x0001 encoded as 02 02 00 01 — non-minimal
      # 0x30 0x07 0x02 0x01 0x01 0x02 0x02 0x00 0x01  (sequence len=7, total 9 bytes)
      expect(described_class.parse_der_signature('300702010102020001')).to be_nil
    end

    it 'parses correctly when r has a valid leading 0x00 (high bit set on next byte)' do
      # r has high bit set so a 0x00 pad byte is required — this IS minimal/valid
      # Use a real Alice sig which has a 0x00-padded r (the 0x21-length component)
      # Alice sig r starts with 0x00 e2... where 0xe2 has high bit set — valid padding
      result = described_class.parse_der_signature(ALICE_SIG_HEX)
      expect(result).not_to be_nil
      r, = result
      expect(r).to eq(0xe2aa1265ce57f54b981ffc6a5f3d229e908d7772fceb75a50c8c2d6076313df0)
    end
  end

  # -------------------------------------------------------------------------
  # Public key decompression
  # -------------------------------------------------------------------------
  describe '.decompress_public_key' do
    it 'decompresses a 0x02-prefix compressed key to the correct (x, y)' do
      # Use a known 02-prefix key: FRANK = priv 1111...1111
      frank_priv = '1111111111111111111111111111111111111111111111111111111111111111'
      frank_pub  = described_class.pub_key_from_priv_key(frank_priv)
      expect(frank_pub[0, 2]).to eq('02').or eq('03')

      x, y = described_class.decompress_public_key(frank_pub)
      # Re-compress and compare
      prefix = y.even? ? '02' : '03'
      re_compressed = "#{prefix}#{x.to_s(16).rjust(64, '0')}"
      expect(re_compressed).to eq(frank_pub)
    end

    it 'decompresses a 0x03-prefix compressed key correctly' do
      x, y = described_class.decompress_public_key(ALICE_PUB_HEX)
      expect(ALICE_PUB_HEX[0, 2]).to eq('03')
      # y must be odd for a 03-prefix key
      expect(y).to be_odd
      expect(x.to_s(16).rjust(64, '0')).to eq(ALICE_PUB_HEX[2, 64])
    end

    it 'accepts a 0x04-prefix uncompressed key' do
      x, y = described_class.decompress_public_key(ALICE_UNCOMPRESSED_PUB_HEX)
      alice_x = ALICE_PUB_HEX[2, 64].to_i(16)
      expect(x).to eq(alice_x)
      expect(y).to be_a(Integer)
      expect(y).to be_positive
    end

    it 'raises ArgumentError for a wrong-length key' do
      expect { described_class.decompress_public_key('03aabbcc') }
        .to raise_error(ArgumentError)
    end

    it 'raises ArgumentError for an invalid prefix byte' do
      bad = "05#{ALICE_PUB_HEX[2..]}"
      expect { described_class.decompress_public_key(bad) }
        .to raise_error(ArgumentError)
    end
  end

  # -------------------------------------------------------------------------
  # Public key derivation
  # -------------------------------------------------------------------------
  describe '.pub_key_from_priv_key' do
    it "derives Alice's known public key from her private key" do
      expect(described_class.pub_key_from_priv_key(ALICE_PRIV_HEX)).to eq(ALICE_PUB_HEX)
    end

    it "derives Bob's known public key from his private key" do
      expect(described_class.pub_key_from_priv_key(BOB_PRIV_HEX)).to eq(BOB_PUB_HEX)
    end

    it 'returns a 66-character hex string (33 bytes)' do
      result = described_class.pub_key_from_priv_key(ALICE_PRIV_HEX)
      expect(result.length).to eq(66)
    end

    it 'returns a compressed key starting with 02 or 03' do
      result = described_class.pub_key_from_priv_key(ALICE_PRIV_HEX)
      expect(%w[02 03]).to include(result[0, 2])
    end
  end

  # -------------------------------------------------------------------------
  # Test message signing
  # -------------------------------------------------------------------------
  describe '.sign_test_message' do
    it 'produces a deterministic signature for Alice matching the Python SDK' do
      result = described_class.sign_test_message(ALICE_PRIV_HEX)
      expect(result).to eq(ALICE_SIG_HEX)
    end

    it 'produces a hex string starting with 30 (DER sequence tag)' do
      result = described_class.sign_test_message(ALICE_PRIV_HEX)
      expect(result[0, 2]).to eq('30')
    end

    it 'produces a low-S signature (BIP 62 normalization)' do
      n_half = Runar::ECDSA::CURVE_N / 2
      _, s = described_class.parse_der_signature(described_class.sign_test_message(ALICE_PRIV_HEX))
      expect(s).to be <= n_half
    end
  end

  # -------------------------------------------------------------------------
  # ECDSA verification
  # -------------------------------------------------------------------------
  describe '.verify' do
    it 'returns true for a valid signature' do
      expect(described_class.verify(TEST_DIGEST_HEX, ALICE_SIG_HEX, ALICE_PUB_HEX)).to be true
    end

    it 'returns false when the signature is for a different public key' do
      expect(described_class.verify(TEST_DIGEST_HEX, ALICE_SIG_HEX, BOB_PUB_HEX)).to be false
    end

    it 'returns false when the message hash is wrong' do
      wrong_hash = 'ff' * 32
      expect(described_class.verify(wrong_hash, ALICE_SIG_HEX, ALICE_PUB_HEX)).to be false
    end

    it 'accepts a signature with a trailing sighash byte' do
      sig_with_sighash = "#{ALICE_SIG_HEX}41"
      expect(described_class.verify(TEST_DIGEST_HEX, sig_with_sighash, ALICE_PUB_HEX)).to be true
    end

    it 'rejects a high-S signature (BIP-62 low-S enforcement)' do
      expect(described_class.verify(TEST_DIGEST_HEX, ALICE_HIGH_S_SIG_HEX, ALICE_PUB_HEX)).to be false
    end

    it 'accepts the original low-S signature that the high-S variant was derived from' do
      expect(described_class.verify(TEST_DIGEST_HEX, ALICE_SIG_HEX, ALICE_PUB_HEX)).to be true
    end

    it 'returns false for a malformed DER signature' do
      expect(described_class.verify(TEST_DIGEST_HEX, 'deadbeef', ALICE_PUB_HEX)).to be false
    end

    it 'returns false when r is zero' do
      # Construct a DER sig with r=0 and s=1
      zero_r_sig = described_class.encode_der_signature(0, 1).unpack1('H*')
      expect(described_class.verify(TEST_DIGEST_HEX, zero_r_sig, ALICE_PUB_HEX)).to be false
    end

    it 'returns false when s is zero' do
      zero_s_sig = described_class.encode_der_signature(1, 0).unpack1('H*')
      expect(described_class.verify(TEST_DIGEST_HEX, zero_s_sig, ALICE_PUB_HEX)).to be false
    end

    it 'returns false when r >= N' do
      r_too_large = Runar::ECDSA::CURVE_N
      sig = described_class.encode_der_signature(r_too_large, 1).unpack1('H*')
      expect(described_class.verify(TEST_DIGEST_HEX, sig, ALICE_PUB_HEX)).to be false
    end
  end

  # -------------------------------------------------------------------------
  # Round-trip: sign then verify
  # -------------------------------------------------------------------------
  describe 'sign/verify round-trip' do
    it 'signs a message and verifies it successfully' do
      sig_hex = described_class.sign_test_message(ALICE_PRIV_HEX)
      pub_hex = described_class.pub_key_from_priv_key(ALICE_PRIV_HEX)
      expect(described_class.verify(TEST_DIGEST_HEX, sig_hex, pub_hex)).to be true
    end

    it "Bob's signed message verifies with Bob's key only" do
      bob_sig_hex = described_class.sign_test_message(BOB_PRIV_HEX)
      bob_pub_hex = described_class.pub_key_from_priv_key(BOB_PRIV_HEX)
      expect(described_class.verify(TEST_DIGEST_HEX, bob_sig_hex, bob_pub_hex)).to be true
      expect(described_class.verify(TEST_DIGEST_HEX, bob_sig_hex, ALICE_PUB_HEX)).to be false
    end
  end
end
# rubocop:enable Metrics/BlockLength
