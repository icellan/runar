# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'runar/ecdsa'

RSpec.describe Runar::SDK::LocalSigner do
  # Well-known test key: private key = 1 (public key = G).
  # G compressed: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  KEY_ONE_HEX = '0000000000000000000000000000000000000000000000000000000000000001'.freeze
  G_COMPRESSED_HEX = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'.freeze
  # Mainnet P2PKH address for the *compressed* public key of priv key 1
  # (HASH160 = 751e76e8199196d454941c45d1b3a323f1433bd6).
  KEY_ONE_ADDRESS = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'.freeze

  # ---------------------------------------------------------------------------
  # When neither bsv-sdk nor the pure-Ruby fallback is usable
  # ---------------------------------------------------------------------------
  context 'when no signing backend is available' do
    before do
      stub_const('Runar::SDK::LocalSigner::BSV_SDK_AVAILABLE', false)
      stub_const('Runar::SDK::LocalSigner::FALLBACK_AVAILABLE', false)
    end

    it 'raises RuntimeError on instantiation' do
      expect { described_class.new(KEY_ONE_HEX) }
        .to raise_error(RuntimeError, /no signing backend/)
    end

    it 'includes an installation hint in the error message' do
      expect { described_class.new(KEY_ONE_HEX) }
        .to raise_error(RuntimeError, /bsv-sdk/)
    end
  end

  # ---------------------------------------------------------------------------
  # Pure-Ruby fallback path — always exercised (no optional dependencies)
  # ---------------------------------------------------------------------------
  context 'when only the pure-Ruby fallback is available' do
    before do
      # Force the fallback path even if bsv-sdk happens to be installed.
      stub_const('Runar::SDK::LocalSigner::BSV_SDK_AVAILABLE', false)
    end

    subject(:signer) { described_class.new(KEY_ONE_HEX) }

    it 'is a Runar::SDK::Signer' do
      expect(signer).to be_a(Runar::SDK::Signer)
    end

    describe '#get_public_key' do
      it 'returns a 66-character hex string' do
        expect(signer.get_public_key).to match(/\A[0-9a-f]{66}\z/)
      end

      it 'returns the compressed secp256k1 generator point for key=1' do
        expect(signer.get_public_key).to eq(G_COMPRESSED_HEX)
      end
    end

    describe '#get_address' do
      it 'returns the canonical mainnet P2PKH address for key=1' do
        expect(signer.get_address).to eq(KEY_ONE_ADDRESS)
      end

      it 'starts with a 1 (mainnet P2PKH version byte)' do
        expect(signer.get_address).to start_with('1')
      end
    end

    describe '#sign' do
      # Minimal 1-in 1-out transaction for signing tests
      # (same fixture as oppushtx_spec).
      let(:tx_hex) do
        '0100000001' \
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
          '00000000' \
          '00' \
          'ffffffff' \
          '01' \
          '50c3000000000000' \
          '19' \
          '76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac' \
          '00000000'
      end

      let(:subscript) { '76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac' }
      let(:satoshis)  { 50_000 }

      subject(:sig) { signer.sign(tx_hex, 0, subscript, satoshis) }

      it 'returns a hex string' do
        expect(sig).to be_a(String)
        expect(sig).to match(/\A[0-9a-f]+\z/)
      end

      it 'starts with the DER SEQUENCE tag (30)' do
        expect(sig[0, 2]).to eq('30')
      end

      it 'ends with the SIGHASH_ALL|FORKID byte (41)' do
        expect(sig[-2..]).to eq('41')
      end

      it 'has a plausible length (140-148 hex chars for DER + hashtype)' do
        expect(sig.length).to be_between(140, 148)
      end

      it 'is deterministic for the same inputs (RFC-6979)' do
        a = signer.sign(tx_hex, 0, subscript, satoshis)
        b = signer.sign(tx_hex, 0, subscript, satoshis)
        expect(a).to eq(b)
      end

      it 'produces different signatures for different satoshi values' do
        sig1 = signer.sign(tx_hex, 0, subscript, satoshis)
        sig2 = signer.sign(tx_hex, 0, subscript, satoshis + 1)
        expect(sig1).not_to eq(sig2)
      end

      it 'produces a low-S, valid ECDSA signature over the BIP-143 sighash' do
        # Recompute the BIP-143 digest, parse the DER signature, and verify
        # against the signer's public key.  This proves the signature is real
        # cryptography rather than a stub.
        flag = Runar::SDK::LocalSigner::SIGHASH_ALL_FORKID
        parsed = Runar::SDK::BIP143.parse_raw_tx([tx_hex].pack('H*'))
        digest = Runar::SDK::BIP143.bip143_sighash(
          parsed, 0, [subscript].pack('H*'), satoshis, flag
        )
        digest_hex = digest.unpack1('H*')

        # Strip trailing sighash byte (last 2 hex chars) before verifying.
        der_hex = sig[0..-3]
        expect(Runar::ECDSA.verify(digest_hex, der_hex, signer.get_public_key))
          .to be true

        # BIP-62 low-S
        _r, s = Runar::ECDSA.parse_der_signature(der_hex)
        expect(s).to be <= (Runar::ECDSA::CURVE_N >> 1)
      end
    end

    describe 'private key validation' do
      it 'rejects keys that are the wrong length' do
        expect { described_class.new('00' * 31) }
          .to raise_error(ArgumentError, /64-char/)
      end

      it 'rejects non-hex characters' do
        expect { described_class.new('zz' + ('00' * 31)) }
          .to raise_error(ArgumentError, /non-hex/)
      end

      it 'rejects the zero private key' do
        expect { described_class.new('00' * 32) }
          .to raise_error(ArgumentError, /out of range/)
      end

      it 'rejects private keys >= n' do
        # secp256k1 curve order n
        n_hex = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
        expect { described_class.new(n_hex) }
          .to raise_error(ArgumentError, /out of range/)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # When bsv-sdk IS available (integration path — only runs if gem installed)
  # ---------------------------------------------------------------------------
  context 'when the bsv-sdk gem is available', if: Runar::SDK::LocalSigner::BSV_SDK_AVAILABLE do
    subject(:signer) { described_class.new(KEY_ONE_HEX) }

    it 'is a Runar::SDK::Signer' do
      expect(signer).to be_a(Runar::SDK::Signer)
    end

    describe '#get_public_key' do
      it 'returns a 66-character hex string' do
        expect(signer.get_public_key).to match(/\A[0-9a-f]{66}\z/)
      end

      it 'returns the compressed secp256k1 generator point for key=1' do
        expect(signer.get_public_key).to eq(G_COMPRESSED_HEX)
      end
    end

    describe '#get_address' do
      it 'returns a non-empty P2PKH address' do
        expect(signer.get_address).to be_a(String)
        expect(signer.get_address).not_to be_empty
        expect(signer.get_address).to start_with('1')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Abstract interface contract — always verified
  # ---------------------------------------------------------------------------
  context 'class structure' do
    it 'inherits from Runar::SDK::Signer' do
      expect(described_class.superclass).to eq(Runar::SDK::Signer)
    end

    it 'defines get_public_key' do
      expect(described_class.method_defined?(:get_public_key)).to be true
    end

    it 'defines get_address' do
      expect(described_class.method_defined?(:get_address)).to be true
    end

    it 'defines sign' do
      expect(described_class.method_defined?(:sign)).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # BIP-62 low-S enforcement (uses the pure-Ruby ECDSA implementation)
  # ---------------------------------------------------------------------------
  describe 'BIP-62 low-S enforcement' do
    it 'produces low-S signatures per BIP-62' do
      half_n = Runar::ECDSA::CURVE_N >> 1
      priv_key = 1  # well-known test key: private key = 1 (public key = G)

      20.times do |i|
        # Produce a distinct 32-byte message hash for each iteration
        msg_hash = ([i] + [0] * 31).pack('C*')
        der = Runar::ECDSA.ecdsa_sign(priv_key, msg_hash)

        result = Runar::ECDSA.parse_der_signature_bytes(der)
        expect(result).not_to be_nil, "iteration #{i}: could not parse DER signature"
        _r, s = result
        expect(s).to be <= half_n,
          "iteration #{i}: S value 0x#{s.to_s(16)} exceeds N/2 (BIP-62 low-S violation)"
      end
    end
  end
end
