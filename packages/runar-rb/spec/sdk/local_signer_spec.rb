# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

RSpec.describe Runar::SDK::LocalSigner do
  # ---------------------------------------------------------------------------
  # When bsv-sdk is NOT available
  # ---------------------------------------------------------------------------
  context 'when the bsv-sdk gem is not installed' do
    before do
      # Temporarily force the availability flag to false so we can test the
      # error path regardless of whether the gem happens to be installed.
      stub_const('Runar::SDK::LocalSigner::BSV_SDK_AVAILABLE', false)
    end

    it 'raises RuntimeError on instantiation' do
      expect { described_class.new('00' * 32) }
        .to raise_error(RuntimeError, /bsv-sdk/)
    end

    it 'includes an installation hint in the error message' do
      expect { described_class.new('00' * 32) }
        .to raise_error(RuntimeError, /Gemfile/)
    end
  end

  # ---------------------------------------------------------------------------
  # When bsv-sdk IS available (integration path)
  # ---------------------------------------------------------------------------
  context 'when the bsv-sdk gem is available', if: Runar::SDK::LocalSigner::BSV_SDK_AVAILABLE do
    # Well-known test key: private key = 1 (public key = G).
    let(:priv_key_hex) { '0000000000000000000000000000000000000000000000000000000000000001' }

    subject(:signer) { described_class.new(priv_key_hex) }

    it 'is a Runar::SDK::Signer' do
      expect(signer).to be_a(Runar::SDK::Signer)
    end

    describe '#get_public_key' do
      it 'returns a 66-character hex string' do
        expect(signer.get_public_key).to match(/\A[0-9a-f]{66}\z/)
      end

      it 'returns the compressed secp256k1 generator point for key=1' do
        # G compressed: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        expect(signer.get_public_key).to eq('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
      end
    end

    describe '#get_address' do
      it 'returns a non-empty string' do
        expect(signer.get_address).to be_a(String)
        expect(signer.get_address).not_to be_empty
      end

      it 'returns a P2PKH-style address (starts with 1)' do
        expect(signer.get_address).to start_with('1')
      end
    end

    describe '#sign' do
      # Minimal 1-in 1-out transaction for signing tests (same fixture as oppushtx_spec).
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

      let(:subscript)  { '76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac' }
      let(:satoshis)   { 50_000 }

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

      it 'has a plausible length (142-148 hex chars for a DER signature + hashtype)' do
        expect(sig.length).to be_between(140, 148)
      end

      it 'is deterministic for the same inputs' do
        a = signer.sign(tx_hex, 0, subscript, satoshis)
        b = signer.sign(tx_hex, 0, subscript, satoshis)
        expect(a).to eq(b)
      end

      it 'produces different signatures for different satoshi values' do
        sig1 = signer.sign(tx_hex, 0, subscript, satoshis)
        sig2 = signer.sign(tx_hex, 0, subscript, satoshis + 1)
        expect(sig1).not_to eq(sig2)
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
end
