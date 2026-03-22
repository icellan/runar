# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk/oppushtx'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK OP_PUSH_TX helpers' do
  # rubocop:enable RSpec/DescribeClass

  # A minimal 1-input 1-output raw transaction built from known constants:
  #   version=1, prevTxid=aa*32, prevIndex=0, scriptSig='', sequence=0xFFFFFFFF,
  #   output: satoshis=50_000, script=P2PKH(bb*20), locktime=0
  TX_HEX = '0100000001' \
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
            '00000000' \
            '00' \
            'ffffffff' \
            '01' \
            '50c3000000000000' \
            '19' \
            '76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac' \
            '00000000'

  SUBSCRIPT_HEX = '76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac'
  SATOSHIS      = 50_000

  # Preimage and signature values cross-validated against the Python implementation.
  # rubocop:disable Layout/LineLength
  EXPECTED_PREIMAGE = '010000006324e33631b1cb491f73dac8baa476a642eaeccfc7e00c2708764468c82a4e6c3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000001976a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac50c3000000000000ffffffffc97de0223927d47bfdd14a8c9528f219136e5efa8b45004d9cd2734cdc5e4e9f0000000041000000'
  EXPECTED_SIG      = '3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022' \
                      '0510ba1fc305e216ed68632865e4d0ef395fcfa6f7b3424ce2a1789b5a75a0de841'
  # rubocop:enable Layout/LineLength

  # ---------------------------------------------------------------------------
  # double_sha256
  # ---------------------------------------------------------------------------
  describe 'double_sha256' do
    # SHA256(SHA256('')) is a well-known test vector.
    it 'produces the correct digest for an empty input' do
      result = Runar::SDK.double_sha256('')
      expect(result).to eq('5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456')
    end

    it 'returns a 64-character lowercase hex string' do
      result = Runar::SDK.double_sha256('deadbeef')
      expect(result).to match(/\A[0-9a-f]{64}\z/)
    end

    it 'is deterministic for the same input' do
      a = Runar::SDK.double_sha256('abc')
      b = Runar::SDK.double_sha256('abc')
      expect(a).to eq(b)
    end

    it 'produces different output for different inputs' do
      a = Runar::SDK.double_sha256('abc')
      b = Runar::SDK.double_sha256('abd')
      expect(a).not_to eq(b)
    end
  end

  # ---------------------------------------------------------------------------
  # compute_preimage
  # ---------------------------------------------------------------------------
  describe 'compute_preimage' do
    subject(:preimage) do
      Runar::SDK.compute_preimage(TX_HEX, 0, SUBSCRIPT_HEX, SATOSHIS)
    end

    it 'returns a non-empty hex string' do
      expect(preimage).to be_a(String)
      expect(preimage).not_to be_empty
    end

    it 'returns only lowercase hex characters' do
      expect(preimage).to match(/\A[0-9a-f]+\z/)
    end

    it 'has the correct BIP-143 preimage length (182 bytes = 364 hex chars)' do
      # Fixed-size fields: version(4) + hashPrevouts(32) + hashSequence(32) +
      # outpoint(36) + scriptCode_varint(1) + scriptCode(25) + value(8) +
      # sequence(4) + hashOutputs(32) + locktime(4) + sighash_type(4) = 182 bytes
      expect(preimage.length).to eq(364)
    end

    it 'starts with the little-endian version (01000000)' do
      expect(preimage[0, 8]).to eq('01000000')
    end

    it 'ends with the little-endian sighash type (41000000 for SIGHASH_ALL|FORKID)' do
      expect(preimage[-8..]).to eq('41000000')
    end

    it 'embeds the subscript bytes within the preimage' do
      # scriptCode content appears after the varint, inside the preimage
      expect(preimage).to include('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')
    end

    it 'matches the cross-validated expected value' do
      expect(preimage).to eq(EXPECTED_PREIMAGE)
    end

    it 'uses the supplied sighash_type in the final field' do
      result = Runar::SDK.compute_preimage(TX_HEX, 0, SUBSCRIPT_HEX, SATOSHIS, 0x43)
      expect(result[-8..]).to eq('43000000')
    end
  end

  # ---------------------------------------------------------------------------
  # get_subscript
  # ---------------------------------------------------------------------------
  describe 'get_subscript' do
    it 'returns the full script when code_separator_index is nil' do
      result = Runar::SDK.get_subscript(SUBSCRIPT_HEX, nil)
      expect(result).to eq(SUBSCRIPT_HEX)
    end

    it 'returns the full script when code_separator_index is -1' do
      result = Runar::SDK.get_subscript(SUBSCRIPT_HEX, -1)
      expect(result).to eq(SUBSCRIPT_HEX)
    end

    it 'returns everything after byte 0 when code_separator_index is 0' do
      result = Runar::SDK.get_subscript(SUBSCRIPT_HEX, 0)
      expect(result).to eq(SUBSCRIPT_HEX[2..])
    end

    it 'returns everything after byte 1 when code_separator_index is 1' do
      result = Runar::SDK.get_subscript(SUBSCRIPT_HEX, 1)
      expect(result).to eq(SUBSCRIPT_HEX[4..])
    end

    it 'returns an empty string when code_separator_index points to the last byte' do
      last_byte_idx = (SUBSCRIPT_HEX.length / 2) - 1
      result = Runar::SDK.get_subscript(SUBSCRIPT_HEX, last_byte_idx)
      expect(result).to eq('')
    end

    it 'returns the full script when code_separator_index exceeds script length' do
      result = Runar::SDK.get_subscript(SUBSCRIPT_HEX, 999)
      expect(result).to eq(SUBSCRIPT_HEX)
    end
  end

  # ---------------------------------------------------------------------------
  # sign_preimage_k1
  # ---------------------------------------------------------------------------
  describe 'sign_preimage_k1' do
    subject(:sig) do
      preimage = Runar::SDK.compute_preimage(TX_HEX, 0, SUBSCRIPT_HEX, SATOSHIS)
      Runar::SDK.sign_preimage_k1(preimage)
    end

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

    it 'has a plausible DER-encoded signature length (140-146 hex chars + 2 for sighash)' do
      # A secp256k1 DER signature is 70-72 bytes; with hashtype byte 71-73 bytes.
      expect(sig.length).to be_between(140, 148)
    end

    it 'is deterministic for the same preimage' do
      preimage = Runar::SDK.compute_preimage(TX_HEX, 0, SUBSCRIPT_HEX, SATOSHIS)
      a = Runar::SDK.sign_preimage_k1(preimage)
      b = Runar::SDK.sign_preimage_k1(preimage)
      expect(a).to eq(b)
    end

    it 'produces different signatures for different preimages' do
      preimage1 = Runar::SDK.compute_preimage(TX_HEX, 0, SUBSCRIPT_HEX, SATOSHIS)
      preimage2 = Runar::SDK.compute_preimage(TX_HEX, 0, SUBSCRIPT_HEX, SATOSHIS + 1)
      sig1 = Runar::SDK.sign_preimage_k1(preimage1)
      sig2 = Runar::SDK.sign_preimage_k1(preimage2)
      expect(sig1).not_to eq(sig2)
    end

    it 'matches the cross-validated expected signature' do
      preimage = Runar::SDK.compute_preimage(TX_HEX, 0, SUBSCRIPT_HEX, SATOSHIS)
      expect(Runar::SDK.sign_preimage_k1(preimage)).to eq(EXPECTED_SIG)
    end
  end
end
