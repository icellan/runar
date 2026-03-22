# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::Signer' do
  # rubocop:enable RSpec/DescribeClass

  describe Runar::SDK::Signer do
    subject(:signer) { described_class.new }

    it 'raises NotImplementedError for get_public_key' do
      expect { signer.get_public_key }.to raise_error(NotImplementedError)
    end

    it 'raises NotImplementedError for get_address' do
      expect { signer.get_address }.to raise_error(NotImplementedError)
    end

    it 'raises NotImplementedError for sign' do
      expect { signer.sign('hex', 0, 'subscript', 1000) }.to raise_error(NotImplementedError)
    end
  end

  describe Runar::SDK::MockSigner do
    subject(:signer) { described_class.new }

    describe 'default behavior' do
      it 'returns a 66-character hex public key' do
        pk = signer.get_public_key
        expect(pk).to match(/\A[0-9a-f]{66}\z/)
      end

      it 'returns the deterministic default public key' do
        expect(signer.get_public_key).to eq('02' + '00' * 32)
      end

      it 'returns the deterministic default address' do
        expect(signer.get_address).to eq('00' * 20)
      end

      it 'returns a 72-byte mock DER signature' do
        sig = signer.sign('deadbeef', 0, 'subscript', 10_000)
        # 72 bytes = 144 hex chars
        expect(sig.length).to eq(144)
        expect(sig).to match(/\A[0-9a-f]+\z/)
      end

      it 'signature begins with 0x30 (DER sequence tag)' do
        sig = signer.sign('deadbeef', 0, 'subscript', 10_000)
        expect(sig[0, 2]).to eq('30')
      end

      it 'signature ends with sighash byte 0x41' do
        sig = signer.sign('deadbeef', 0, 'subscript', 10_000)
        expect(sig[-2..]).to eq('41')
      end

      it 'is deterministic: same signature regardless of input' do
        sig1 = signer.sign('aaa', 0, 'sub', 100)
        sig2 = signer.sign('bbb', 1, 'other', 9999)
        expect(sig1).to eq(sig2)
      end
    end

    describe 'custom initialisation' do
      it 'accepts a custom public key' do
        custom_pk = '03' + 'ab' * 32
        s = described_class.new(pub_key_hex: custom_pk)
        expect(s.get_public_key).to eq(custom_pk)
      end

      it 'accepts a custom address' do
        s = described_class.new(address: '1ABCxyz')
        expect(s.get_address).to eq('1ABCxyz')
      end
    end
  end

  describe Runar::SDK::ExternalSigner do
    let(:pub_key) { '03' + 'ff' * 32 }
    let(:address) { '1TestAddress' }
    let(:sign_fn) { ->(tx_hex, input_index, subscript, satoshis, sighash_type) {
      "signed:#{tx_hex}:#{input_index}:#{subscript}:#{satoshis}:#{sighash_type}"
    } }

    subject(:signer) { described_class.new(pub_key_hex: pub_key, address: address, sign_fn: sign_fn) }

    it 'delegates get_public_key to the supplied key' do
      expect(signer.get_public_key).to eq(pub_key)
    end

    it 'delegates get_address to the supplied address' do
      expect(signer.get_address).to eq(address)
    end

    it 'delegates sign to the provided callable' do
      result = signer.sign('myhex', 2, 'myscript', 5000, 0x41)
      expect(result).to eq('signed:myhex:2:myscript:5000:65')
    end

    it 'passes nil sighash_type through to the callable' do
      result = signer.sign('tx', 0, 'sub', 100)
      expect(result).to end_with(':')
    end

    it 'works with a proc as well as a lambda' do
      called_with = nil
      proc_sign = proc do |tx_hex, input_index, subscript, satoshis, sighash_type|
        called_with = [tx_hex, input_index, subscript, satoshis, sighash_type]
        'mock_sig'
      end
      s = described_class.new(pub_key_hex: pub_key, address: address, sign_fn: proc_sign)
      result = s.sign('rawhex', 1, 'script', 2000, nil)
      expect(result).to eq('mock_sig')
      expect(called_with).to eq(['rawhex', 1, 'script', 2000, nil])
    end
  end
end
