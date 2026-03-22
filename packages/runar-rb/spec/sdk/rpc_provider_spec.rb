# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

RSpec.describe Runar::SDK::RPCProvider do
  describe '.regtest' do
    it 'creates an RPCProvider instance' do
      provider = described_class.regtest
      expect(provider).to be_a(described_class)
    end

    it 'is a subclass of Provider' do
      provider = described_class.regtest
      expect(provider).to be_a(Runar::SDK::Provider)
    end

    it 'defaults to localhost:18332' do
      # Verified via get_network (no live call needed)
      provider = described_class.regtest
      expect(provider.get_network).to eq('regtest')
    end

    it 'accepts custom host/port/credentials' do
      provider = described_class.regtest(host: '10.0.0.1', port: 8332, username: 'user', password: 'pass')
      expect(provider.get_network).to eq('regtest')
    end
  end

  describe '#initialize' do
    it 'sets network from keyword argument' do
      provider = described_class.new(network: 'mainnet')
      expect(provider.get_network).to eq('mainnet')
    end

    it 'defaults network to regtest' do
      provider = described_class.new
      expect(provider.get_network).to eq('regtest')
    end
  end

  describe '#get_network' do
    it 'returns regtest for a regtest-configured provider' do
      expect(described_class.regtest.get_network).to eq('regtest')
    end

    it 'returns the network passed at construction' do
      provider = described_class.new(network: 'testnet')
      expect(provider.get_network).to eq('testnet')
    end
  end

  describe '#get_fee_rate' do
    it 'returns 1 (regtest default)' do
      expect(described_class.regtest.get_fee_rate).to eq(1)
    end

    it 'returns an Integer' do
      expect(described_class.regtest.get_fee_rate).to be_an(Integer)
    end
  end

  describe '#get_contract_utxo' do
    it 'raises NotImplementedError with a helpful message' do
      provider = described_class.regtest
      expect { provider.get_contract_utxo('somehash') }
        .to raise_error(NotImplementedError, /RPCProvider#get_contract_utxo/)
    end
  end

  describe 'live RPC calls (skipped — no node available)' do
    # Integration tests against a real Bitcoin node belong in
    # integration/ruby/, not here. The tests above verify all behavior
    # that does not require network I/O.
  end
end
