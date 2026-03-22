# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::Provider' do
  # rubocop:enable RSpec/DescribeClass

  describe Runar::SDK::Provider do
    subject(:provider) { described_class.new }

    it 'raises NotImplementedError for get_transaction' do
      expect { provider.get_transaction('abc') }.to raise_error(NotImplementedError)
    end

    it 'raises NotImplementedError for get_raw_transaction' do
      expect { provider.get_raw_transaction('abc') }.to raise_error(NotImplementedError)
    end

    it 'raises NotImplementedError for broadcast' do
      expect { provider.broadcast('rawhex') }.to raise_error(NotImplementedError)
    end

    it 'raises NotImplementedError for get_utxos' do
      expect { provider.get_utxos('addr') }.to raise_error(NotImplementedError)
    end

    it 'raises NotImplementedError for get_contract_utxo' do
      expect { provider.get_contract_utxo('hash') }.to raise_error(NotImplementedError)
    end

    it 'raises NotImplementedError for get_network' do
      expect { provider.get_network }.to raise_error(NotImplementedError)
    end

    it 'raises NotImplementedError for get_fee_rate' do
      expect { provider.get_fee_rate }.to raise_error(NotImplementedError)
    end
  end

  describe Runar::SDK::MockProvider do
    subject(:provider) { described_class.new }

    describe 'initialisation' do
      it 'defaults to testnet' do
        expect(provider.get_network).to eq('testnet')
      end

      it 'accepts a custom network' do
        p = described_class.new(network: 'mainnet')
        expect(p.get_network).to eq('mainnet')
      end

      it 'defaults fee rate to 100 sat/KB' do
        expect(provider.get_fee_rate).to eq(100)
      end

      it 'starts with no broadcasted transactions' do
        expect(provider.get_broadcasted_txs).to be_empty
      end
    end

    describe '#add_utxo and #get_utxos' do
      let(:utxo) do
        Runar::SDK::Utxo.new(
          txid: 'abc123',
          output_index: 0,
          satoshis: 10_000,
          script: '76a914deadbeef88ac'
        )
      end

      it 'returns an empty array for an unknown address' do
        expect(provider.get_utxos('unknown')).to eq([])
      end

      it 'stores and retrieves a UTXO by address' do
        provider.add_utxo('addr1', utxo)
        result = provider.get_utxos('addr1')
        expect(result.length).to eq(1)
        expect(result.first.txid).to eq('abc123')
      end

      it 'accumulates multiple UTXOs under the same address' do
        utxo2 = Runar::SDK::Utxo.new(txid: 'def456', output_index: 1, satoshis: 5000, script: '')
        provider.add_utxo('addr1', utxo)
        provider.add_utxo('addr1', utxo2)
        expect(provider.get_utxos('addr1').length).to eq(2)
      end

      it 'returns a copy so external mutation does not affect stored data' do
        provider.add_utxo('addr1', utxo)
        provider.get_utxos('addr1') << Runar::SDK::Utxo.new(txid: 'x', output_index: 0, satoshis: 1, script: '')
        expect(provider.get_utxos('addr1').length).to eq(1)
      end
    end

    describe '#add_transaction and #get_transaction' do
      let(:tx) do
        Runar::SDK::Transaction.new(
          txid: 'deadbeef',
          version: 1,
          outputs: [Runar::SDK::TxOutput.new(script: '76a914ff88ac', satoshis: 10_000)]
        )
      end

      it 'retrieves a stored transaction by txid' do
        provider.add_transaction(tx)
        result = provider.get_transaction('deadbeef')
        expect(result.txid).to eq('deadbeef')
        expect(result.outputs.first.satoshis).to eq(10_000)
      end

      it 'raises a RuntimeError for an unknown txid' do
        expect { provider.get_transaction('notfound') }
          .to raise_error(RuntimeError, /not found/)
      end
    end

    describe '#get_raw_transaction' do
      it 'returns the raw hex of a transaction that has raw data' do
        tx = Runar::SDK::Transaction.new(txid: 'abc', raw: 'deadbeef01020304')
        provider.add_transaction(tx)
        expect(provider.get_raw_transaction('abc')).to eq('deadbeef01020304')
      end

      it 'raises when the transaction has no raw hex' do
        tx = Runar::SDK::Transaction.new(txid: 'abc')
        provider.add_transaction(tx)
        expect { provider.get_raw_transaction('abc') }
          .to raise_error(RuntimeError, /no raw hex/)
      end

      it 'raises for an unknown txid' do
        expect { provider.get_raw_transaction('gone') }
          .to raise_error(RuntimeError, /not found/)
      end
    end

    describe '#add_contract_utxo and #get_contract_utxo' do
      let(:utxo) { Runar::SDK::Utxo.new(txid: 'abc', output_index: 0, satoshis: 1000, script: 'beef') }

      it 'returns nil for an unknown script hash' do
        expect(provider.get_contract_utxo('unknown')).to be_nil
      end

      it 'stores and retrieves a contract UTXO by script hash' do
        provider.add_contract_utxo('scripthash1', utxo)
        result = provider.get_contract_utxo('scripthash1')
        expect(result.txid).to eq('abc')
      end
    end

    describe '#broadcast' do
      it 'stores the raw transaction and returns a deterministic txid' do
        txid = provider.broadcast('rawhexdata')
        expect(provider.get_broadcasted_txs).to eq(['rawhexdata'])
        expect(txid).to match(/\A[0-9a-f]{64}\z/)
      end

      it 'tracks multiple broadcasts in order' do
        provider.broadcast('tx1raw')
        provider.broadcast('tx2raw')
        expect(provider.get_broadcasted_txs).to eq(%w[tx1raw tx2raw])
      end

      it 'returns different txids for different inputs' do
        txid1 = provider.broadcast('aaaaaa')
        txid2 = provider.broadcast('bbbbbb')
        expect(txid1).not_to eq(txid2)
      end

      it 'returns a copy of broadcasted txs so external mutation is safe' do
        provider.broadcast('tx1raw')
        provider.get_broadcasted_txs << 'injected'
        expect(provider.get_broadcasted_txs.length).to eq(1)
      end
    end

    describe '#set_fee_rate' do
      it 'overrides the default fee rate' do
        provider.set_fee_rate(5)
        expect(provider.get_fee_rate).to eq(5)
      end
    end

    # -------------------------------------------------------------------------
    # get_raw_transaction after broadcast
    # -------------------------------------------------------------------------

    describe '#get_raw_transaction after #broadcast' do
      it 'returns the raw hex of a transaction that was broadcast' do
        raw = 'deadbeef01020304'
        txid = provider.broadcast(raw)
        expect(provider.get_raw_transaction(txid)).to eq(raw)
      end

      it 'returns raw hex keyed by the txid returned from broadcast' do
        raw1 = 'aabbccdd'
        raw2 = '11223344'
        txid1 = provider.broadcast(raw1)
        txid2 = provider.broadcast(raw2)
        expect(provider.get_raw_transaction(txid1)).to eq(raw1)
        expect(provider.get_raw_transaction(txid2)).to eq(raw2)
      end

      it 'prioritizes broadcast-stored hex over add_transaction raw field' do
        # If both exist for the same txid, broadcast storage wins.
        raw_broadcast = 'broadcasthex'
        txid = provider.broadcast(raw_broadcast)

        tx = Runar::SDK::Transaction.new(txid: txid, raw: 'stored_raw')
        provider.add_transaction(tx)

        expect(provider.get_raw_transaction(txid)).to eq(raw_broadcast)
      end

      it 'still raises for an unknown txid not seen by broadcast' do
        expect { provider.get_raw_transaction('unknowntxid') }
          .to raise_error(RuntimeError, /not found/)
      end

      it 'still returns raw from add_transaction when txid was not broadcast' do
        tx = Runar::SDK::Transaction.new(txid: 'abc123', raw: 'hexdata')
        provider.add_transaction(tx)
        expect(provider.get_raw_transaction('abc123')).to eq('hexdata')
      end
    end
  end
end
