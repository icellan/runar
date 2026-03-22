# frozen_string_literal: true

# Provider interface and MockProvider for testing.
#
# A Provider abstracts blockchain access: fetching UTXOs, looking up
# transactions, and broadcasting signed transactions to the network.

require_relative 'types'

module Runar
  module SDK
    # Abstract base class for blockchain providers.
    #
    # Subclasses must implement all abstract methods. Raise NotImplementedError
    # from the default implementations keeps the intent explicit.
    class Provider
      # Fetch a Transaction by its txid.
      def get_transaction(_txid)
        raise NotImplementedError, "#{self.class}#get_transaction is not implemented"
      end

      # Fetch the raw transaction hex by its txid.
      def get_raw_transaction(_txid)
        raise NotImplementedError, "#{self.class}#get_raw_transaction is not implemented"
      end

      # Broadcast a raw transaction hex to the network.
      # Returns the txid of the broadcasted transaction.
      def broadcast(_raw_tx)
        raise NotImplementedError, "#{self.class}#broadcast is not implemented"
      end

      # Return all UTXOs for a given address.
      def get_utxos(_address)
        raise NotImplementedError, "#{self.class}#get_utxos is not implemented"
      end

      # Find a UTXO by its script hash (for stateful contract lookup).
      # Returns nil if not found.
      def get_contract_utxo(_script_hash)
        raise NotImplementedError, "#{self.class}#get_contract_utxo is not implemented"
      end

      # Return the network this provider is connected to (e.g. 'mainnet', 'testnet').
      def get_network
        raise NotImplementedError, "#{self.class}#get_network is not implemented"
      end

      # Return the current fee rate in satoshis per kilobyte.
      def get_fee_rate
        raise NotImplementedError, "#{self.class}#get_fee_rate is not implemented"
      end
    end

    # In-memory provider for unit tests and local development.
    #
    # Pre-populate with UTXOs and transactions, then inspect broadcasted
    # transactions after the fact.
    #
    #   provider = Runar::SDK::MockProvider.new
    #   provider.add_utxo('myAddress', Runar::SDK::Utxo.new(txid: 'abc...', ...))
    #   provider.get_utxos('myAddress') # => [<Utxo>]
    class MockProvider < Provider
      DEFAULT_FEE_RATE = 100

      def initialize(network: 'testnet')
        @transactions     = {}
        @utxos            = {}
        @contract_utxos   = {}
        @broadcasted_txs  = []
        @raw_transactions = {}
        @broadcast_count  = 0
        @network          = network
        @fee_rate         = DEFAULT_FEE_RATE
      end

      # -- Mutation helpers ---------------------------------------------------

      # Register a transaction for later retrieval.
      def add_transaction(tx)
        @transactions[tx.txid] = tx
      end

      # Register a UTXO under an address.
      def add_utxo(address, utxo)
        @utxos[address] ||= []
        @utxos[address] << utxo
      end

      # Register a UTXO under a script hash for stateful contract lookup.
      def add_contract_utxo(script_hash, utxo)
        @contract_utxos[script_hash] = utxo
      end

      # Override the fee rate (default: 100 sat/KB).
      def set_fee_rate(rate)
        @fee_rate = rate
      end

      # Return a copy of all raw transaction hexes that have been broadcasted.
      def get_broadcasted_txs
        @broadcasted_txs.dup
      end

      # -- Provider interface -------------------------------------------------

      def get_transaction(txid)
        tx = @transactions[txid]
        raise "MockProvider: transaction #{txid} not found" unless tx

        tx
      end

      def get_raw_transaction(txid)
        # Return auto-stored raw hex from a previous broadcast first.
        return @raw_transactions[txid] if @raw_transactions.key?(txid)

        tx = @transactions[txid]
        raise "MockProvider: transaction #{txid} not found" unless tx
        raise "MockProvider: transaction #{txid} has no raw hex" if tx.raw.to_s.empty?

        tx.raw
      end

      def broadcast(raw_tx)
        @broadcasted_txs << raw_tx
        @broadcast_count += 1
        fake_txid = mock_hash64("mock-broadcast-#{@broadcast_count}-#{raw_tx[0, 16]}")
        # Auto-store raw hex so get_raw_transaction works without an explicit add_transaction call.
        @raw_transactions[fake_txid] = raw_tx
        fake_txid
      end

      def get_utxos(address)
        Array(@utxos[address]).dup
      end

      def get_contract_utxo(script_hash)
        @contract_utxos[script_hash]
      end

      def get_network
        @network
      end

      def get_fee_rate
        @fee_rate
      end

      private

      # Deterministic mock hash producing a 64-character hex string (like a txid).
      # Uses a simple FNV-inspired mix so the result is stable across Ruby versions.
      def mock_hash64(input)
        h0 = 0x6A09E667
        h1 = 0xBB67AE85
        h2 = 0x3C6EF372
        h3 = 0xA54FF53A
        mask32 = 0xFFFFFFFF

        input.each_char do |ch|
          c = ch.ord
          h0 = ((h0 ^ c) * 0x01000193) & mask32
          h1 = ((h1 ^ c) * 0x01000193) & mask32
          h2 = ((h2 ^ c) * 0x01000193) & mask32
          h3 = ((h3 ^ c) * 0x01000193) & mask32
        end

        parts = [h0, h1, h2, h3, h0 ^ h2, h1 ^ h3, h0 ^ h1, h2 ^ h3]
        parts.map { |p| format('%08x', p) }.join
      end
    end
  end
end
