# frozen_string_literal: true

# Provider interface and MockProvider for testing.
#
# A Provider abstracts blockchain access: fetching UTXOs, looking up
# transactions, and broadcasting signed transactions to the network.

require 'digest'
require_relative 'types'
require_relative 'errors'
require_relative 'bip143'

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

      # Shape of last_validation_report before any validating broadcast has run.
      EMPTY_VALIDATION_REPORT = {
        scripts_executed: 0,
        known_inputs: 0,
        total_inputs: 0,
        value_conserved: false
      }.freeze

      def initialize(network: 'testnet', validate_broadcasts: true)
        @transactions        = {}
        @utxos               = {}
        @contract_utxos      = {}
        @broadcasted_txs     = []
        @raw_transactions    = {}
        @broadcast_count     = 0
        @network             = network
        @fee_rate            = DEFAULT_FEE_RATE
        @validate_broadcasts = validate_broadcasts
        @known_outpoints     = {}
        @last_report         = EMPTY_VALIDATION_REPORT
        # "txid:vout" -> txid of the accepted broadcast that spent it. Checked
        # on EVERY broadcast, whatever validate_broadcasts says: a node refuses
        # a second transaction spending an outpoint already spent.
        @spent_outpoints     = {}
        # Real txid of every accepted broadcast -> the txid this provider
        # returned for it: re-broadcasting the identical tx is idempotent.
        @accepted_txids      = {}
      end

      # A MockProvider whose +broadcast+ never validates — the pre-Phase-A5
      # behaviour.
      #
      # FOR ALLOWLISTED SPECS ONLY: every spec file that calls this (or the
      # other opt-outs) must carry a matching entry in
      # +always_ack_allowlist.json+, enforced by
      # +spec/sdk/always_ack_allowlist_spec.rb+. Fund-path deploy/call specs
      # must not use it.
      def self.always_ack(network: 'testnet')
        new(network: network, validate_broadcasts: false)
      end

      # Turn the fail-closed +broadcast+ check on or off. Passing +false+ is an
      # allowlisted opt-out — see +MockProvider.always_ack+.
      def enable_broadcast_validation(enabled = true)
        @validate_broadcasts = enabled
      end

      # Restore the legacy always-ack +broadcast+. Allowlisted opt-out.
      def disable_broadcast_validation
        @validate_broadcasts = false
      end

      # Report from the most recent validating +broadcast+. Exposed so a spec
      # can assert its gate is NOT vacuous.
      #
      # +:scripts_executed+ is ALWAYS 0 in this tier and is present precisely so
      # that fact stays visible: Ruby ships no Bitcoin Script VM (see README,
      # "How fund-path tests fail closed in the Ruby tier").
      def last_validation_report
        @last_report
      end

      # Shorthand for +last_validation_report[:known_inputs]+ — the number of
      # spent outpoints this provider actually recognised and checked.
      def last_validated_input_count
        @last_report[:known_inputs]
      end

      # -- Mutation helpers ---------------------------------------------------

      # Register a transaction for later retrieval.
      def add_transaction(tx)
        @transactions[tx.txid] = tx
        Array(tx.outputs).each_with_index do |out, i|
          remember_outpoint(tx.txid, i, out.script, out.satoshis)
        end
      end

      # Register a UTXO under an address.
      def add_utxo(address, utxo)
        @utxos[address] ||= []
        @utxos[address] << utxo
        remember_outpoint(utxo.txid, utxo.output_index, utxo.script, utxo.satoshis)
      end

      # Register a UTXO under a script hash for stateful contract lookup.
      def add_contract_utxo(script_hash, utxo)
        @contract_utxos[script_hash] = utxo
        remember_outpoint(utxo.txid, utxo.output_index, utxo.script, utxo.satoshis)
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

      # Validate the transaction (unless validation has been opted out of) and
      # then record it, returning a deterministic fake txid.
      #
      # Fail-closed by default (testing-gap remediation Phase A5). This tier has
      # NO Bitcoin Script VM, so it makes no script-validity claim — see
      # +validate_broadcast!+ for exactly what it does and does not check.
      def broadcast(raw_tx)
        parsed = validate_broadcast!(raw_tx) if @validate_broadcasts
        spending_txid, input_outpoints, structural = check_double_spend!(raw_tx)

        # Re-broadcasting a tx already accepted is idempotent, as on a node:
        # same txid, nothing registered twice. It is still validated above, so
        # a tx an always-ack provider acked is not waved through once
        # validation is on.
        return @accepted_txids[spending_txid] if spending_txid && @accepted_txids.key?(spending_txid)

        # Accepted: its inputs are now spent.
        input_outpoints.each { |key| @spent_outpoints[key] = spending_txid }

        @broadcasted_txs << raw_tx
        @broadcast_count += 1
        fake_txid = mock_hash64("mock-broadcast-#{@broadcast_count}-#{raw_tx[0, 16]}")
        # Auto-store raw hex so get_raw_transaction works without an explicit add_transaction call.
        @raw_transactions[fake_txid] = raw_tx
        # Register this tx's own outputs as known outpoints so a chained call
        # (spending the continuation this broadcast just created) is checkable.
        parsed&.fetch(:outputs)&.each_with_index do |out, i|
          remember_outpoint(fake_txid, i, out[:script].unpack1('H*'), out[:satoshis])
        end
        @accepted_txids[spending_txid] = fake_txid if spending_txid
        list_new_p2pkh_outputs(fake_txid, structural) if structural
        fake_txid
      end

      def get_utxos(address)
        # An outpoint an accepted broadcast spent is no longer a UTXO (a node's
        # listing would not return it either).
        utxos = Array(@utxos[address]).reject { |u| @spent_outpoints.key?("#{u.txid}:#{u.output_index}") }
        # DoS-bound: reject pathological scripts at the provider boundary.
        utxos.each do |u|
          next if u.script.nil? || u.script.empty?

          SDK.assert_script_hex_under_limit(
            u.script, SDK::MAX_SCRIPT_BYTES,
            "MockProvider.get_utxos(#{address})"
          )
        end
        utxos
      end

      def get_contract_utxo(script_hash)
        utxo = @contract_utxos[script_hash]
        if utxo && utxo.script && !utxo.script.empty?
          SDK.assert_script_hex_under_limit(
            utxo.script, SDK::MAX_SCRIPT_BYTES,
            "MockProvider.get_contract_utxo(#{script_hash})"
          )
        end
        utxo
      end

      def get_network
        @network
      end

      def get_fee_rate
        @fee_rate
      end

      private

      # Record an outpoint's script + value so broadcast validation can reason
      # about it.
      def remember_outpoint(txid, vout, script_hex, satoshis)
        return if txid.nil? || script_hex.nil? || script_hex.to_s.empty?

        @known_outpoints["#{txid}:#{vout}"] = { script: script_hex, satoshis: satoshis.to_i }
      end

      # Fail-closed broadcast validation (testing-gap remediation Phase A5).
      #
      # WHAT THIS CHECKS — and, just as importantly, what it does not.
      #
      # The Ruby tier ships no Bitcoin Script VM: there is no canonical upstream
      # BSV Ruby SDK to wrap, and project policy forbids hand-rolling an
      # interpreter (root CLAUDE.md, "Off-chain Script VM"). So this method
      # makes NO claim about signature or covenant validity. It applies the
      # checks that are genuinely available from the serialized bytes alone:
      #
      #   1. STRUCTURAL      — the payload must parse as a Bitcoin transaction.
      #   2. NON-VACUITY     — at least one spent outpoint must be known here,
      #                        so the gate can never pass by checking nothing.
      #   3. VALUE CONSERVE  — when every input is known, outputs <= inputs.
      #   4. SCRIPT-SIZE     — every output script stays under MAX_SCRIPT_BYTES.
      #
      # Script-level correctness for this tier is proven VERTICALLY instead:
      # absolute-hex pins against the peer tiers' goldens plus the on-chain
      # integration spends in integration/ruby.
      #
      # @raise [BroadcastRejected] when any check above fails
      # @return [Hash] the parsed transaction (for the caller to reuse)
      def validate_broadcast!(raw_tx)
        parsed = parse_broadcast_tx(raw_tx)

        known_inputs = 0
        total_known_in = 0
        all_inputs_known = true

        parsed[:inputs].each do |input|
          key = "#{input[:prev_txid].bytes.reverse.pack('C*').unpack1('H*')}:#{input[:prev_output_index]}"
          known = @known_outpoints[key]
          if known.nil?
            all_inputs_known = false
            next
          end
          known_inputs += 1
          total_known_in += known[:satoshis]
        end

        total_out = 0
        parsed[:outputs].each_with_index do |out, i|
          script_hex = out[:script].unpack1('H*')
          SDK.assert_script_hex_under_limit(
            script_hex, SDK::MAX_SCRIPT_BYTES, "MockProvider.broadcast output #{i}"
          )
          total_out += out[:satoshis]
        end

        @last_report = {
          scripts_executed: 0, # this tier has no Script VM — see the note above
          known_inputs: known_inputs,
          total_inputs: parsed[:inputs].length,
          value_conserved: all_inputs_known
        }.freeze

        if known_inputs.zero?
          raise BroadcastRejected,
                'MockProvider: refusing to broadcast — checked 0 of ' \
                "#{parsed[:inputs].length} input(s): no spent outpoint is known to this " \
                'provider, so validation would pass vacuously. Seed the spent outpoints via ' \
                'add_utxo/add_contract_utxo/add_transaction, or use MockProvider.always_ack ' \
                '(allowlisted) if this spec genuinely needs always-ack'
        end

        if all_inputs_known && total_out > total_known_in
          raise BroadcastRejected,
                "MockProvider: refusing to broadcast invalid transaction: underfunded: outputs " \
                "(#{total_out} sats) exceed known inputs (#{total_known_in} sats)"
        end

        parsed
      end

      # Double-spend gate, independent of validate_broadcasts. Refuses a
      # transaction that spends one outpoint twice, or an outpoint an earlier
      # accepted broadcast spent. Re-broadcasting the identical transaction is
      # not a conflict (a node treats it as already known).
      #
      # @raise [BroadcastRejected]
      # @return [Array] the real txid, input outpoints and structural parse
      def check_double_spend!(raw_tx)
        parsed = begin
          parse_broadcast_tx(raw_tx)
        rescue BroadcastRejected
          # A payload that does not parse spends no outpoint, so there is
          # nothing to check here; validation (when on) refuses it as not a
          # transaction, and the always-ack opt-out keeps acking it.
          return [nil, [], nil]
        end
        txid = Digest::SHA256.digest(Digest::SHA256.digest([raw_tx.to_s].pack('H*'))).reverse.unpack1('H*')
        outpoints = []
        parsed[:inputs].each do |input|
          key = "#{input[:prev_txid].bytes.reverse.pack('C*').unpack1('H*')}:#{input[:prev_output_index]}"
          if outpoints.include?(key)
            raise BroadcastRejected,
                  "MockProvider: refusing to broadcast a transaction that spends #{key} more than once"
          end
          outpoints << key
          spender = @spent_outpoints[key]
          if spender && !@accepted_txids.key?(txid)
            raise BroadcastRejected,
                  "MockProvider: refusing to broadcast a double spend: #{key} is already spent by #{spender}"
          end
        end
        [txid, outpoints, parsed]
      end

      # A P2PKH output paying an address this provider lists (e.g. the change
      # of a deploy) is a new UTXO of that address, as a node's listing would
      # show it, so a later call can be funded from it.
      def list_new_p2pkh_outputs(txid, parsed)
        @utxos.each do |address, listed|
          p2pkh = begin
            SDK.build_p2pkh_script(address).downcase
          rescue StandardError
            next # not a real address (a test label)
          end
          parsed[:outputs].each_with_index do |out, i|
            next unless out[:script].unpack1('H*') == p2pkh

            listed << Utxo.new(txid: txid, output_index: i, satoshis: out[:satoshis], script: p2pkh)
          end
        end
      end

      def parse_broadcast_tx(raw_tx)
        hex = raw_tx.to_s
        raise BroadcastRejected, broadcast_parse_error(hex) unless hex.match?(/\A(?:[0-9a-fA-F]{2})+\z/)

        parsed = BIP143.parse_raw_tx([hex].pack('H*'))
        raise BroadcastRejected, broadcast_parse_error(hex) if parsed[:inputs].empty?

        parsed
      rescue ArgumentError, NoMethodError, TypeError
        raise BroadcastRejected, broadcast_parse_error(raw_tx.to_s)
      end

      def broadcast_parse_error(hex)
        'MockProvider: refusing to broadcast — payload is not a parseable Bitcoin transaction ' \
        "(#{hex.length / 2} byte(s)). A real node would reject it outright."
      end

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
