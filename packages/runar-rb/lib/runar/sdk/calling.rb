# frozen_string_literal: true

# Transaction construction for contract method invocation.
#
# All public methods live at module level under Runar::SDK so they can be
# called as Runar::SDK.build_call_transaction(...) etc.

module Runar
  module SDK
    module_function

    # Build a raw (partially-signed) transaction that spends a contract UTXO.
    #
    # Input 0 is the contract's current UTXO, carrying the provided
    # +unlocking_script+ (which may be empty when building before signing).
    # Additional contract inputs from +options[:additional_contract_inputs]+ are
    # appended next, each with their own unlocking script.  P2PKH funding inputs
    # from +additional_utxos+ follow with empty scriptSigs.
    #
    # Output 0 is the new contract continuation output.  When
    # +options[:contract_outputs]+ is present it replaces the single
    # continuation output with multiple outputs (token-split pattern).  A P2PKH
    # change output is appended when the remaining balance is positive.
    #
    # @param current_utxo [Utxo] the contract UTXO being spent
    # @param unlocking_script [String] hex-encoded scriptSig for input 0 (may be empty)
    # @param new_locking_script [String] hex-encoded locking script for the continuation output
    # @param new_satoshis [Integer] satoshis for the continuation output (0 = carry forward)
    # @param change_address [String] Base58Check address or 40-char hex pubkey hash for change
    # @param change_script [String] pre-built change script hex (overrides +change_address+)
    # @param additional_utxos [Array<Utxo>, nil] P2PKH UTXOs used to fund fees
    # @param fee_rate [Integer] satoshis per kilobyte (minimum 1)
    # @param options [Hash, nil] optional extensions:
    #   - +:contract_outputs+ [Array<Hash>] each +{script:, satoshis:}+ for multi-output
    #   - +:additional_contract_inputs+ [Array<Hash>] each +{utxo:, unlocking_script:}+
    # @return [Array(String, Integer, Integer)] [tx_hex, input_count, change_amount]
    def build_call_transaction(
      current_utxo,
      unlocking_script,
      new_locking_script,
      new_satoshis,
      change_address,
      change_script = '',
      additional_utxos = nil,
      fee_rate: 100,
      options: nil
    )
      opts                   = options || {}
      extra_contract_inputs  = opts[:additional_contract_inputs] || []
      additional             = additional_utxos || []

      all_utxos = [current_utxo] + extra_contract_inputs.map { |ci| ci[:utxo] } + additional
      total_input = all_utxos.sum(&:satoshis)

      # Resolve contract outputs — multi-output takes priority over single.
      resolved_outputs =
        if opts[:contract_outputs] && !opts[:contract_outputs].empty?
          opts[:contract_outputs]
        elsif !new_locking_script.empty?
          sats = new_satoshis.positive? ? new_satoshis : current_utxo.satoshis
          [{ script: new_locking_script, satoshis: sats }]
        else
          []
        end

      contract_output_sats = resolved_outputs.sum { |co| co[:satoshis] }

      # Estimate transaction size for fee calculation.
      #
      # Input 0: prevTxid(32) + prevIndex(4) + scriptSig varint + scriptSig + sequence(4)
      unlock_byte_len = unlocking_script.length / 2
      input0_size = 32 + 4 + varint_byte_size(unlock_byte_len) + unlock_byte_len + 4

      extra_inputs_size = extra_contract_inputs.sum do |ci|
        ci_len = ci[:unlocking_script].length / 2
        32 + 4 + varint_byte_size(ci_len) + ci_len + 4
      end

      # P2PKH funding inputs are unsigned at construction time (~148 bytes each).
      additional_inputs_size = additional.length * P2PKH_INPUT_SIZE

      inputs_size = input0_size + extra_inputs_size + additional_inputs_size

      outputs_size = resolved_outputs.sum do |co|
        s_len = co[:script].length / 2
        8 + varint_byte_size(s_len) + s_len
      end

      # Include change output in size estimate only when a recipient is specified.
      has_change_recipient = !change_address.to_s.empty? || !change_script.to_s.empty?
      outputs_size += P2PKH_OUTPUT_SIZE if has_change_recipient

      estimated_size = TX_OVERHEAD + inputs_size + outputs_size
      rate           = [1, fee_rate].max
      fee            = (estimated_size * rate + 999) / 1000
      change         = total_input - contract_output_sats - fee

      # Build raw transaction bytes as a hex string.
      tx = +''

      # Version
      tx << to_le32(1)

      # Input count
      tx << encode_varint(all_utxos.length)

      # Input 0: contract UTXO with (possibly empty) unlocking script.
      tx << reverse_hex(current_utxo.txid)
      tx << to_le32(current_utxo.output_index)
      tx << encode_varint(unlock_byte_len)
      tx << unlocking_script
      tx << 'ffffffff'

      # Additional contract inputs with their own unlocking scripts.
      extra_contract_inputs.each do |ci|
        ci_utxo   = ci[:utxo]
        ci_script = ci[:unlocking_script]
        tx << reverse_hex(ci_utxo.txid)
        tx << to_le32(ci_utxo.output_index)
        tx << encode_varint(ci_script.length / 2)
        tx << ci_script
        tx << 'ffffffff'
      end

      # P2PKH funding inputs — unsigned, empty scriptSig.
      additional.each do |utxo|
        tx << reverse_hex(utxo.txid)
        tx << to_le32(utxo.output_index)
        tx << '00'
        tx << 'ffffffff'
      end

      # Output count
      has_change = change.positive? && has_change_recipient
      output_count = resolved_outputs.length + (has_change ? 1 : 0)
      tx << encode_varint(output_count)

      # Contract continuation outputs.
      resolved_outputs.each do |co|
        s = co[:script]
        tx << to_le64(co[:satoshis])
        tx << encode_varint(s.length / 2)
        tx << s
      end

      # Change output.
      if has_change
        actual_change_script = change_script.to_s.empty? ? build_p2pkh_script(change_address) : change_script
        tx << to_le64(change)
        tx << encode_varint(actual_change_script.length / 2)
        tx << actual_change_script
      end

      # Locktime
      tx << to_le32(0)

      [tx, all_utxos.length, has_change ? change : 0]
    end

    # Replace the scriptSig of a specific input within a raw transaction.
    #
    # Parses the hex-encoded transaction, locates the scriptSig at
    # +input_index+, substitutes it with +unlock_script+, and returns the
    # modified transaction as hex.  All other fields remain unchanged.
    #
    # @param tx_hex [String] hex-encoded raw transaction
    # @param input_index [Integer] zero-based index of the input to update
    # @param unlock_script [String] hex-encoded replacement scriptSig
    # @return [String] modified transaction hex
    # @raise [ArgumentError] when +input_index+ is out of range
    def insert_unlocking_script(tx_hex, input_index, unlock_script)
      pos = 0

      # Skip version (4 bytes = 8 hex chars).
      pos += 8

      # Read input count varint.
      input_count, ic_hex_len = read_varint_hex(tx_hex, pos)
      pos += ic_hex_len

      if input_index >= input_count
        raise ArgumentError,
              "insert_unlocking_script: input index #{input_index} out of range " \
              "(#{input_count} inputs)"
      end

      input_count.times do |i|
        # prevTxid (32 bytes = 64 hex chars) + prevOutputIndex (4 bytes = 8 hex chars)
        pos += 64 + 8

        # Read scriptSig length varint.
        script_len, sl_hex_len = read_varint_hex(tx_hex, pos)

        if i == input_index
          new_byte_len = unlock_script.length / 2
          new_varint   = encode_varint(new_byte_len)
          before       = tx_hex[0, pos]
          after        = tx_hex[pos + sl_hex_len + script_len * 2..]
          return "#{before}#{new_varint}#{unlock_script}#{after}"
        end

        # Skip scriptSig bytes + sequence (4 bytes = 8 hex chars).
        pos += sl_hex_len + script_len * 2 + 8
      end

      raise ArgumentError,
            "insert_unlocking_script: input index #{input_index} out of range"
    end

    # ---------------------------------------------------------------------------
    # Private helper
    # ---------------------------------------------------------------------------

    # Read a Bitcoin-style varint from a hex string at position +pos+.
    #
    # @param hex_str [String] hex-encoded data
    # @param pos [Integer] character offset (not byte offset)
    # @return [Array(Integer, Integer)] [value, hex_chars_consumed]
    def read_varint_hex(hex_str, pos)
      first = hex_str[pos, 2].to_i(16)

      case first
      when 0...0xFD
        [first, 2]
      when 0xFD
        lo = hex_str[pos + 2, 2].to_i(16)
        hi = hex_str[pos + 4, 2].to_i(16)
        [lo | (hi << 8), 6]
      when 0xFE
        value = [hex_str[pos + 2, 8]].pack('H*').unpack1('V')
        [value, 10]
      else # 0xFF
        value = [hex_str[pos + 2, 16]].pack('H*').unpack1('Q<')
        [value, 18]
      end
    end
  end
end
