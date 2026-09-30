# frozen_string_literal: true

require 'digest'

# Transaction construction for contract deployment.
#
# All public methods live at module level under Runar::SDK so they can be
# called as Runar::SDK.build_deploy_transaction(...) etc.

module Runar
  module SDK
    # P2PKH sizes used for fee estimation.
    P2PKH_INPUT_SIZE  = 148 # prevTxid(32) + index(4) + scriptSig(~107) + sequence(4) + varint(1)
    P2PKH_OUTPUT_SIZE = 34  # satoshis(8) + varint(1) + P2PKH script(25)
    TX_OVERHEAD       = 10  # version(4) + input varint(1) + output varint(1) + locktime(4)

    module_function

    # Build an unsigned deployment transaction.
    #
    # @param locking_script [String] hex-encoded contract locking script
    # @param utxos [Array<Utxo>] funding UTXOs (must not be empty)
    # @param satoshis [Integer] value to lock in the contract output
    # @param change_address [String] Base58Check address or 40-char hex pubkey hash for change
    # @param change_script [String] pre-built change script hex (overrides change_address when present)
    # @param fee_rate [Integer] satoshis per kilobyte (minimum 1)
    # @return [Array(String, Integer)] [tx_hex, input_count]
    def build_deploy_transaction(locking_script, utxos, satoshis, change_address,
                                 change_script = '', fee_rate: 100)
      raise ArgumentError, 'build_deploy_transaction: no UTXOs provided' if utxos.empty?

      total_input = utxos.sum(&:satoshis)
      fee         = estimate_deploy_fee(utxos.length, locking_script.length / 2, fee_rate)
      change      = total_input - satoshis - fee

      if change < 0
        raise ArgumentError,
              "build_deploy_transaction: insufficient funds. " \
              "Need #{satoshis + fee} sats, have #{total_input}"
      end

      tx = +''

      # Version (4 bytes, little-endian)
      tx << to_le32(1)

      # Input count (varint)
      tx << encode_varint(utxos.length)

      # Inputs (unsigned — empty scriptSig)
      utxos.each do |utxo|
        tx << reverse_hex(utxo.txid)
        tx << to_le32(utxo.output_index)
        tx << '00'         # empty scriptSig (varint 0)
        tx << 'ffffffff'   # sequence
      end

      # Output count (varint)
      has_change   = change > 0
      output_count = has_change ? 2 : 1
      tx << encode_varint(output_count)

      # Output 0: contract locking script
      tx << to_le64(satoshis)
      tx << encode_varint(locking_script.length / 2)
      tx << locking_script

      # Output 1: change (omitted when change is zero)
      if has_change
        actual_change_script = change_script.empty? ? build_p2pkh_script(change_address) : change_script
        tx << to_le64(change)
        tx << encode_varint(actual_change_script.length / 2)
        tx << actual_change_script
      end

      # Locktime (4 bytes, little-endian)
      tx << to_le32(0)

      [tx, utxos.length]
    end

    # Select the minimum set of UTXOs needed to fund a deployment using a
    # largest-first strategy. Returns the selected subset; raises ArgumentError
    # when funds are insufficient.
    #
    # @param utxos [Array<Utxo>] available UTXOs
    # @param target_satoshis [Integer] amount to place in the contract output
    # @param locking_script_byte_len [Integer] byte length of the locking script
    # @param fee_rate [Integer] satoshis per kilobyte
    # @param extra_input_bytes [Integer] serialized size of any non-P2PKH inputs
    #   the same tx spends (the contract/covenant input) — keeps the fee, and
    #   therefore how much funding is selected, from being under-provisioned
    #   (finding C2). Defaults to 0.
    # @param extra_output_bytes [Integer] framing of any outputs beyond the single
    #   continuation (multi-output / raw / data outputs) — same purpose (finding
    #   C15). Defaults to 0.
    # @return [Array<Utxo>]
    def select_utxos(utxos, target_satoshis, locking_script_byte_len, fee_rate: 100,
                     extra_input_bytes: 0, extra_output_bytes: 0)
      sorted   = utxos.sort_by { |u| -u.satoshis }
      selected = []
      total    = 0

      sorted.each do |utxo|
        selected << utxo
        total += utxo.satoshis
        fee = estimate_deploy_fee(
          selected.length, locking_script_byte_len, fee_rate,
          extra_input_bytes: extra_input_bytes, extra_output_bytes: extra_output_bytes
        )
        return selected if total >= target_satoshis + fee
      end

      raise ArgumentError,
            "select_utxos: insufficient funds. " \
            "Need #{target_satoshis} sats plus fee, have #{total}"
    end

    # Estimate the fee for a deploy transaction.
    #
    # Accounts for: overhead, P2PKH inputs, the contract output (variable-size
    # script), and one P2PKH change output.
    #
    # @param num_inputs [Integer] number of inputs
    # @param locking_script_byte_len [Integer] byte length of the locking script
    # @param fee_rate [Integer] satoshis per kilobyte (minimum 1)
    # @param extra_input_bytes [Integer] serialized byte size of any NON-P2PKH
    #   inputs this fee must also cover (e.g. a contract/covenant input spent in
    #   the same tx). Defaults to 0 — pure-deploy and funding-only selection are
    #   unaffected. Used by +prepare_call+ so funding coin-selection sizes the fee
    #   against the real contract-input unlock bytes (tens of KB for a MERGE that
    #   embeds both parent txs) instead of ignoring them (finding C2).
    # @param extra_output_bytes [Integer] serialized framing (8 + varint +
    #   scriptLen) of every output BEYOND the single +locking_script_byte_len+
    #   one — additional multi-outputs, raw outputs (finding G1) and data outputs.
    #   Defaults to 0. A call-path selection that ignored them under-provisioned
    #   funding on multi-output / large-dataOutput calls (finding C15). Deploy
    #   passes 0.
    # @return [Integer] estimated fee in satoshis
    def estimate_deploy_fee(num_inputs, locking_script_byte_len, fee_rate = 100,
                            extra_input_bytes: 0, extra_output_bytes: 0)
      rate               = [1, fee_rate].max
      inputs_size        = num_inputs * P2PKH_INPUT_SIZE + extra_input_bytes
      contract_out_size  = 8 + varint_byte_size(locking_script_byte_len) + locking_script_byte_len
      change_output_size = P2PKH_OUTPUT_SIZE
      tx_size            = TX_OVERHEAD + inputs_size + contract_out_size + extra_output_bytes + change_output_size
      (tx_size * rate + 999) / 1000
    end

    # Build a standard P2PKH locking script.
    #
    # Accepted input formats (parity with Go BuildP2PKHScript / TS buildP2PKHScript):
    # - 40-char hex: raw 20-byte pubkey hash
    # - 66-char hex: compressed public key (hashed with HASH160)
    # - 130-char hex: uncompressed public key (hashed with HASH160)
    # - otherwise: Base58Check P2PKH address (checksum and version verified)
    # Returns the script as hex: +76a914{20-byte-hash}88ac+.
    #
    # @param address [String] pubkey hash, public key, or Base58Check address
    # @return [String] hex-encoded P2PKH script
    # @raise [ArgumentError] if the input is none of the above
    def build_p2pkh_script(address)
      pub_key_hash =
        if address.length == 40 && hex_string?(address)
          address
        elsif [66, 130].include?(address.length) && hex_string?(address)
          Digest::RMD160.hexdigest(Digest::SHA256.digest([address].pack('H*')))
        else
          address_to_pubkey_hash(address)
        end

      "76a914#{pub_key_hash}88ac"
    end

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    private_constant :P2PKH_INPUT_SIZE, :P2PKH_OUTPUT_SIZE, :TX_OVERHEAD

    # Encode an integer as a Bitcoin-style varint (hex string).
    # @param n [Integer]
    # @return [String] hex
    def encode_varint(n)
      if n < 0xFD
        format('%02x', n)
      elsif n <= 0xFFFF
        'fd' + [n].pack('v').unpack1('H*')
      elsif n <= 0xFFFFFFFF
        'fe' + [n].pack('V').unpack1('H*')
      else
        'ff' + [n].pack('Q<').unpack1('H*')
      end
    end

    # Return the byte size of a varint encoding for +n+.
    # @param n [Integer]
    # @return [Integer]
    def varint_byte_size(n)
      return 1 if n < 0xFD
      return 3 if n <= 0xFFFF
      return 5 if n <= 0xFFFFFFFF

      9
    end

    # Encode a 32-bit unsigned integer as 4 little-endian bytes (hex string).
    def to_le32(n)
      [n].pack('V').unpack1('H*')
    end

    # Encode a 64-bit unsigned integer as 8 little-endian bytes (hex string).
    def to_le64(n)
      [n].pack('Q<').unpack1('H*')
    end

    # Reverse the byte order of a hex string (converts txid to wire format).
    def reverse_hex(hex_str)
      [hex_str].pack('H*').reverse.unpack1('H*')
    end

    # Return true if +str+ is a valid hexadecimal string.
    def hex_string?(str)
      str.match?(/\A[0-9a-fA-F]+\z/)
    end

    # Decode a Base58-encoded string to bytes.
    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.freeze

    def base58_decode(encoded)
      num = 0
      encoded.each_char do |c|
        digit = BASE58_ALPHABET.index(c)
        raise ArgumentError, "invalid Base58 character #{c.inspect} in #{encoded.inspect}" if digit.nil?

        num = (num * 58) + digit
      end

      result = []
      while num > 0
        num, rem = num.divmod(256)
        result.unshift(rem)
      end

      # Leading '1' characters map to zero bytes.
      pad = encoded.chars.take_while { |c| c == '1' }.length
      ([0] * pad + result).pack('C*')
    end

    # Extract the 20-byte pubkey hash from a Base58Check P2PKH address,
    # verifying the SHA256d checksum and the version byte (0x00 mainnet,
    # 0x6f testnet/regtest).
    # @return [String] lowercase hex
    # @raise [ArgumentError] on a bad character, length, checksum or version
    def address_to_pubkey_hash(address)
      decoded = base58_decode(address)
      raise ArgumentError, "invalid address length: #{decoded.bytesize}" unless decoded.bytesize == 25

      payload = decoded.byteslice(0, 21)
      checksum = Digest::SHA256.digest(Digest::SHA256.digest(payload)).byteslice(0, 4)
      raise ArgumentError, "invalid address checksum: #{address.inspect}" unless checksum == decoded.byteslice(21, 4)

      version = payload.getbyte(0)
      unless [0x00, 0x6f].include?(version)
        raise ArgumentError,
              format('unsupported address version byte 0x%02x (expected 0x00 or 0x6f P2PKH): %s', version, address)
      end

      payload.byteslice(1, 20).unpack1('H*')
    end

    private_constant :BASE58_ALPHABET
  end
end
