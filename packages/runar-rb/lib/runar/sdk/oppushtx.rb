# frozen_string_literal: true

require 'digest'
require_relative '../ec_primitives'

# OP_PUSH_TX helper for checkPreimage contracts.
#
# Computes the BIP-143 sighash preimage and the deterministic k=1 ECDSA
# signature used by the OP_PUSH_TX technique.  Contracts that use
# checkPreimage() receive both the preimage and the signature as push-data
# in their unlocking script; the on-chain script verifies the preimage
# algebraically rather than verifying a standard ECDSA signature.
#
# The k=1 trick: private key d=1 means the public key is the secp256k1
# generator point G.  Using nonce k=1 produces a reproducible (r, s) pair
# from the sighash alone without needing a private key at all.  This is
# deliberately insecure for normal signing; its only valid use is OP_PUSH_TX.
#
# EC arithmetic is delegated to Runar::ECPrimitives.
# Zero external dependencies — uses only Ruby stdlib (Digest::SHA256).

module Runar
  module SDK
    SIGHASH_ALL_FORKID = 0x41

    module_function

    # Compute the BIP-143 sighash preimage for a transaction input.
    #
    # Parses the raw transaction hex, then assembles the ten-field BIP-143
    # preimage for the given input.  Returns the preimage as a lowercase
    # hex string (208 bytes = 416 hex chars for typical transactions).
    #
    # @param tx_hex          [String]  raw transaction hex
    # @param input_index     [Integer] index of the input being signed
    # @param subscript_hex   [String]  hex-encoded subscript (locking script or
    #                                  the portion after OP_CODESEPARATOR)
    # @param satoshis        [Integer] value of the UTXO being spent
    # @param sighash_type    [Integer] sighash type (default: SIGHASH_ALL|FORKID = 0x41)
    # @return [String] BIP-143 preimage as hex
    def compute_preimage(tx_hex, input_index, subscript_hex, satoshis, sighash_type = SIGHASH_ALL_FORKID)
      tx = parse_raw_tx([tx_hex].pack('H*'))
      subscript = [subscript_hex].pack('H*')

      bip143_preimage(tx, input_index, subscript, satoshis, sighash_type).unpack1('H*')
    end

    # Compute the OP_PUSH_TX DER signature for a preimage.
    #
    # Hashes the preimage with double-SHA256, then signs with private key d=1
    # and nonce k=1.  Returns the DER-encoded signature with the sighash byte
    # appended, hex-encoded.
    #
    # @param preimage_hex [String] BIP-143 preimage as hex (from +compute_preimage+)
    # @return [String] DER signature + sighash byte, hex-encoded
    def sign_preimage_k1(preimage_hex)
      hash = double_sha256(preimage_hex)
      hash_bytes = [hash].pack('H*')

      r, s = ecdsa_sign_k1(hash_bytes)

      # Enforce low-S normalisation.
      half_n = ECPrimitives::SECP256K1_N >> 1
      s = ECPrimitives::SECP256K1_N - s if s > half_n

      der_encode(r, s).unpack1('H*') + format('%02x', SIGHASH_ALL_FORKID)
    end

    # Compute the OP_PUSH_TX DER signature and BIP-143 preimage for a
    # transaction input.
    #
    # Convenience wrapper combining +compute_preimage+ and +sign_preimage_k1+.
    # When +code_separator_index+ is provided and non-negative, only the portion
    # of the subscript after the OP_CODESEPARATOR byte is used as the scriptCode.
    #
    # @param tx_hex               [String]       raw transaction hex
    # @param input_index          [Integer]      index of the input being signed
    # @param subscript_hex        [String]       hex-encoded locking script
    # @param satoshis             [Integer]      value of the UTXO being spent
    # @param code_separator_index [Integer, nil] byte offset of OP_CODESEPARATOR, or -1/nil
    # @return [Array(String, String)] [sig_hex, preimage_hex]
    def compute_op_push_tx(tx_hex, input_index, subscript_hex, satoshis, code_separator_index = -1)
      effective_subscript = get_subscript(subscript_hex, code_separator_index)
      preimage_hex = compute_preimage(tx_hex, input_index, effective_subscript, satoshis)
      sig_hex = sign_preimage_k1(preimage_hex)
      [sig_hex, preimage_hex]
    end

    # Extract the subscript for BIP-143 sighash computation.
    #
    # When +code_separator_index+ is +nil+ or +-1+, the full script is returned.
    # Otherwise everything after the OP_CODESEPARATOR at the given *byte* offset
    # is returned (i.e. bytes from +code_separator_index + 1+ onward).
    #
    # @param script_hex            [String]       hex-encoded locking script
    # @param code_separator_index  [Integer, nil] byte offset of the OP_CODESEPARATOR,
    #                                             or -1 / nil to use the full script
    # @return [String] hex-encoded subscript
    def get_subscript(script_hex, code_separator_index)
      return script_hex if code_separator_index.nil? || code_separator_index.negative?

      # code_separator_index is the byte offset of the OP_CODESEPARATOR opcode
      # itself; the subscript begins at the next byte.
      trim_pos = (code_separator_index + 1) * 2
      return script_hex if trim_pos > script_hex.length

      script_hex[trim_pos..]
    end

    # Double-SHA256 hash (SHA256(SHA256(data))).
    #
    # @param hex [String] hex-encoded input data
    # @return [String] 32-byte digest as lowercase hex
    def double_sha256(hex)
      bytes = [hex].pack('H*')
      Digest::SHA256.hexdigest(Digest::SHA256.digest(bytes))
    end

    # ---------------------------------------------------------------------------
    # Private helpers — OP_PUSH_TX specific signing
    #
    # Single-letter parameter names (r, s, n) are conventional in cryptographic
    # literature.  The cops below are disabled for this section.
    # rubocop:disable Naming/MethodParameterName
    # ---------------------------------------------------------------------------

    # ECDSA sign with private key d=1 and nonce k=1.
    #
    # For OP_PUSH_TX: the generator point G is used as both the nonce point
    # (R = k*G = G) and the public key (Q = d*G = G).  The contract verifies
    # the preimage algebraically rather than checking the signature against a
    # known public key.
    #
    # EC arithmetic is delegated to Runar::ECPrimitives.
    #
    # @param msg_hash [String] 32-byte binary message digest
    # @return [Array(Integer, Integer)] (r, s) signature components
    def ecdsa_sign_k1(msg_hash)
      z = msg_hash.unpack1('H*').to_i(16)
      r = ECPrimitives::SECP256K1_GX % ECPrimitives::SECP256K1_N
      # s = k⁻¹ × (z + r×d) mod N; d=1, k=1 → k⁻¹=1
      s = (z + r) % ECPrimitives::SECP256K1_N
      [r, s]
    end
    private_class_method :ecdsa_sign_k1

    # DER-encode an ECDSA (r, s) pair.
    #
    # @param r [Integer]
    # @param s [Integer]
    # @return [String] binary DER-encoded signature
    def der_encode(r, s)
      r_bytes = int_to_der_bytes(r)
      s_bytes = int_to_der_bytes(s)
      payload = "\x02".b + [r_bytes.bytesize].pack('C') + r_bytes +
                "\x02".b + [s_bytes.bytesize].pack('C') + s_bytes
      "\x30".b + [payload.bytesize].pack('C') + payload
    end
    private_class_method :der_encode

    # Encode a positive integer as a DER INTEGER value (big-endian, minimal,
    # with a leading 0x00 byte added when the high bit is set).
    def int_to_der_bytes(n)
      byte_len = (n.bit_length + 7) / 8
      b = [format('%0*x', byte_len * 2, n)].pack('H*')
      b = "\x00".b + b if b.getbyte(0) & 0x80 != 0
      b
    end
    private_class_method :int_to_der_bytes

    # rubocop:enable Naming/MethodParameterName

    # ---------------------------------------------------------------------------
    # BIP-143 preimage assembly
    # ---------------------------------------------------------------------------

    # Build the full BIP-143 preimage for SIGHASH_ALL|FORKID.
    #
    # @param tx           [Hash]    parsed transaction ({version:, inputs:, outputs:, locktime:})
    # @param input_index  [Integer]
    # @param subscript    [String]  binary subscript bytes
    # @param satoshis     [Integer] value of the UTXO being spent
    # @param sighash_type [Integer]
    # @return [String] binary preimage
    # rubocop:disable Metrics/AbcSize, Metrics/MethodLength, Naming/MethodParameterName
    def bip143_preimage(tx, input_index, subscript, satoshis, sighash_type)
      # hashPrevouts — double-SHA256 of all outpoints.
      prevouts = tx[:inputs].flat_map { |inp| [inp[:prev_txid], [inp[:prev_output_index]].pack('V')] }.join
      hash_prevouts = [double_sha256(prevouts.unpack1('H*'))].pack('H*')

      # hashSequence — double-SHA256 of all input sequences.
      sequences = tx[:inputs].map { |inp| [inp[:sequence]].pack('V') }.join
      hash_sequence = [double_sha256(sequences.unpack1('H*'))].pack('H*')

      # hashOutputs — double-SHA256 of all serialized outputs.
      outputs_data = tx[:outputs].map do |out|
        [out[:satoshis]].pack('Q<') + encode_varint_bin(out[:script].bytesize) + out[:script]
      end.join
      hash_outputs = [double_sha256(outputs_data.unpack1('H*'))].pack('H*')

      inp = tx[:inputs][input_index]

      preimage = +''
      preimage << [tx[:version]].pack('V')              # nVersion (4 LE)
      preimage << hash_prevouts                         # hashPrevouts
      preimage << hash_sequence                         # hashSequence
      preimage << inp[:prev_txid]                       # outpoint txid (32 bytes)
      preimage << [inp[:prev_output_index]].pack('V')   # outpoint index (4 LE)
      preimage << encode_varint_bin(subscript.bytesize) # scriptCode varint
      preimage << subscript                             # scriptCode bytes
      preimage << [satoshis].pack('Q<')                 # value (8 LE)
      preimage << [inp[:sequence]].pack('V')            # nSequence (4 LE)
      preimage << hash_outputs                          # hashOutputs
      preimage << [tx[:locktime]].pack('V')             # nLocktime (4 LE)
      preimage << [sighash_type].pack('V')              # sighash type (4 LE)
      preimage
    end
    # rubocop:enable Metrics/AbcSize, Metrics/MethodLength, Naming/MethodParameterName
    private_class_method :bip143_preimage

    # ---------------------------------------------------------------------------
    # Minimal raw transaction parser
    # ---------------------------------------------------------------------------

    # Parse a raw binary transaction into a simple Hash.
    #
    # @param data [String] binary transaction bytes
    # @return [Hash] {version:, inputs: [...], outputs: [...], locktime:}
    # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
    def parse_raw_tx(data)
      pos = 0

      read = lambda do |n|
        chunk = data.byteslice(pos, n)
        pos += n
        chunk
      end

      version = read.call(4).unpack1('V')
      input_count, vi_len = decode_varint_bin(data, pos)
      pos += vi_len

      inputs = input_count.times.map do
        prev_txid = read.call(32)
        prev_output_idx = read.call(4).unpack1('V')
        script_len, vl = decode_varint_bin(data, pos)
        pos += vl
        read.call(script_len) # scriptSig — discard
        sequence = read.call(4).unpack1('V')
        { prev_txid: prev_txid, prev_output_index: prev_output_idx, sequence: sequence }
      end

      output_count, vi_len = decode_varint_bin(data, pos)
      pos += vi_len

      outputs = output_count.times.map do
        sats = read.call(8).unpack1('Q<')
        script_len, vl = decode_varint_bin(data, pos)
        pos += vl
        script = read.call(script_len)
        { satoshis: sats, script: script }
      end

      locktime = read.call(4).unpack1('V')

      { version: version, inputs: inputs, outputs: outputs, locktime: locktime }
    end
    # rubocop:enable Metrics/AbcSize, Metrics/MethodLength
    private_class_method :parse_raw_tx

    # Decode a Bitcoin varint from binary data at +offset+.
    # Returns [value, bytes_consumed].
    def decode_varint_bin(data, offset)
      first = data.getbyte(offset)
      case first
      when 0...0xFD then [first, 1]
      when 0xFD     then [data.byteslice(offset + 1, 2).unpack1('v'), 3]
      when 0xFE     then [data.byteslice(offset + 1, 4).unpack1('V'), 5]
      else               [data.byteslice(offset + 1, 8).unpack1('Q<'), 9]
      end
    end
    private_class_method :decode_varint_bin

    # Encode a non-negative integer as a Bitcoin varint (binary).
    def encode_varint_bin(num)
      if num < 0xFD
        [num].pack('C')
      elsif num <= 0xFFFF
        "\xfd".b + [num].pack('v')
      elsif num <= 0xFFFFFFFF
        "\xfe".b + [num].pack('V')
      else
        "\xff".b + [num].pack('Q<')
      end
    end
    private_class_method :encode_varint_bin
  end
end
