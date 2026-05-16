# frozen_string_literal: true

require 'digest'

# BIP-143 sighash + raw-transaction helpers used by the pure-Ruby fallback
# path of {Runar::SDK::LocalSigner}.  These are pure serialization and
# double-SHA256 hashing — no new crypto is introduced.
#
# The implementation mirrors {Runar::SDK::LocalSigner}'s Python sibling at
# packages/runar-py/runar/sdk/local_signer.py.  Cross-tier byte-level
# equivalence is what lets the fallback produce signatures interchangeable
# with bsv-sdk.

module Runar
  module SDK
    # BIP-143 sighash preimage computation + supporting raw-tx parser.
    module BIP143
      module_function

      # Parse a raw Bitcoin transaction into its component parts.
      #
      # @param data [String] binary transaction bytes
      # @return [Hash{Symbol => Object}] with :version, :inputs, :outputs, :locktime
      #   Each input is a Hash with :prev_txid (32 bytes), :prev_output_index, :sequence.
      #   Each output is a Hash with :satoshis and :script (bytes).
      def parse_raw_tx(data)
        pos = 0

        read = lambda do |n|
          raise ArgumentError, 'transaction hex too short' if pos + n > data.bytesize

          chunk = data.byteslice(pos, n)
          pos += n
          chunk
        end

        read_u32_le = lambda do
          read.call(4).unpack1('V')
        end

        read_u64_le = lambda do
          lo, hi = read.call(8).unpack('VV')
          (hi << 32) | lo
        end

        read_var_int = lambda do
          first = read.call(1).bytes.first
          case first
          when 0xfd then read.call(2).unpack1('v')
          when 0xfe then read.call(4).unpack1('V')
          when 0xff
            lo, hi = read.call(8).unpack('VV')
            (hi << 32) | lo
          else first
          end
        end

        version = read_u32_le.call

        inputs = []
        in_count = read_var_int.call
        in_count.times do
          prev_txid = read.call(32)
          prev_idx = read_u32_le.call
          script_len = read_var_int.call
          read.call(script_len) # skip scriptSig
          sequence = read_u32_le.call
          inputs << {
            prev_txid: prev_txid,
            prev_output_index: prev_idx,
            sequence: sequence
          }
        end

        outputs = []
        out_count = read_var_int.call
        out_count.times do
          sats = read_u64_le.call
          script_len = read_var_int.call
          script = read.call(script_len)
          outputs << { satoshis: sats, script: script }
        end

        locktime = read_u32_le.call

        { version: version, inputs: inputs, outputs: outputs, locktime: locktime }
      end

      # Serialize +n+ as a Bitcoin variable-length integer.
      #
      # @param n [Integer] non-negative integer
      # @return [String] binary varint encoding
      def write_var_int(n)
        if n < 0xfd
          [n].pack('C')
        elsif n <= 0xffff
          [0xfd, n].pack('Cv')
        elsif n <= 0xffffffff
          [0xfe, n].pack('CV')
        else
          [0xff, n & 0xffffffff, n >> 32].pack('CVV')
        end
      end

      # Double SHA-256 (Bitcoin's "hash256").
      def sha256d(data)
        Digest::SHA256.digest(Digest::SHA256.digest(data))
      end

      # Compute the BIP-143 sighash digest for one input of a parsed transaction.
      #
      # @param tx           [Hash]    output of {parse_raw_tx}
      # @param input_index  [Integer] index of the input being signed
      # @param subscript    [String]  binary scriptCode for this input
      # @param satoshis     [Integer] value of the UTXO being spent
      # @param sighash_type [Integer] sighash flags (typically 0x41 = ALL|FORKID)
      # @return [String] 32-byte binary digest
      def bip143_sighash(tx, input_index, subscript, satoshis, sighash_type)
        hash_prevouts = sha256d(
          tx[:inputs].map { |inp| inp[:prev_txid] + [inp[:prev_output_index]].pack('V') }.join
        )

        hash_sequence = sha256d(
          tx[:inputs].map { |inp| [inp[:sequence]].pack('V') }.join
        )

        hash_outputs = sha256d(
          tx[:outputs].map { |out|
            [out[:satoshis] & 0xffffffff, out[:satoshis] >> 32].pack('VV') +
              write_var_int(out[:script].bytesize) + out[:script]
          }.join
        )

        inp = tx[:inputs][input_index]
        preimage = [tx[:version]].pack('V') +
                   hash_prevouts +
                   hash_sequence +
                   inp[:prev_txid] +
                   [inp[:prev_output_index]].pack('V') +
                   write_var_int(subscript.bytesize) + subscript +
                   [satoshis & 0xffffffff, satoshis >> 32].pack('VV') +
                   [inp[:sequence]].pack('V') +
                   hash_outputs +
                   [tx[:locktime]].pack('V') +
                   [sighash_type & 0xffffffff].pack('V')

        sha256d(preimage)
      end

      # Bitcoin Base58 alphabet.
      BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

      # Encode +payload+ as a Base58Check string with the standard 4-byte
      # double-SHA256 checksum suffix.
      def base58check_encode(payload)
        checksum = Digest::SHA256.digest(Digest::SHA256.digest(payload))[0, 4]
        full = payload + checksum

        num = full.empty? ? 0 : full.unpack1('H*').to_i(16)
        encoded = +''
        while num.positive?
          num, rem = num.divmod(58)
          encoded.prepend(BASE58_ALPHABET[rem])
        end

        full.each_byte do |b|
          break unless b.zero?

          encoded.prepend('1')
        end

        encoded
      end
    end
  end
end
