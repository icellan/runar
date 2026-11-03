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

      # 32 zero bytes: what BIP-143 puts in hashPrevouts / hashSequence /
      # hashOutputs when the sighash flags exclude them.
      ZERO32 = ("\x00".b * 32).freeze

      # Build the BIP-143 sighash preimage for one input of a parsed transaction.
      #
      # F-137: this is the ONLY BIP-143 preimage builder in the Ruby SDK. Both
      # {Runar::SDK.compute_preimage} (OP_PUSH_TX / WalletSigner) and
      # {Runar::SDK::LocalSigner}'s pure-Ruby backend (via {bip143_sighash})
      # go through it. LocalSigner used to have its own copy that skipped the
      # issue-#123 per-flag zeroing below and signed the wrong digest for every
      # flag other than ALL|FORKID.
      #
      # @param tx           [Hash]    output of {parse_raw_tx}
      # @param input_index  [Integer] index of the input being signed
      # @param subscript    [String]  binary scriptCode for this input
      # @param satoshis     [Integer] value of the UTXO being spent
      # @param sighash_type [Integer] sighash flags (typically 0x41 = ALL|FORKID)
      # @return [String] binary preimage
      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
      def bip143_preimage(tx, input_index, subscript, satoshis, sighash_type)
        base = sighash_type & 0x1f
        acp  = (sighash_type & 0x80) != 0

        # hashPrevouts. Issue #123: ANYONECANPAY zeroes it (only this input is signed).
        hash_prevouts =
          if acp
            ZERO32.dup
          else
            sha256d(tx[:inputs].map { |inp| inp[:prev_txid] + [inp[:prev_output_index]].pack('V') }.join)
          end

        # hashSequence. Issue #123: zeroed under anything but pure SIGHASH_ALL
        # (NONE / SINGLE / ANYONECANPAY all clear it).
        hash_sequence =
          if base == 0x01 && !acp
            sha256d(tx[:inputs].map { |inp| [inp[:sequence]].pack('V') }.join)
          else
            ZERO32.dup
          end

        # hashOutputs by sighash base (issue #123):
        #   ALL    -> hash256(all outputs)
        #   SINGLE -> hash256(the single output at THIS input's index), or 32 zero
        #             bytes when input_index >= outputs.length. It must NOT digest
        #             the whole output set — under SINGLE every other output is
        #             attacker-controllable (F5).
        #   NONE   -> 32 zero bytes (no outputs committed)
        hash_outputs =
          if base == 0x02 # NONE
            ZERO32.dup
          elsif base == 0x03 # SINGLE
            if input_index < tx[:outputs].length
              sha256d(serialize_output(tx[:outputs][input_index]))
            else
              ZERO32.dup
            end
          else
            sha256d(tx[:outputs].map { |out| serialize_output(out) }.join)
          end

        inp = tx[:inputs][input_index]
        [tx[:version]].pack('V') +
          hash_prevouts +
          hash_sequence +
          inp[:prev_txid] +
          [inp[:prev_output_index]].pack('V') +
          write_var_int(subscript.bytesize) + subscript +
          [satoshis].pack('Q<') +
          [inp[:sequence]].pack('V') +
          hash_outputs +
          [tx[:locktime]].pack('V') +
          [sighash_type & 0xffffffff].pack('V')
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

      # Serialize one output as value (8 LE) || varint(len) || script.
      def serialize_output(out)
        [out[:satoshis]].pack('Q<') + write_var_int(out[:script].bytesize) + out[:script]
      end

      # Compute the BIP-143 sighash digest for one input of a parsed transaction:
      # sha256d of {bip143_preimage}. Same parameters.
      #
      # @return [String] 32-byte binary digest
      def bip143_sighash(tx, input_index, subscript, satoshis, sighash_type)
        sha256d(bip143_preimage(tx, input_index, subscript, satoshis, sighash_type))
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
