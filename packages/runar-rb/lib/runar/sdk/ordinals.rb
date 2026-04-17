# frozen_string_literal: true

# 1sat Ordinals support — build, parse, find, and strip inscription envelopes.
#
# Envelope layout:
#   OP_FALSE OP_IF PUSH("ord") OP_1 PUSH(<content-type>) OP_0 PUSH(<data>) OP_ENDIF
#
# Hex:
#   00 63 03 6f7264 51 <push content-type> 00 <push data> 68
#
# The envelope is a no-op (OP_FALSE causes the IF block to be skipped)
# and can be placed anywhere in a script without affecting execution.
#
# BSV-20 (v1) and BSV-21 (v2) token inscription helpers are also provided.

require 'json'

module Runar
  module SDK
    # Inscription data: content type and hex-encoded payload.
    Inscription = Struct.new(:content_type, :data, keyword_init: true)

    # Hex-char offsets bounding an inscription envelope within a script.
    EnvelopeBounds = Struct.new(:start_hex, :end_hex, keyword_init: true)

    # Envelope build/parse/strip helpers.
    module Ordinals
      module_function

      # -------------------------------------------------------------------
      # Push-data encoding (local copy, same logic as State.encode_push_data)
      # -------------------------------------------------------------------

      def encode_push_data(data_hex)
        return '00' if data_hex.empty? # OP_0

        data_len = data_hex.length / 2

        if data_len <= 75
          format('%02x', data_len) + data_hex
        elsif data_len <= 0xFF
          '4c' + format('%02x', data_len) + data_hex
        elsif data_len <= 0xFFFF
          '4d' + [data_len].pack('v').unpack1('H*') + data_hex
        else
          '4e' + [data_len].pack('V').unpack1('H*') + data_hex
        end
      end
      private_class_method :encode_push_data

      # Convert a UTF-8 string to its hex representation.
      def utf8_to_hex(str)
        str.encode('UTF-8').bytes.map { |b| format('%02x', b) }.join
      end
      private_class_method :utf8_to_hex

      # Convert a hex string to UTF-8.
      def hex_to_utf8(hex)
        [hex].pack('H*').force_encoding('UTF-8')
      end
      private_class_method :hex_to_utf8

      # -------------------------------------------------------------------
      # Build
      # -------------------------------------------------------------------

      # Build a 1sat ordinals inscription envelope as hex.
      #
      # @param content_type [String] MIME type (e.g. "image/png", "application/bsv-20")
      # @param data [String] Hex-encoded inscription content
      # @return [String] Hex string of the full envelope script fragment
      def build_inscription_envelope(content_type, data)
        content_type_hex = utf8_to_hex(content_type)

        # OP_FALSE (00) OP_IF (63) PUSH "ord" (03 6f7264) OP_1 (51)
        hex = '006303' + '6f7264' + '51'
        # PUSH content-type
        hex += encode_push_data(content_type_hex)
        # OP_0 (00) -- content delimiter
        hex += '00'
        # PUSH data
        hex += encode_push_data(data)
        # OP_ENDIF (68)
        hex += '68'

        hex
      end

      # -------------------------------------------------------------------
      # Parse / Find
      # -------------------------------------------------------------------

      # Read a push-data value at the given hex offset. Returns [data_hex,
      # bytes_read] or nil if invalid.
      def read_push_data(script_hex, offset)
        return nil if offset + 2 > script_hex.length

        opcode = script_hex[offset, 2].to_i(16)

        if opcode >= 0x01 && opcode <= 0x4B
          data_len = opcode * 2
          return nil if offset + 2 + data_len > script_hex.length

          [script_hex[offset + 2, data_len], 2 + data_len]
        elsif opcode == 0x4C
          return nil if offset + 4 > script_hex.length

          len = script_hex[offset + 2, 2].to_i(16)
          data_len = len * 2
          return nil if offset + 4 + data_len > script_hex.length

          [script_hex[offset + 4, data_len], 4 + data_len]
        elsif opcode == 0x4D
          return nil if offset + 6 > script_hex.length

          lo = script_hex[offset + 2, 2].to_i(16)
          hi = script_hex[offset + 4, 2].to_i(16)
          len = lo | (hi << 8)
          data_len = len * 2
          return nil if offset + 6 + data_len > script_hex.length

          [script_hex[offset + 6, data_len], 6 + data_len]
        elsif opcode == 0x4E
          return nil if offset + 10 > script_hex.length

          b0 = script_hex[offset + 2, 2].to_i(16)
          b1 = script_hex[offset + 4, 2].to_i(16)
          b2 = script_hex[offset + 6, 2].to_i(16)
          b3 = script_hex[offset + 8, 2].to_i(16)
          len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
          data_len = len * 2
          return nil if offset + 10 + data_len > script_hex.length

          [script_hex[offset + 10, data_len], 10 + data_len]
        end
      end
      private_class_method :read_push_data

      # Compute the number of hex chars an opcode occupies (including its push
      # data) so we can advance past it while walking a script.
      def opcode_size(script_hex, offset)
        return 2 if offset + 2 > script_hex.length

        opcode = script_hex[offset, 2].to_i(16)

        if opcode >= 0x01 && opcode <= 0x4B
          2 + opcode * 2
        elsif opcode == 0x4C
          return 2 if offset + 4 > script_hex.length

          len = script_hex[offset + 2, 2].to_i(16)
          4 + len * 2
        elsif opcode == 0x4D
          return 2 if offset + 6 > script_hex.length

          lo = script_hex[offset + 2, 2].to_i(16)
          hi = script_hex[offset + 4, 2].to_i(16)
          6 + (lo | (hi << 8)) * 2
        elsif opcode == 0x4E
          return 2 if offset + 10 > script_hex.length

          b0 = script_hex[offset + 2, 2].to_i(16)
          b1 = script_hex[offset + 4, 2].to_i(16)
          b2 = script_hex[offset + 6, 2].to_i(16)
          b3 = script_hex[offset + 8, 2].to_i(16)
          10 + (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) * 2
        else
          2
        end
      end
      private_class_method :opcode_size

      # Find the inscription envelope within a script hex string.
      #
      # Walks the script as Bitcoin Script opcodes looking for the pattern:
      #   OP_FALSE(00) OP_IF(63) PUSH3 "ord"(03 6f7264) ...
      #
      # @param script_hex [String]
      # @return [EnvelopeBounds, nil] Hex-char offsets of the envelope, or nil if not found.
      def find_inscription_envelope(script_hex)
        offset = 0
        len = script_hex.length

        while offset + 2 <= len
          opcode = script_hex[offset, 2].to_i(16)

          # Look for OP_FALSE (0x00)
          if opcode == 0x00
            # Check: OP_IF (63) PUSH3 (03) "ord" (6f7264)
            if offset + 12 <= len &&
               script_hex[offset + 2, 2] == '63' &&
               script_hex[offset + 4, 8] == '036f7264'

              envelope_start = offset
              # Skip: OP_FALSE(2) + OP_IF(2) + PUSH3 "ord"(8) = 12 hex chars
              pos = offset + 12

              # Expect OP_1 (0x51)
              if pos + 2 > len || script_hex[pos, 2] != '51'
                offset += 2
                next
              end
              pos += 2 # skip OP_1

              # Read content-type push
              ct_push = read_push_data(script_hex, pos)
              unless ct_push
                offset += 2
                next
              end
              pos += ct_push[1]

              # Expect OP_0 (0x00) -- content delimiter
              if pos + 2 > len || script_hex[pos, 2] != '00'
                offset += 2
                next
              end
              pos += 2 # skip OP_0

              # Read data push
              data_push = read_push_data(script_hex, pos)
              unless data_push
                offset += 2
                next
              end
              pos += data_push[1]

              # Expect OP_ENDIF (0x68)
              if pos + 2 > len || script_hex[pos, 2] != '68'
                offset += 2
                next
              end
              pos += 2 # skip OP_ENDIF

              return EnvelopeBounds.new(start_hex: envelope_start, end_hex: pos)
            end
          end

          # Advance past this opcode
          offset += opcode_size(script_hex, offset)
        end

        nil
      end

      # Parse an inscription envelope from a script hex string.
      #
      # @param script_hex [String]
      # @return [Inscription, nil] The inscription data, or nil if no envelope is found.
      def parse_inscription_envelope(script_hex)
        bounds = find_inscription_envelope(script_hex)
        return nil unless bounds

        envelope_hex = script_hex[bounds.start_hex...bounds.end_hex]

        # Parse the envelope contents:
        # 00 63 03 6f7264 51 <ct-push> 00 <data-push> 68
        pos = 12 # skip OP_FALSE + OP_IF + PUSH3 "ord"
        pos += 2 # skip OP_1

        ct_push = read_push_data(envelope_hex, pos)
        return nil unless ct_push

        pos += ct_push[1]
        pos += 2 # skip OP_0

        data_push = read_push_data(envelope_hex, pos)
        return nil unless data_push

        Inscription.new(
          content_type: hex_to_utf8(ct_push[0]),
          data: data_push[0]
        )
      end

      # Remove the inscription envelope from a script, returning the bare script.
      #
      # @param script_hex [String]
      # @return [String] Script hex with the envelope removed, or the original if none found.
      def strip_inscription_envelope(script_hex)
        bounds = find_inscription_envelope(script_hex)
        return script_hex unless bounds

        script_hex[0, bounds.start_hex] + script_hex[bounds.end_hex..]
      end

      # -------------------------------------------------------------------
      # BSV-20 (v1) -- tick-based fungible tokens
      # -------------------------------------------------------------------

      # Build a BSV-20 deploy inscription.
      #
      # @param tick [String] ticker symbol
      # @param max [String] maximum supply
      # @param lim [String, nil] mint limit per transaction
      # @param dec [String, nil] decimal places
      # @return [Inscription]
      def bsv20_deploy(tick:, max:, lim: nil, dec: nil)
        obj = { 'p' => 'bsv-20', 'op' => 'deploy', 'tick' => tick, 'max' => max }
        obj['lim'] = lim unless lim.nil?
        obj['dec'] = dec unless dec.nil?
        json_inscription(obj)
      end

      # Build a BSV-20 mint inscription.
      #
      # @param tick [String] ticker symbol
      # @param amt [String] amount to mint
      # @return [Inscription]
      def bsv20_mint(tick:, amt:)
        json_inscription({ 'p' => 'bsv-20', 'op' => 'mint', 'tick' => tick, 'amt' => amt })
      end

      # Build a BSV-20 transfer inscription.
      #
      # @param tick [String] ticker symbol
      # @param amt [String] amount to transfer
      # @return [Inscription]
      def bsv20_transfer(tick:, amt:)
        json_inscription({ 'p' => 'bsv-20', 'op' => 'transfer', 'tick' => tick, 'amt' => amt })
      end

      # -------------------------------------------------------------------
      # BSV-21 (v2) -- ID-based fungible tokens
      # -------------------------------------------------------------------

      # Build a BSV-21 deploy+mint inscription.
      #
      # @param amt [String] amount to mint
      # @param dec [String, nil] decimal places
      # @param sym [String, nil] symbol
      # @param icon [String, nil] icon reference
      # @return [Inscription]
      def bsv21_deploy_mint(amt:, dec: nil, sym: nil, icon: nil)
        obj = { 'p' => 'bsv-20', 'op' => 'deploy+mint', 'amt' => amt }
        obj['dec'] = dec unless dec.nil?
        obj['sym'] = sym unless sym.nil?
        obj['icon'] = icon unless icon.nil?
        json_inscription(obj)
      end

      # Build a BSV-21 transfer inscription.
      #
      # @param id [String] token ID (format: "<txid>_<vout>")
      # @param amt [String] amount to transfer
      # @return [Inscription]
      def bsv21_transfer(id:, amt:)
        json_inscription({ 'p' => 'bsv-20', 'op' => 'transfer', 'id' => id, 'amt' => amt })
      end

      # -------------------------------------------------------------------
      # Private helpers
      # -------------------------------------------------------------------

      def json_inscription(obj)
        Inscription.new(
          content_type: 'application/bsv-20',
          data: utf8_to_hex(JSON.generate(obj))
        )
      end
      private_class_method :json_inscription
    end
  end
end
