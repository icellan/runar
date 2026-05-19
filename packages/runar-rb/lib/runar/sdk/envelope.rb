# frozen_string_literal: true

require 'digest'
require 'json'
require_relative '../ecdsa'

# Signed-broadcast wire protocol for overlay apps. Byte-compatible with the
# TypeScript reference implementation in
# `packages/runar-sdk/src/envelope.ts`.

module Runar
  module SDK
    module Envelope
      VERIFY_REASONS = %w[
        missing-fields expired bad-json envelope-mismatch bad-sig pubkey-not-allowed
      ].freeze

      # ---------------------------------------------------------------------
      # CanonicalJSON
      # ---------------------------------------------------------------------

      # Serialise +value+ to RFC 8785 / JCS canonical JSON. Sorted object keys
      # (UTF-16 code-unit order), no whitespace, ES-style number formatting.
      def self.canonical_json(value)
        out = String.new
        canonical_append(out, value)
        out
      end

      def self.canonical_append(out, value)
        case value
        when nil
          out << 'null'
        when true
          out << 'true'
        when false
          out << 'false'
        when Integer
          out << value.to_s
        when Float
          raise ArgumentError, 'canonical JSON: non-finite number' unless value.finite?
          if value.zero?
            out << '0'
          else
            # Ruby's Float#to_s ("1.0e+21") diverges from ECMA-262
            # Number::toString ("1e+21") for the scientific cases needed by
            # RFC 8785 §3.2.2.3 (audit D5). Run the spec algorithm directly.
            out << format_ecma262_double(value)
          end
        when String
          append_json_string(out, value)
        when Array
          out << '['
          value.each_with_index do |e, i|
            out << ',' unless i.zero?
            canonical_append(out, e)
          end
          out << ']'
        when Hash
          # Sort keys (must be strings) by UTF-16 code-unit order.
          # Dedup the stringified-key list — a Hash with both "k" and :k
          # collapses to one entry; the string-key form takes precedence.
          keys = value.keys.map(&:to_s).uniq.sort_by { |k| k.encode('UTF-16BE').bytes }
          out << '{'
          first = true
          keys.each do |k|
            # Use explicit key-presence (key? / fetch) — `value[k] || value[k.to_sym]`
            # silently rewrites legitimately-falsy values (false, nil, 0, "")
            # to the symbol-key variant, breaking canonical form. RFC 8785 D4.
            v = if value.key?(k)
                  value[k]
                elsif value.key?(k.to_sym)
                  value[k.to_sym]
                else
                  raise KeyError, "canonical JSON: missing key #{k.inspect}"
                end
            out << ',' unless first
            first = false
            append_json_string(out, k)
            out << ':'
            canonical_append(out, v)
          end
          out << '}'
        else
          raise TypeError, "canonical JSON: unsupported type #{value.class}"
        end
      end

      def self.append_json_string(out, str)
        out << '"'
        # Normalise to UTF-8 so each_char yields scalar values. UTF-16BE /
        # ASCII-8BIT inputs are valid Ruby strings but each_char on them
        # behaves byte-pair-wise (UTF-16BE) or byte-wise (BINARY) — both
        # break the codepoint loop below. The encode also surfaces ill-
        # formed sequences as Encoding::UndefinedConversionError /
        # InvalidByteSequenceError, which we catch and turn into the typed
        # canonical-JSON error.
        utf8 = if str.encoding == Encoding::UTF_8
                 str
               else
                 begin
                   str.encode(Encoding::UTF_8)
                 rescue Encoding::UndefinedConversionError,
                        Encoding::InvalidByteSequenceError,
                        Encoding::ConverterNotFoundError => e
                   raise ArgumentError,
                         "canonical JSON: malformed Unicode string (#{e.class}: #{e.message})"
                 end
               end
        unless utf8.valid_encoding?
          raise ArgumentError, 'canonical JSON: malformed Unicode string (invalid UTF-8)'
        end
        utf8.each_char do |c|
          cp = c.ord
          # RFC 8785 §3.2.2.2: lone surrogates (U+D800..U+DFFF) are not
          # valid scalar values and MUST be rejected. Even if a tier's
          # safe string type permits the codepoint, canonical_json refuses
          # to emit it (audit D6).
          if cp >= 0xD800 && cp <= 0xDFFF
            raise ArgumentError,
                  format('canonical JSON: lone surrogate U+%04X in string', cp)
          end
          case c
          when '"' then out << '\\"'
          when '\\' then out << '\\\\'
          when "\b" then out << '\\b'
          when "\f" then out << '\\f'
          when "\n" then out << '\\n'
          when "\r" then out << '\\r'
          when "\t" then out << '\\t'
          else
            if cp < 0x20
              out << format('\\u%04x', cp)
            else
              out << c
            end
          end
        end
        out << '"'
      end

      # Format a finite Float per ECMA-262 §6.1.6.1.13 Number::toString so
      # the wire output matches the TS reference (and every other SDK tier)
      # byte-for-byte. Ruby's Float#to_s emits "1.0e+21" / "1.0e-300" which
      # diverges from JS "1e+21" / "1e-300" (audit D5).
      def self.format_ecma262_double(x)
        return '0' if x.zero?
        return "-#{format_ecma262_double(-x)}" if x.negative?
        # Ruby's Float#to_s prints a shortest-roundtrip decimal. For very
        # large/small values it emits "1.0e+21" / "1.0e-300"; for typical
        # ones, "15000000000.0" or "0.5". We re-derive (digits, k) from the
        # surface form and re-emit per the ECMA rules.
        s = x.to_s
        m_idx = s =~ /[eE]/
        if m_idx
          mantissa = s[0...m_idx]
          exp_part = s[(m_idx + 1)..].to_i
        else
          mantissa = s
          exp_part = 0
        end
        if (dot_idx = mantissa.index('.'))
          int_part = mantissa[0...dot_idx]
          frac_part = mantissa[(dot_idx + 1)..]
        else
          int_part = mantissa
          frac_part = ''
        end
        raw_digits = int_part + frac_part
        # Strip leading zeros (they shift k down).
        leading_zeros = 0
        leading_zeros += 1 while leading_zeros < raw_digits.length && raw_digits[leading_zeros] == '0'
        trimmed = raw_digits[leading_zeros..]
        # Strip trailing zeros to land on significant digits only.
        digits = trimmed.sub(/0+\z/, '')
        return '0' if digits.empty?
        k = int_part.length - leading_zeros + exp_part
        s_len = digits.length
        if k >= s_len && k <= 21
          return digits + ('0' * (k - s_len))
        end
        if k.positive? && k <= 21
          return "#{digits[0...k]}.#{digits[k..]}"
        end
        if k > -6 && k <= 0
          return "0.#{'0' * (-k)}#{digits}"
        end
        exp = k - 1
        exp_str = exp.negative? ? "e-#{-exp}" : "e+#{exp}"
        if s_len == 1
          "#{digits}#{exp_str}"
        else
          "#{digits[0]}.#{digits[1..]}#{exp_str}"
        end
      end

      # ---------------------------------------------------------------------
      # SignedEnvelope
      # ---------------------------------------------------------------------

      # Wire format for a signed broadcast payload.
      SignedEnvelope = Struct.new(:payload, :sig, :pubkey, :nonce, :expiresAt) do
        def to_h
          {
            'payload' => payload,
            'sig' => sig,
            'pubkey' => pubkey,
            'nonce' => nonce,
            'expiresAt' => expiresAt
          }
        end

        def self.from_h(h)
          new(h['payload'], h['sig'], h['pubkey'], h['nonce'].to_i, h['expiresAt'].to_i)
        end
      end

      # Sign an envelope around +data+. +signer+ must be a callable
      # (#call(digest_bytes) -> der_bytes) producing raw-ECDSA DER over the
      # 32-byte sha256 digest. +pubkey_hex+ is the 66-char compressed pubkey.
      def self.sign_envelope(data:, signer:, pubkey:, ttl_ms: 30_000, now_ms: nil)
        nonce = now_ms || (Time.now.to_f * 1000).to_i
        expires_at = nonce + ttl_ms
        merged = data.transform_keys(&:to_s).merge('nonce' => nonce, 'expiresAt' => expires_at)
        payload = canonical_json(merged)
        digest = Digest::SHA256.digest(payload)
        sig_bytes = signer.call(digest)
        SignedEnvelope.new(payload, sig_bytes.unpack1('H*'), pubkey, nonce, expires_at)
      end

      # Verify a signed envelope. Returns a Hash with :ok (bool),
      # :reason (one of VERIFY_REASONS or nil), and :data (parsed payload
      # or nil).
      def self.verify_envelope(envelope:, expected_keys: nil, clock_skew_ms: 5_000, now_ms: nil)
        # 1. Field presence.
        unless envelope.is_a?(SignedEnvelope) &&
               envelope.payload && !envelope.payload.empty? &&
               envelope.sig && !envelope.sig.empty? &&
               envelope.pubkey && !envelope.pubkey.empty? &&
               envelope.nonce && envelope.nonce != 0 &&
               envelope.expiresAt && envelope.expiresAt != 0
          return { ok: false, reason: 'missing-fields', data: nil }
        end

        now = now_ms || (Time.now.to_f * 1000).to_i

        # 2. Expiry.
        return { ok: false, reason: 'expired', data: nil } if envelope.expiresAt < (now - clock_skew_ms)

        # 3. Parse payload.
        parsed = nil
        begin
          parsed = JSON.parse(envelope.payload)
        rescue JSON::ParserError
          return { ok: false, reason: 'bad-json', data: nil }
        end
        return { ok: false, reason: 'bad-json', data: nil } unless parsed.is_a?(Hash)

        # 4. Inner nonce / expiresAt must match outer fields.
        if parsed['nonce'] != envelope.nonce || parsed['expiresAt'] != envelope.expiresAt
          return { ok: false, reason: 'envelope-mismatch', data: parsed }
        end

        # 5. ECDSA verify (raw, no re-hashing).
        begin
          sig_bytes = [envelope.sig].pack('H*')
          pk_bytes = [envelope.pubkey].pack('H*')
        rescue StandardError
          return { ok: false, reason: 'bad-sig', data: parsed }
        end
        digest = Digest::SHA256.digest(envelope.payload)
        return { ok: false, reason: 'bad-sig', data: parsed } unless Runar::ECDSA.ecdsa_verify(sig_bytes, pk_bytes, digest)

        # 6. Allowlist.
        if expected_keys && !expected_keys.include?(envelope.pubkey)
          return { ok: false, reason: 'pubkey-not-allowed', data: parsed }
        end

        { ok: true, reason: nil, data: parsed }
      end
    end
  end
end
