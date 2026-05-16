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
          elsif value == value.to_i && value.between?(-9_007_199_254_740_992.0, 9_007_199_254_740_992.0)
            out << value.to_i.to_s
          else
            # Ruby's Float#to_s produces shortest-roundtrip; matches ES
            # Number.prototype.toString for typical finite values.
            out << value.to_s
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
          keys = value.keys.map(&:to_s).sort_by { |k| k.encode('UTF-16BE').bytes }
          out << '{'
          first = true
          keys.each do |k|
            v = value[k] || value[k.to_sym]
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
        str.each_char do |c|
          cp = c.ord
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
