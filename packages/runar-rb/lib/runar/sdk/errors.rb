# frozen_string_literal: true

module Runar
  module SDK
    # Mirrors InputLimits.MAX_SCRIPT_BYTES (4 MiB) from the TS schema package.
    # Any locking script larger than this is rejected at SDK entry points
    # (deploy / call / Provider#get_utxos / Provider#get_contract_utxo) BEFORE
    # any signing or broadcast work runs. Largest legitimate script measured
    # is p384-wallet at ~1.87 MB; 4 MiB gives ~2× headroom.
    MAX_SCRIPT_BYTES = 4 * 1024 * 1024

    # Raised when a script exceeds MAX_SCRIPT_BYTES at a public SDK entry
    # point. Distinct typed exception so callers can distinguish DoS-bound
    # rejection from generic decode / network errors.
    class ScriptSizeExceededError < StandardError
      attr_reader :limit, :actual, :context

      def initialize(limit:, actual:, context:)
        @limit = limit
        @actual = actual
        @context = context
        super(
          "script exceeds MAX_SCRIPT_BYTES (limit=#{limit}, actual=#{actual}, context=#{context})"
        )
      end
    end

    # Raise ScriptSizeExceededError if `script_hex` (hex-encoded) exceeds
    # `limit` bytes. Hex is 2 chars per byte; tolerate odd-length defensively.
    def self.assert_script_hex_under_limit(script_hex, limit, context)
      actual_bytes = (script_hex.length + 1) / 2
      return if actual_bytes <= limit

      raise ScriptSizeExceededError.new(limit: limit, actual: actual_bytes, context: context)
    end

    # Raised when a method call requires a caller-supplied intent-intrinsic
    # witness value (auto-injected +_prevOutScript_<i>+ or +_serialisedOutputs+)
    # that has not been set on the RunarContract.
    #
    # Auto-injected witness params come from the compiler when a contract
    # method uses +extractPrevOutputScript(i)+ or +requireOutputP2PKH(...)+.
    # The caller must supply concrete bytes for each before invoking +call+ /
    # +prepare_call+ via +RunarContract#set_prev_out_script+ and
    # +RunarContract#set_serialised_outputs+.
    # Normalize a witness-value hex input (optional 0x prefix, any casing)
    # into a lowercase hex string suitable for the SDK's PUSHDATA helpers.
    # Raises ArgumentError on odd-length / non-hex inputs.
    def self.normalize_witness_hex(value)
      raise ArgumentError, 'witness value: expected String' unless value.is_a?(String)

      h = value
      h = h[2..] if h.start_with?('0x', '0X')
      raise ArgumentError, "witness value: hex string must have even length (got #{h.length})" unless h.length.even?
      raise ArgumentError, 'witness value: invalid hex characters' unless h.match?(/\A[0-9a-fA-F]*\z/)

      h.downcase
    end

    class WitnessValueMissingError < StandardError
      attr_reader :param_name, :method_name, :contract_name

      def initialize(param_name:, method_name:, contract_name:)
        @param_name = param_name
        @method_name = method_name
        @contract_name = contract_name
        super(
          "witness value missing for auto-injected param '#{param_name}' on " \
          "#{contract_name}.#{method_name} — call set_prev_out_script(i, bytes) " \
          "or set_serialised_outputs(bytes) before invoking the method"
        )
      end
    end
  end
end
