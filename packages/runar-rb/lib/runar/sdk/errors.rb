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

    # Raised when MockProvider refuses to acknowledge a broadcast (testing-gap
    # remediation Phase A5). Distinct typed exception so a spec can assert the
    # fund-safety gate fired, rather than matching on a generic RuntimeError.
    class BroadcastRejected < StandardError; end

    # Raise ScriptSizeExceededError if `script_hex` (hex-encoded) exceeds
    # `limit` bytes. Hex is 2 chars per byte; tolerate odd-length defensively.
    def self.assert_script_hex_under_limit(script_hex, limit, context)
      actual_bytes = (script_hex.length + 1) / 2
      return if actual_bytes <= limit

      raise ScriptSizeExceededError.new(limit: limit, actual: actual_bytes, context: context)
    end

    # Raised when an artifact reaches a builtin the compiler does not claim is
    # sound and the caller has not acknowledged it (R-062 / CL-BUG-105).
    class UnsoundPrimitiveError < StandardError
      attr_reader :missing, :context

      def initialize(missing:, context:)
        @missing = missing
        @context = context
        plural = missing.length == 1 ? '' : 's'
        quoted = missing.map { |m| "'#{m}'" }.join(', ')
        super(
          "#{context}: this artifact reaches #{missing.length} builtin#{plural} the compiler " \
          "does not claim is sound: #{missing.join(', ')}. The compiler emitted it only " \
          "because the gap was acknowledged at COMPILE time; funding it is a second " \
          "decision, and this SDK will not make it for you. Pass " \
          "DeployOptions.new(acknowledge_unsound: [#{quoted}]) to proceed"
        )
      end
    end

    # Raise UnsoundPrimitiveError unless every unsound primitive the artifact
    # declares appears in +acknowledged+ (R-062).
    #
    # The compiler refuses to emit a script reaching +verifySP1FRI+ unless the
    # author wrote +@acknowledgeUnsoundSP1FriVerifier+ or the invoker passed
    # +--acknowledge-unsound-sp1-fri+ (R-012). That acknowledgement stopped at
    # whoever ran the compiler: the artifact handed on afterwards looked like
    # any other and every SDK funded it in silence. The compiler now stamps
    # +unsoundPrimitives+ into the artifact, and this is the SDK half.
    #
    # Deploy only, deliberately. Spending an already-deployed contract is how
    # funds are RECOVERED from one.
    def self.assert_unsound_primitives_acknowledged(artifact, acknowledged, context)
      declared = Array(artifact&.unsound_primitives)
      return if declared.empty?

      ok = Array(acknowledged)
      missing = declared.reject { |p| ok.include?(p) }
      return if missing.empty?

      raise UnsoundPrimitiveError.new(missing: missing, context: context)
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
