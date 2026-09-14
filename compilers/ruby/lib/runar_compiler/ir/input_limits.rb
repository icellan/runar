# frozen_string_literal: true

# DoS-bound input limits + typed errors for the Ruby ANF IR loader.
#
# Mirrors InputLimits from packages/runar-ir-schema/src/input-limits.ts
# and the Go reference at compilers/go/ir/input_limits.go.
#
# BUG-008 follow-up.

module RunarCompiler
  module IR
    module InputLimits
      # Mirrors InputLimits.MAX_IR_BYTES (16 MiB) from the TS schema package.
      MAX_IR_BYTES = 16 * 1024 * 1024

      # Mirrors InputLimits.MAX_NESTING (512) from the TS schema package.
      MAX_IR_NESTING = 512

      # Raised when an IR JSON payload exceeds MAX_IR_BYTES at a public
      # loader entry point. Distinct typed exception so callers can
      # distinguish DoS-bound rejection from generic deserialisation
      # failures.
      class IRSizeExceededError < StandardError
        attr_reader :limit, :actual

        def initialize(limit:, actual:)
          super("IR JSON exceeds MAX_IR_BYTES (limit=#{limit}, actual=#{actual})")
          @limit = limit
          @actual = actual
        end
      end

      # Raised when an IR JSON payload's structural nesting exceeds
      # MAX_IR_NESTING.
      class IRNestingExceededError < StandardError
        attr_reader :limit

        def initialize(limit:)
          super("IR JSON nesting exceeds MAX_NESTING (limit=#{limit})")
          @limit = limit
        end
      end

      # Raise IRSizeExceededError if data.bytesize > MAX_IR_BYTES.
      def self.assert_ir_bytes_under_limit(data)
        n = data.bytesize
        return if n <= MAX_IR_BYTES

        raise IRSizeExceededError.new(limit: MAX_IR_BYTES, actual: n)
      end

      # Walk the raw JSON bytes and raise IRNestingExceededError the
      # first time the structural nesting (objects + arrays) exceeds
      # MAX_IR_NESTING. Runs BEFORE JSON.parse so a deeply-nested
      # payload cannot exhaust the Ruby fiber stack inside the
      # deserializer.
      #
      # Skips strings (respecting backslash-escapes).
      def self.assert_ir_nesting_under_limit(data)
        depth = 0
        in_string = false
        escaped = false
        bytes = data.is_a?(String) ? data.b : data
        bytes.each_byte do |b|
          if in_string
            if escaped
              escaped = false
              next
            end
            if b == 0x5C # '\\'
              escaped = true
              next
            end
            if b == 0x22 # '"'
              in_string = false
            end
            next
          end

          case b
          when 0x22 # '"'
            in_string = true
          when 0x7B, 0x5B # '{' or '['
            depth += 1
            if depth > MAX_IR_NESTING
              raise IRNestingExceededError.new(limit: MAX_IR_NESTING)
            end
          when 0x7D, 0x5D # '}' or ']'
            depth -= 1 if depth.positive?
          end
        end
      end

      # Raised when an IR JSON payload contains a number written in float
      # syntax. N-131.
      #
      # The ANF IR has no float-typed field. The schema
      # (packages/runar-ir-schema/src/schemas/anf-ir.schema.json) types
      # loop.count, loop.step and the raw_script arities as +integer+, and
      # loop.start / load_const.value as integer-or-string; an oversize value
      # is written as a decimal string with an +n+ suffix. So what the six
      # --ir tiers did with a float was unspecified, and they disagreed in
      # emitted BYTES rather than in diagnostics. This tier was the worst of
      # them: it read {"start":1e30} as start = 0 and emitted a script for a
      # loop the IR did not describe, while rust and python read the same
      # field as 1e30.
      #
      # The rule is LEXICAL -- float syntax, not fractional value -- so 1.0
      # and 1e2 are refused too. That is what go and java, the two tiers
      # already correct here, do, and it is the line every tier's JSON parser
      # already draws at the token rather than the value.
      class IRFloatValueError < StandardError
        attr_reader :token

        def initialize(token:)
          @token = token
          super(
            "IR JSON contains a floating-point number (#{token}); every " \
            "numeric field in the ANF IR is an integer (write an oversize " \
            "value as a decimal string with an `n` suffix)"
          )
        end
      end

      # Walk a parsed JSON document and raise IRFloatValueError the first
      # time a Float appears. N-131.
      #
      # Ruby's JSON parser classifies a number token lexically -- 1.0, 1e2
      # and 3.5 all arrive as Float, 5 as Integer -- so the parser has
      # already applied exactly the rule, and this walk only has to act on
      # it. Walking the GENERIC document rather than checking named fields is
      # the point: the fields nobody thought to name (loop.step,
      # raw_script.out_arity) are precisely the ones that diverged.
      def self.assert_no_json_floats(value)
        case value
        when Float
          raise IRFloatValueError.new(token: value.to_s)
        when Hash
          value.each_value { |v| assert_no_json_floats(v) }
        when Array
          value.each { |v| assert_no_json_floats(v) }
        end
      end
    end
  end
end
