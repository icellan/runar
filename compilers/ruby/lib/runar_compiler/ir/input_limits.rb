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
    end
  end
end
