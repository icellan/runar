# frozen_string_literal: true

# DoS-bound input limits + typed errors for the Ruby compiler frontend.
#
# Mirrors InputLimits from packages/runar-ir-schema/src/input-limits.ts.
# See compilers/go/frontend/input_limits.go for the reference shape.

module RunarCompiler
  module Frontend
    module InputLimits
      # Mirrors InputLimits.MAX_SOURCE_BYTES (4 MiB) from the TS schema package.
      # Rúnar source files larger than this are rejected at the parser entry
      # point (Compiler._parse_source) BEFORE any tokenizer touches the input.
      # BUG-008 follow-up.
      MAX_SOURCE_BYTES = 4 * 1024 * 1024

      # Raised when a source payload exceeds MAX_SOURCE_BYTES at a public
      # parser entry point. Distinct typed exception so callers can
      # distinguish DoS-bound rejection from generic syntax errors.
      class SourceSizeExceededError < StandardError
        attr_reader :limit, :actual

        def initialize(limit:, actual:)
          super("source exceeds MAX_SOURCE_BYTES (limit=#{limit}, actual=#{actual})")
          @limit = limit
          @actual = actual
        end
      end

      # Raise SourceSizeExceededError if source.bytesize > MAX_SOURCE_BYTES.
      def self.assert_source_bytes_under_limit(source)
        n = source.bytesize
        return if n <= MAX_SOURCE_BYTES

        raise SourceSizeExceededError.new(limit: MAX_SOURCE_BYTES, actual: n)
      end
    end
  end
end
