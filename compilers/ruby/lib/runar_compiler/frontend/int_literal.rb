# frozen_string_literal: true

# F-026 — integer literals mean what their host language says they mean.
#
# A port of the TS reference (packages/runar-compiler/src/passes/int-literal.ts,
# user decision R15). Every hand-written tokenizer scans a number token over
# every [0-9A-Za-z_] character glued to its first digit and validates the whole
# token against the surface's host-language grammar. The table every tier must
# reproduce is conformance/negatives/int-literal-cases.json.
#
# A lowercase `0x` on .runar.sol / .runar.move / .runar.rs is a Rúnar
# ByteString literal, handled by those tokenizers before a number is scanned;
# on every other surface `0x` is a hexadecimal integer.

module RunarCompiler
  module Frontend
    module IntLiteral
      LANGUAGE = {
        "ts" => "TypeScript", "sol" => "Solidity", "move" => "Move", "go" => "Go", "rs" => "Rust",
        "py" => "Python", "zig" => "Zig", "rb" => "Ruby", "java" => "Java"
      }.freeze

      # A validated literal. +neg_only+ marks a literal valid only as the
      # operand of a unary minus (Java `2147483648`, Rust `128i8`); +value+ is
      # then the positive magnitude.
      Lit = Struct.new(:value, :neg_only)

      DEC = /\A(?:0|[1-9](?:_?[0-9])*)\z/
      RADIX = { "x" => 16, "X" => 16, "o" => 8, "O" => 8, "b" => 2, "B" => 2, "d" => 10, "D" => 10 }.freeze
      MOVE_BITS = { "u8" => 8, "u16" => 16, "u32" => 32, "u64" => 64, "u128" => 128, "u256" => 256 }.freeze
      RUST_BITS = {
        "i8" => [8, true], "i16" => [16, true], "i32" => [32, true], "i64" => [64, true], "i128" => [128, true],
        "isize" => [64, true], "u8" => [8, false], "u16" => [16, false], "u32" => [32, false],
        "u64" => [64, false], "u128" => [128, false], "usize" => [64, false]
      }.freeze

      module_function

      # The TS reference's invalidIntegerLiteral().
      def invalid_integer_literal(surface, text)
        "invalid #{LANGUAGE[surface]} integer literal '#{text}'"
      end

      def number_continue?(ch)
        !ch.nil? && ch.match?(/\A[0-9A-Za-z_]\z/)
      end

      # End (exclusive) of the number token whose first digit is at +pos+.
      def scan_number_end(source, pos)
        i = pos + 1
        i += 1 while i < source.length && number_continue?(source[i])
        i
      end

      def val(digits, radix)
        digits.delete("_").to_i(radix)
      end

      def ok(v, neg_only = false)
        Lit.new(v, neg_only)
      end

      def prefixed(text, *patterns)
        patterns.each do |re|
          m = re.match(text)
          return ok(val(m[1], RADIX[text[1]])) if m
        end
        nil
      end

      def parse_ts(text)
        body = text.end_with?("n") ? text[0...-1] : text
        return ok(val(body, 10)) if DEC.match?(body)

        prefixed(body, /\A0[xX]([0-9a-fA-F](?:_?[0-9a-fA-F])*)\z/, /\A0[oO]([0-7](?:_?[0-7])*)\z/, /\A0[bB]([01](?:_?[01])*)\z/)
      end

      def parse_move(text)
        m = /\A([0-9][0-9_]*)(u8|u16|u32|u64|u128|u256)?\z/.match(text)
        return nil unless m

        v = val(m[1], 10)
        v < (1 << MOVE_BITS[m[2] || "u256"]) ? ok(v) : nil
      end

      def parse_go(text)
        return ok(val(text, 10)) if DEC.match?(text)

        m = /\A0((?:_?[0-7])+)\z/.match(text)
        return ok(val(m[1], 8)) if m

        prefixed(text, /\A0[xX]((?:_?[0-9a-fA-F])+)\z/, /\A0[oO]((?:_?[0-7])+)\z/, /\A0[bB]((?:_?[01])+)\z/)
      end

      def parse_rust(text)
        m = /\A(?:0x([0-9a-fA-F_]*)|0o([0-7_]*)|0b([01_]*)|([0-9][0-9_]*))(i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize)?\z/.match(text)
        return nil unless m

        digits, radix = if m[1] then [m[1], 16]
                        elsif m[2] then [m[2], 8]
                        elsif m[3] then [m[3], 2]
                        else [m[4], 10]
                        end
        return nil unless digits.match?(/[0-9a-fA-F]/)

        v = val(digits, radix)
        # Unsuffixed values are unbounded: rustc stops at u128::MAX, but
        # Rúnar's Int is a bigint and the corpus spells 256-bit constants so.
        return ok(v) if m[5].nil?

        bits, signed = RUST_BITS[m[5]]
        return (v < (1 << bits) ? ok(v) : nil) unless signed

        lo = 1 << (bits - 1)
        return ok(v) if v < lo

        v == lo ? ok(v, true) : nil
      end

      def parse_py(text)
        return ok(val(text, 10)) if /\A(?:[1-9](?:_?[0-9])*|0(?:_?0)*)\z/.match?(text)

        prefixed(text, /\A0[xX]((?:_?[0-9a-fA-F])+)\z/, /\A0[oO]((?:_?[0-7])+)\z/, /\A0[bB]((?:_?[01])+)\z/)
      end

      def parse_zig(text)
        return ok(val(text, 10)) if DEC.match?(text)

        prefixed(text, /\A0x([0-9a-fA-F](?:_?[0-9a-fA-F])*)\z/, /\A0o([0-7](?:_?[0-7])*)\z/, /\A0b([01](?:_?[01])*)\z/)
      end

      def parse_rb(text)
        return ok(val(text, 10)) if DEC.match?(text)

        m = /\A0(_?[0-7](?:_?[0-7])*)\z/.match(text)
        return ok(val(m[1], 8)) if m

        prefixed(text, /\A0[dD]([0-9](?:_?[0-9])*)\z/, /\A0[xX]([0-9a-fA-F](?:_?[0-9a-fA-F])*)\z/,
                 /\A0[oO]([0-7](?:_?[0-7])*)\z/, /\A0[bB]([01](?:_?[01])*)\z/)
      end

      def parse_java(text)
        long = text.end_with?("L", "l")
        body = long ? text[0...-1] : text
        bits = long ? 64 : 32
        if /\A(?:0|[1-9](?:[0-9_]*[0-9])?)\z/.match?(body)
          v = val(body, 10)
          lo = 1 << (bits - 1)
          return ok(v) if v < lo

          return v == lo ? ok(v, true) : nil
        end
        v = nil
        if (m = /\A0([0-7_]*[0-7])\z/.match(body)) then v = val(m[1], 8) end
        if (m = /\A0[xX]([0-9a-fA-F](?:[0-9a-fA-F_]*[0-9a-fA-F])?)\z/.match(body)) then v = val(m[1], 16) end
        if (m = /\A0[bB]([01](?:[01_]*[01])?)\z/.match(body)) then v = val(m[1], 2) end
        return nil if v.nil? || v >= (1 << bits)

        ok(v >= (1 << (bits - 1)) ? v - (1 << bits) : v)
      end

      # The value of the integer literal +text+ (the whole number token) on
      # +surface+, or nil when the host language rejects it.
      def parse(surface, text)
        case surface
        when "ts" then parse_ts(text)
        when "sol" then DEC.match?(text) ? ok(val(text, 10)) : nil
        when "move" then parse_move(text)
        when "go" then parse_go(text)
        when "rs" then parse_rust(text)
        when "py" then parse_py(text)
        when "zig" then parse_zig(text)
        when "rb" then parse_rb(text)
        when "java" then parse_java(text)
        end
      end

      # Scan the number token at +pos+: returns [end, decimal value text, the
      # literal or nil, the text as written]. A refused literal is reported to
      # +lex+ with the shared diagnostic and reads as "0".
      def lex_number(surface, source, pos, lex, file_name, line, col)
        stop = scan_number_end(source, pos)
        text = source[pos...stop]
        lit = parse(surface, text)
        if lit.nil?
          lex << Frontend.lex_error(invalid_integer_literal(surface, text), file_name, line, col) unless lex.nil?
          return [stop, "0", nil, text]
        end
        [stop, lit.value.to_s, lit, text]
      end
    end
  end
end
