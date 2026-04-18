# frozen_string_literal: true

# Python format parser (.runar.py) for the Runar compiler.
#
# Ported from compilers/python/runar_compiler/frontend/parser_python.py
# and packages/runar-compiler/src/passes/01-parse-python.ts.
# Hand-written tokenizer with INDENT/DEDENT tokens + recursive descent parser.
#
# Python syntax conventions used in Runar contracts:
#   - `class Foo(SmartContract):` / `class Foo(StatefulSmartContract):`
#   - `@public` decorator for public methods
#   - `self.prop` for property access (maps to `this.prop`)
#   - `def __init__(self, param: Type): super().__init__(param)` for constructor
#   - `assert_(condition)` or `assert condition` for assertions
#   - `and`/`or`/`not` for boolean operators -> `&&`/`||`/`!`
#   - `//` for integer division -> `/` in AST (OP_DIV)
#   - snake_case names converted to camelCase in AST
#   - `Readonly[T]` for readonly properties in stateful contracts
#   - `for i in range(n):` for bounded loops
#   - `b'\xde\xad'` hex byte string literals

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"

module RunarCompiler
  module Frontend
    # -----------------------------------------------------------------------
    # Namespaced token constants for the Python parser
    # -----------------------------------------------------------------------

    module PythonTokens
      TOK_EOF         = 0
      TOK_IDENT       = 1
      TOK_NUMBER      = 2
      TOK_STRING      = 3
      TOK_HEXSTRING   = 4
      TOK_LPAREN      = 5   # (
      TOK_RPAREN      = 6   # )
      TOK_LBRACKET    = 7   # [
      TOK_RBRACKET    = 8   # ]
      TOK_COMMA       = 9   # ,
      TOK_DOT         = 10  # .
      TOK_COLON       = 11  # :
      TOK_EQ          = 12  # =
      TOK_EQEQ        = 13  # ==
      TOK_BANGEQ       = 14  # !=
      TOK_LT          = 15  # <
      TOK_LTEQ        = 16  # <=
      TOK_GT          = 17  # >
      TOK_GTEQ        = 18  # >=
      TOK_PLUS        = 19  # +
      TOK_MINUS       = 20  # -
      TOK_STAR        = 21  # *
      TOK_SLASH       = 22  # /
      TOK_PERCENT     = 23  # %
      TOK_TILDE       = 24  # ~
      TOK_AMP         = 25  # &
      TOK_PIPE        = 26  # |
      TOK_CARET       = 27  # ^
      TOK_AMPAMP      = 28  # && (mapped from 'and')
      TOK_PIPEPIPE    = 29  # || (mapped from 'or')
      TOK_BANG        = 30  # ! (mapped from 'not')
      TOK_PLUSEQ      = 31  # +=
      TOK_MINUSEQ     = 32  # -=
      TOK_STAREQ      = 33  # *=
      TOK_SLASHEQ     = 34  # /=
      TOK_PERCENTEQ   = 35  # %=
      TOK_AT          = 36  # @
      TOK_SLASHSLASH  = 37  # //
      TOK_SLASHSLASHEQ = 38 # //=
      TOK_STARSTAR    = 39  # **
      TOK_ARROW       = 40  # ->
      TOK_LSHIFT      = 41  # <<
      TOK_RSHIFT      = 42  # >>
      TOK_INDENT      = 43
      TOK_DEDENT      = 44
      TOK_NEWLINE     = 45
    end

    # A single token produced by the Python tokenizer.
    PythonToken = Struct.new(:kind, :value, :line, :col, keyword_init: true)

    # -----------------------------------------------------------------------
    # Name conversion: Python snake_case -> camelCase
    # -----------------------------------------------------------------------

    PY_SPECIAL_NAMES = {
      "assert_"                      => "assert",
      "__init__"                     => "constructor",
      "check_sig"                    => "checkSig",
      "check_multi_sig"              => "checkMultiSig",
      "check_preimage"               => "checkPreimage",
      "verify_wots"                  => "verifyWOTS",
      "verify_slh_dsa_sha2_128s"     => "verifySLHDSA_SHA2_128s",
      "verify_slh_dsa_sha2_128f"     => "verifySLHDSA_SHA2_128f",
      "verify_slh_dsa_sha2_192s"     => "verifySLHDSA_SHA2_192s",
      "verify_slh_dsa_sha2_192f"     => "verifySLHDSA_SHA2_192f",
      "verify_slh_dsa_sha2_256s"     => "verifySLHDSA_SHA2_256s",
      "verify_slh_dsa_sha2_256f"     => "verifySLHDSA_SHA2_256f",
      "verify_rabin_sig"             => "verifyRabinSig",
      "ec_add"                       => "ecAdd",
      "ec_mul"                       => "ecMul",
      "ec_mul_gen"                   => "ecMulGen",
      "ec_negate"                    => "ecNegate",
      "ec_on_curve"                  => "ecOnCurve",
      "ec_mod_reduce"                => "ecModReduce",
      "ec_encode_compressed"         => "ecEncodeCompressed",
      "ec_make_point"                => "ecMakePoint",
      "ec_point_x"                   => "ecPointX",
      "ec_point_y"                   => "ecPointY",
      "add_output"                   => "addOutput",
      "add_raw_output"               => "addRawOutput",
      "add_data_output"              => "addDataOutput",
      "get_state_script"             => "getStateScript",
      "extract_locktime"             => "extractLocktime",
      "extract_output_hash"          => "extractOutputHash",
      "extract_sequence"             => "extractSequence",
      "extract_version"              => "extractVersion",
      "extract_amount"               => "extractAmount",
      "extract_hash_prevouts"        => "extractHashPrevouts",
      "extract_hash_sequence"        => "extractHashSequence",
      "extract_outpoint"             => "extractOutpoint",
      "extract_script_code"          => "extractScriptCode",
      "extract_input_index"          => "extractInputIndex",
      "extract_sig_hash_type"        => "extractSigHashType",
      "extract_outputs"              => "extractOutputs",
      "mul_div"                      => "mulDiv",
      "percent_of"                   => "percentOf",
      "reverse_bytes"                => "reverseBytes",
      "safe_div"                     => "safediv",
      "safe_mod"                     => "safemod",
      "sha256"                       => "sha256",
      "ripemd160"                    => "ripemd160",
      "hash160"                      => "hash160",
      "hash256"                      => "hash256",
      "num2bin"                      => "num2bin",
      "bin2num"                      => "bin2num",
      "log2"                         => "log2",
      "div_mod"                      => "divmod",
      "to_byte_string"               => "toByteString",
      "EC_P"                         => "EC_P",
      "EC_N"                         => "EC_N",
      "EC_G"                         => "EC_G",
    }.freeze

    PY_PASSTHROUGH_NAMES = Set.new(%w[
      bool abs min max len pow cat within safediv safemod clamp sign sqrt
      gcd divmod log2 substr
    ]).freeze

    def self.py_convert_name(name)
      return PY_SPECIAL_NAMES[name] if PY_SPECIAL_NAMES.key?(name)

      # No underscores -> return as-is
      return name unless name.include?("_")

      # Dunder names
      if name.start_with?("__") && name.end_with?("__")
        return name
      end

      # Strip trailing underscore (e.g. sum_ -> sum, assert_ -> assert)
      if name.end_with?("_") && name != "_"
        name = name.chomp("_")
        return PY_SPECIAL_NAMES[name + "_"] if PY_SPECIAL_NAMES.key?(name + "_")
      end

      # Strip leading single underscore for private methods
      stripped = name
      if stripped.start_with?("_") && !stripped.start_with?("__")
        stripped = stripped[1..]
      end

      # General snake_case to camelCase
      parts = stripped.split("_")
      return stripped if parts.length <= 1

      result = parts[0]
      parts[1..].each do |part|
        next if part.empty?

        result += part[0].upcase + part[1..]
      end
      result
    end

    # -----------------------------------------------------------------------
    # Byte string helpers
    # -----------------------------------------------------------------------

    def self.py_byte_string_to_hex(s)
      result = +""
      i = 0
      while i < s.length
        if s[i] == "\\" && i + 1 < s.length
          if s[i + 1] == "x" && i + 3 < s.length
            result << s[i + 2, 2]
            i += 4
            next
          elsif s[i + 1] == "0"
            result << "00"
            i += 2
            next
          end
        end
        result << format("%02x", s[i].ord)
        i += 1
      end
      result
    end

    # -----------------------------------------------------------------------
    # Type mapping
    # -----------------------------------------------------------------------

    PY_TYPE_MAP = {
      "int"             => "bigint",
      "Int"             => "bigint",
      "Bigint"          => "bigint",
      "bigint"          => "bigint",
      "bool"            => "boolean",
      "Bool"            => "boolean",
      "boolean"         => "boolean",
      "bytes"           => "ByteString",
      "ByteString"      => "ByteString",
      "PubKey"          => "PubKey",
      "Sig"             => "Sig",
      "Sha256"          => "Sha256",
      "Ripemd160"       => "Ripemd160",
      "Addr"            => "Addr",
      "SigHashPreimage" => "SigHashPreimage",
      "RabinSig"        => "RabinSig",
      "RabinPubKey"     => "RabinPubKey",
      "Point"           => "Point",
    }.freeze

    def self.py_parse_type_name(name)
      mapped = PY_TYPE_MAP[name]
      mapped = name if mapped.nil?
      if primitive_type?(mapped)
        return PrimitiveType.new(name: mapped)
      end

      CustomType.new(name: mapped)
    end

    # -----------------------------------------------------------------------
    # Tokenizer with INDENT/DEDENT
    #
    # Processes source line-by-line (like the TypeScript reference).
    # Significant whitespace at line starts produces INDENT/DEDENT tokens.
    # NEWLINE tokens are emitted at the end of each significant line.
    # -----------------------------------------------------------------------

    def self.tokenize_python(source)
      tokens = []
      lines = source.split("\n", -1)
      indent_stack = [0]
      paren_depth = 0
      in_triple_quote = nil

      lines.each_with_index do |raw_line, line_idx|
        line_num = line_idx + 1
        line = raw_line.chomp("\r")

        # If inside a multi-line triple-quoted string, skip until closing
        if in_triple_quote
          if line.include?(in_triple_quote)
            in_triple_quote = nil
          end
          next
        end

        # Skip blank and comment-only lines
        stripped = line.lstrip
        next if stripped.empty? || stripped.start_with?("#")

        # Skip standalone triple-quoted docstrings
        if stripped.start_with?('"""') || stripped.start_with?("'''")
          quote = stripped[0, 3]
          close_idx = stripped.index(quote, 3)
          if close_idx.nil?
            in_triple_quote = quote
          end
          next
        end

        # Compute indent level (only outside parens)
        if paren_depth == 0
          indent = 0
          line.each_char do |c|
            break unless c == " " || c == "\t"

            if c == " "
              indent += 1
            else
              indent += 4
            end
          end

          if indent > indent_stack.last
            indent_stack.push(indent)
            tokens << PythonToken.new(kind: PythonTokens::TOK_INDENT, value: "", line: line_num, col: 1)
          elsif indent < indent_stack.last
            while indent_stack.length > 1 && indent_stack.last > indent
              indent_stack.pop
              tokens << PythonToken.new(kind: PythonTokens::TOK_DEDENT, value: "", line: line_num, col: 1)
            end
          end
        end

        # Tokenize content of this line
        pos = line.length - stripped.length

        while pos < line.length
          ch = line[pos]
          col = pos + 1

          # Whitespace within line
          if ch == " " || ch == "\t"
            pos += 1
            next
          end

          # Comment
          if ch == "#"
            break
          end

          # Decorators @
          if ch == "@"
            pos += 1
            tokens << PythonToken.new(kind: PythonTokens::TOK_AT, value: "@", line: line_num, col: col)
            next
          end

          # Byte string literals: b'...' or b"..."
          if ch == "b" && pos + 1 < line.length && (line[pos + 1] == "'" || line[pos + 1] == '"')
            quote = line[pos + 1]
            pos += 2
            start = pos
            while pos < line.length && line[pos] != quote
              pos += 1 if line[pos] == "\\"
              pos += 1
            end
            val = line[start...pos]
            pos += 1 if pos < line.length
            hex_val = py_byte_string_to_hex(val)
            tokens << PythonToken.new(kind: PythonTokens::TOK_HEXSTRING, value: hex_val, line: line_num, col: col)
            next
          end

          # String literals
          if ch == "'" || ch == '"'
            # Triple-quote
            if pos + 2 < line.length && line[pos + 1] == ch && line[pos + 2] == ch
              triple = ch * 3
              pos += 3
              close_idx = line.index(triple, pos)
              if close_idx
                pos = close_idx + 3
              else
                in_triple_quote = triple
                break
              end
              next
            end
            # Single-quote string
            quote = ch
            pos += 1
            val = +""
            while pos < line.length && line[pos] != quote
              if line[pos] == "\\" && pos + 1 < line.length
                pos += 1
                val << line[pos]
              else
                val << line[pos]
              end
              pos += 1
            end
            pos += 1 if pos < line.length
            tokens << PythonToken.new(kind: PythonTokens::TOK_STRING, value: val, line: line_num, col: col)
            next
          end

          # Three-character operators: //=
          if pos + 2 < line.length && line[pos, 3] == "//="
            tokens << PythonToken.new(kind: PythonTokens::TOK_SLASHSLASHEQ, value: "//=", line: line_num, col: col)
            pos += 3
            next
          end

          # Two-character operators: **
          if ch == "*" && pos + 1 < line.length && line[pos + 1] == "*"
            tokens << PythonToken.new(kind: PythonTokens::TOK_STARSTAR, value: "**", line: line_num, col: col)
            pos += 2
            next
          end

          # Two-character operator: //
          if ch == "/" && pos + 1 < line.length && line[pos + 1] == "/"
            tokens << PythonToken.new(kind: PythonTokens::TOK_SLASHSLASH, value: "//", line: line_num, col: col)
            pos += 2
            next
          end

          # Other two-character operators
          if pos + 1 < line.length
            two = line[pos, 2]
            two_kind = case two
                       when "==" then PythonTokens::TOK_EQEQ
                       when "!=" then PythonTokens::TOK_BANGEQ
                       when "<=" then PythonTokens::TOK_LTEQ
                       when ">=" then PythonTokens::TOK_GTEQ
                       when "+=" then PythonTokens::TOK_PLUSEQ
                       when "-=" then PythonTokens::TOK_MINUSEQ
                       when "*=" then PythonTokens::TOK_STAREQ
                       when "/=" then PythonTokens::TOK_SLASHEQ
                       when "%=" then PythonTokens::TOK_PERCENTEQ
                       when "->" then PythonTokens::TOK_ARROW
                       when "<<" then PythonTokens::TOK_LSHIFT
                       when ">>" then PythonTokens::TOK_RSHIFT
                       end

            if two_kind
              tokens << PythonToken.new(kind: two_kind, value: two, line: line_num, col: col)
              pos += 2
              next
            end
          end

          # Parentheses (track depth)
          if ch == "("
            paren_depth += 1
            tokens << PythonToken.new(kind: PythonTokens::TOK_LPAREN, value: "(", line: line_num, col: col)
            pos += 1
            next
          end
          if ch == ")"
            paren_depth = [0, paren_depth - 1].max
            tokens << PythonToken.new(kind: PythonTokens::TOK_RPAREN, value: ")", line: line_num, col: col)
            pos += 1
            next
          end
          if ch == "["
            paren_depth += 1
            tokens << PythonToken.new(kind: PythonTokens::TOK_LBRACKET, value: "[", line: line_num, col: col)
            pos += 1
            next
          end
          if ch == "]"
            paren_depth = [0, paren_depth - 1].max
            tokens << PythonToken.new(kind: PythonTokens::TOK_RBRACKET, value: "]", line: line_num, col: col)
            pos += 1
            next
          end

          # Single-character tokens
          single_kind = case ch
                        when "," then PythonTokens::TOK_COMMA
                        when "." then PythonTokens::TOK_DOT
                        when ":" then PythonTokens::TOK_COLON
                        when "+" then PythonTokens::TOK_PLUS
                        when "-" then PythonTokens::TOK_MINUS
                        when "*" then PythonTokens::TOK_STAR
                        when "/" then PythonTokens::TOK_SLASH
                        when "%" then PythonTokens::TOK_PERCENT
                        when "<" then PythonTokens::TOK_LT
                        when ">" then PythonTokens::TOK_GT
                        when "=" then PythonTokens::TOK_EQ
                        when "&" then PythonTokens::TOK_AMP
                        when "|" then PythonTokens::TOK_PIPE
                        when "^" then PythonTokens::TOK_CARET
                        when "~" then PythonTokens::TOK_TILDE
                        when "!" then PythonTokens::TOK_BANG
                        end

          if single_kind
            tokens << PythonToken.new(kind: single_kind, value: ch, line: line_num, col: col)
            pos += 1
            next
          end

          # Numbers
          if ch >= "0" && ch <= "9"
            start = pos
            if ch == "0" && pos + 1 < line.length && (line[pos + 1] == "x" || line[pos + 1] == "X")
              pos += 2
              while pos < line.length && "0123456789abcdefABCDEF".include?(line[pos])
                pos += 1
              end
            else
              while pos < line.length && ((line[pos] >= "0" && line[pos] <= "9") || line[pos] == "_")
                pos += 1
              end
            end
            num_str = line[start...pos].delete("_")
            tokens << PythonToken.new(kind: PythonTokens::TOK_NUMBER, value: num_str, line: line_num, col: col)
            next
          end

          # Identifiers and keywords
          if (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch == "_"
            start = pos
            while pos < line.length && ((line[pos] >= "a" && line[pos] <= "z") ||
                                        (line[pos] >= "A" && line[pos] <= "Z") ||
                                        (line[pos] >= "0" && line[pos] <= "9") ||
                                        line[pos] == "_")
              pos += 1
            end
            word = line[start...pos]

            case word
            when "and"
              tokens << PythonToken.new(kind: PythonTokens::TOK_AMPAMP, value: "and", line: line_num, col: col)
            when "or"
              tokens << PythonToken.new(kind: PythonTokens::TOK_PIPEPIPE, value: "or", line: line_num, col: col)
            when "not"
              tokens << PythonToken.new(kind: PythonTokens::TOK_BANG, value: "not", line: line_num, col: col)
            else
              tokens << PythonToken.new(kind: PythonTokens::TOK_IDENT, value: word, line: line_num, col: col)
            end
            next
          end

          # Skip unknown
          pos += 1
        end

        # Emit NEWLINE at end of significant line (only outside parens)
        if paren_depth == 0
          tokens << PythonToken.new(kind: PythonTokens::TOK_NEWLINE, value: "", line: line_num, col: line.length + 1)
        end
      end

      # Emit remaining DEDENTs
      while indent_stack.length > 1
        indent_stack.pop
        tokens << PythonToken.new(kind: PythonTokens::TOK_DEDENT, value: "", line: lines.length, col: 1)
      end

      tokens << PythonToken.new(kind: PythonTokens::TOK_EOF, value: "", line: lines.length + 1, col: 1)
      tokens
    end

    # -----------------------------------------------------------------------
    # Parser
    # -----------------------------------------------------------------------

    class PythonParser
      include PythonTokens

      INT64_MAX = 9_223_372_036_854_775_807
      INT64_MIN = -9_223_372_036_854_775_808

      def initialize(file_name)
        @file_name = file_name
        @tokens = []
        @pos = 0
        @errors = []
      end

      attr_accessor :tokens, :pos, :errors

      # -- Error helpers ----------------------------------------------------

      def add_error(msg)
        @errors << Diagnostic.new(message: msg, severity: Severity::ERROR)
      end

      # -- Token helpers ----------------------------------------------------

      def peek
        return @tokens[@pos] if @pos < @tokens.length

        PythonToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
      end

      def advance
        tok = peek
        @pos += 1 if @pos < @tokens.length
        tok
      end

      def expect(kind)
        tok = advance
        if tok.kind != kind
          add_error("line #{tok.line}: expected token kind #{kind}, got #{tok.kind} (#{tok.value.inspect})")
        end
        tok
      end

      def check(kind)
        peek.kind == kind
      end

      def check_ident(value)
        peek.kind == TOK_IDENT && peek.value == value
      end

      def match_tok(kind)
        if check(kind)
          advance
          return true
        end
        false
      end

      def match_ident(value)
        if check_ident(value)
          advance
          return true
        end
        false
      end

      def loc
        tok = peek
        SourceLocation.new(file: @file_name, line: tok.line, column: tok.col)
      end

      def peek_next
        return @tokens[@pos + 1] if @pos + 1 < @tokens.length

        PythonToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
      end

      def skip_newlines
        advance while check(TOK_NEWLINE)
      end

      # -- Top-level parsing ------------------------------------------------

      def parse_contract
        skip_newlines

        # Skip import lines: `from runar import ...` or `import ...`
        while check_ident("from") || check_ident("import")
          parse_import_line
          skip_newlines
        end

        # Parse class
        parse_class
      end

      def parse_import_line
        if check_ident("from")
          advance # 'from'
          until check_ident("import") || check(TOK_NEWLINE) || check(TOK_EOF)
            advance
          end
          if match_ident("import")
            until check(TOK_NEWLINE) || check(TOK_EOF)
              advance
            end
          end
        elsif check_ident("import")
          advance
          until check(TOK_NEWLINE) || check(TOK_EOF)
            advance
          end
        end
        skip_newlines
      end

      # -- Class parsing ----------------------------------------------------

      def parse_class
        skip_newlines

        unless check_ident("class")
          add_error("Expected class declaration")
          raise "Expected class declaration"
        end
        advance # 'class'

        name_tok = expect(TOK_IDENT)
        contract_name = name_tok.value

        expect(TOK_LPAREN)
        parent_tok = expect(TOK_IDENT)
        parent_class = parent_tok.value
        expect(TOK_RPAREN)
        expect(TOK_COLON)
        skip_newlines
        expect(TOK_INDENT)
        skip_newlines

        unless %w[SmartContract StatefulSmartContract].include?(parent_class)
          add_error("Unknown parent class: #{parent_class}")
          raise "Unknown parent class: #{parent_class}"
        end

        properties = []
        methods = []
        constructor = nil

        while !check(TOK_DEDENT) && !check(TOK_EOF)
          skip_newlines
          break if check(TOK_DEDENT) || check(TOK_EOF)

          # Decorators
          decorators = []
          while check(TOK_AT)
            advance # '@'
            dec_name = advance.value
            decorators << dec_name
            skip_newlines
          end

          # Method definition
          if check_ident("def")
            method = parse_method_def(decorators)
            if method.name == "constructor"
              constructor = method
            else
              methods << method
            end
            skip_newlines
            next
          end

          # Property: name: Type
          if check(TOK_IDENT)
            prop = parse_property(parent_class)
            if prop
              properties << prop
            end
            skip_newlines
            next
          end

          # Skip unknown
          advance
        end

        match_tok(TOK_DEDENT)

        # Auto-generate constructor if not provided
        constructor ||= auto_generate_constructor(properties)

        ContractNode.new(
          name: contract_name,
          parent_class: parent_class,
          properties: properties,
          constructor: constructor,
          methods: methods,
          source_file: @file_name
        )
      end

      # -- Property parsing --------------------------------------------------

      def parse_property(parent_class)
        location = loc
        name_tok = advance
        raw_name = name_tok.value

        unless check(TOK_COLON)
          # Not a property — skip rest of line
          until check(TOK_NEWLINE) || check(TOK_EOF) || check(TOK_DEDENT)
            advance
          end
          return nil
        end
        advance # ':'

        # Parse type (possibly Readonly[T])
        is_readonly = false
        if check_ident("Readonly")
          is_readonly = true
          advance # 'Readonly'
          expect(TOK_LBRACKET)
          type_node = parse_type
          expect(TOK_RBRACKET)
        else
          type_node = parse_type
        end

        # In stateless contracts, all properties are readonly
        is_readonly = true if parent_class == "SmartContract"

        # Check for initializer: = value
        initializer = nil
        if check(TOK_EQ)
          advance # '='
          initializer = parse_expression
        end

        # Skip rest of line
        until check(TOK_NEWLINE) || check(TOK_EOF) || check(TOK_DEDENT)
          advance
        end

        PropertyNode.new(
          name: Frontend.py_convert_name(raw_name),
          type: type_node,
          readonly: is_readonly,
          initializer: initializer,
          source_location: location
        )
      end

      # -- Type parsing ------------------------------------------------------

      def parse_type
        tok = advance
        raw_name = tok.value

        # FixedArray[T, N]
        if raw_name == "FixedArray" && check(TOK_LBRACKET)
          advance # '['
          elem_type = parse_type
          expect(TOK_COMMA)
          size_tok = expect(TOK_NUMBER)
          size = begin
            Integer(size_tok.value, 0)
          rescue ArgumentError
            0
          end
          expect(TOK_RBRACKET)
          return FixedArrayType.new(element: elem_type, length: size)
        end

        Frontend.py_parse_type_name(raw_name)
      end

      # -- Method definition -------------------------------------------------

      def parse_method_def(decorators)
        location = loc
        expect_ident("def")

        name_tok = advance
        raw_name = name_tok.value

        expect(TOK_LPAREN)
        params = parse_params
        expect(TOK_RPAREN)

        # Optional return type: -> Type
        if match_tok(TOK_ARROW)
          parse_type # consume and discard
        end

        expect(TOK_COLON)
        skip_newlines
        expect(TOK_INDENT)

        body = parse_statements

        match_tok(TOK_DEDENT)

        # Determine if this is the constructor
        if raw_name == "__init__"
          return MethodNode.new(
            name: "constructor",
            params: params,
            body: body,
            visibility: "public",
            source_location: location
          )
        end

        is_public = decorators.include?("public")
        method_name = Frontend.py_convert_name(raw_name)

        MethodNode.new(
          name: method_name,
          params: params,
          body: body,
          visibility: is_public ? "public" : "private",
          source_location: location
        )
      end

      def expect_ident(value)
        tok = advance
        if tok.kind != TOK_IDENT || tok.value != value
          add_error("line #{tok.line}: expected '#{value}', got #{tok.value.inspect}")
        end
        tok
      end

      def parse_params
        params = []

        while !check(TOK_RPAREN) && !check(TOK_EOF)
          # Skip 'self' parameter
          if check_ident("self")
            advance
            match_tok(TOK_COMMA)
            next
          end

          name_tok = advance
          raw_name = name_tok.value

          type_node = nil
          if match_tok(TOK_COLON)
            type_node = parse_type
          end

          params << ParamNode.new(
            name: Frontend.py_convert_name(raw_name),
            type: type_node || CustomType.new(name: "unknown")
          )

          break unless match_tok(TOK_COMMA)
        end

        params
      end

      def auto_generate_constructor(properties)
        uninit_props = properties.reject { |p| p.initializer }
        params = uninit_props.map { |p| ParamNode.new(name: p.name, type: p.type) }

        super_args = params.map { |p| Identifier.new(name: p.name) }

        default_loc = SourceLocation.new(file: @file_name, line: 1, column: 0)

        super_call = ExpressionStmt.new(
          expr: CallExpr.new(
            callee: Identifier.new(name: "super"),
            args: super_args
          ),
          source_location: default_loc
        )

        assignments = uninit_props.map do |p|
          AssignmentStmt.new(
            target: PropertyAccessExpr.new(property: p.name),
            value: Identifier.new(name: p.name),
            source_location: default_loc
          )
        end

        MethodNode.new(
          name: "constructor",
          params: params,
          body: [super_call] + assignments,
          visibility: "public",
          source_location: default_loc
        )
      end

      # -- Statement parsing -------------------------------------------------

      def parse_statements
        stmts = []

        while !check(TOK_DEDENT) && !check(TOK_EOF)
          skip_newlines
          break if check(TOK_DEDENT) || check(TOK_EOF)

          stmt = parse_statement
          stmts << stmt if stmt
          skip_newlines
        end

        stmts
      end

      def parse_statement
        location = loc

        # assert statement: assert expr
        if check_ident("assert")
          return parse_assert_statement(location)
        end

        # assert_ function call (handled as identifier in expression parsing)

        # if statement
        if check_ident("if")
          return parse_if_statement(location)
        end

        # for statement
        if check_ident("for")
          return parse_for_statement(location)
        end

        # return statement
        if check_ident("return")
          return parse_return_statement(location)
        end

        # pass statement
        if check_ident("pass")
          advance
          return nil
        end

        # super().__init__(...) — parse as constructor body
        if check_ident("super")
          return parse_super_call(location)
        end

        # self.prop = expr (assignment to property)
        if check_ident("self")
          return parse_self_statement(location)
        end

        # Variable declaration or expression statement
        if check(TOK_IDENT)
          return parse_ident_statement(location)
        end

        # Skip unknown
        advance
        nil
      end

      def parse_assert_statement(location)
        advance # 'assert'
        expr = parse_expression
        ExpressionStmt.new(
          expr: CallExpr.new(
            callee: Identifier.new(name: "assert"),
            args: [expr]
          ),
          source_location: location
        )
      end

      def parse_if_statement(location)
        expect_ident("if")
        condition = parse_expression
        expect(TOK_COLON)
        skip_newlines
        expect(TOK_INDENT)
        then_block = parse_statements
        match_tok(TOK_DEDENT)
        skip_newlines

        else_block = nil

        if check_ident("elif")
          elif_loc = loc
          else_block = [parse_elif_statement(elif_loc)]
        elsif check_ident("else")
          advance # 'else'
          expect(TOK_COLON)
          skip_newlines
          expect(TOK_INDENT)
          else_block = parse_statements
          match_tok(TOK_DEDENT)
        end

        IfStmt.new(
          condition: condition,
          then: then_block,
          else_: else_block || [],
          source_location: location
        )
      end

      def parse_elif_statement(location)
        expect_ident("elif")
        condition = parse_expression
        expect(TOK_COLON)
        skip_newlines
        expect(TOK_INDENT)
        then_block = parse_statements
        match_tok(TOK_DEDENT)
        skip_newlines

        else_block = nil

        if check_ident("elif")
          elif_loc = loc
          else_block = [parse_elif_statement(elif_loc)]
        elsif check_ident("else")
          advance
          expect(TOK_COLON)
          skip_newlines
          expect(TOK_INDENT)
          else_block = parse_statements
          match_tok(TOK_DEDENT)
        end

        IfStmt.new(
          condition: condition,
          then: then_block,
          else_: else_block || [],
          source_location: location
        )
      end

      def parse_for_statement(location)
        expect_ident("for")

        iter_tok = advance
        var_name = Frontend.py_convert_name(iter_tok.value)

        expect_ident("in")
        expect_ident("range")
        expect(TOK_LPAREN)

        first_arg = parse_expression
        if match_tok(TOK_COMMA)
          start_expr = first_arg
          end_expr = parse_expression
        else
          start_expr = BigIntLiteral.new(value: 0)
          end_expr = first_arg
        end

        expect(TOK_RPAREN)
        expect(TOK_COLON)
        skip_newlines
        expect(TOK_INDENT)
        body = parse_statements
        match_tok(TOK_DEDENT)

        init = VariableDeclStmt.new(
          name: var_name,
          type: PrimitiveType.new(name: "bigint"),
          mutable: true,
          init: start_expr,
          source_location: location
        )

        condition = BinaryExpr.new(
          op: "<",
          left: Identifier.new(name: var_name),
          right: end_expr
        )

        update = ExpressionStmt.new(
          expr: IncrementExpr.new(
            operand: Identifier.new(name: var_name),
            prefix: false
          ),
          source_location: location
        )

        ForStmt.new(
          init: init,
          condition: condition,
          update: update,
          body: body,
          source_location: location
        )
      end

      def parse_return_statement(location)
        expect_ident("return")
        value = nil
        if !check(TOK_NEWLINE) && !check(TOK_DEDENT) && !check(TOK_EOF)
          value = parse_expression
        end
        ReturnStmt.new(value: value, source_location: location)
      end

      def parse_super_call(location)
        advance # 'super'
        expect(TOK_LPAREN)
        expect(TOK_RPAREN)
        expect(TOK_DOT)
        method_tok = advance # __init__
        unless method_tok.value == "__init__"
          add_error("Expected __init__ after super(), got '#{method_tok.value}'")
        end
        expect(TOK_LPAREN)
        args = []
        while !check(TOK_RPAREN) && !check(TOK_EOF)
          args << parse_expression
          break unless match_tok(TOK_COMMA)
        end
        expect(TOK_RPAREN)

        ExpressionStmt.new(
          expr: CallExpr.new(
            callee: Identifier.new(name: "super"),
            args: args
          ),
          source_location: location
        )
      end

      def parse_self_statement(location)
        expr = parse_expression

        # Assignment: self.x = expr
        if match_tok(TOK_EQ)
          value = parse_expression
          return AssignmentStmt.new(target: expr, value: value, source_location: location)
        end

        # Compound assignment
        compound_ops = {
          TOK_PLUSEQ     => "+",
          TOK_MINUSEQ    => "-",
          TOK_STAREQ     => "*",
          TOK_SLASHEQ    => "/",
          TOK_PERCENTEQ  => "%",
          TOK_SLASHSLASHEQ => "/",
        }
        compound_ops.each do |kind, bin_op|
          if match_tok(kind)
            right = parse_expression
            value = BinaryExpr.new(op: bin_op, left: expr, right: right)
            return AssignmentStmt.new(target: expr, value: value, source_location: location)
          end
        end

        # Expression statement (method call)
        ExpressionStmt.new(expr: expr, source_location: location)
      end

      def parse_ident_statement(location)
        name_tok = peek
        raw_name = name_tok.value

        # Variable declaration with type: name: Type = expr
        if peek_next.kind == TOK_COLON
          advance # ident
          advance # ':'
          type_node = parse_type
          init = if match_tok(TOK_EQ)
                   parse_expression
                 else
                   BigIntLiteral.new(value: 0)
                 end
          return VariableDeclStmt.new(
            name: Frontend.py_convert_name(raw_name),
            type: type_node,
            mutable: true,
            init: init,
            source_location: location
          )
        end

        # Simple name = expr (variable declaration without type)
        if peek_next.kind == TOK_EQ
          advance # ident
          advance # '='
          value = parse_expression
          return VariableDeclStmt.new(
            name: Frontend.py_convert_name(raw_name),
            mutable: true,
            init: value,
            source_location: location
          )
        end

        # Parse as expression first
        expr = parse_expression

        # Simple assignment
        if match_tok(TOK_EQ)
          value = parse_expression
          return AssignmentStmt.new(target: expr, value: value, source_location: location)
        end

        # Compound assignment
        compound_ops = {
          TOK_PLUSEQ     => "+",
          TOK_MINUSEQ    => "-",
          TOK_STAREQ     => "*",
          TOK_SLASHEQ    => "/",
          TOK_PERCENTEQ  => "%",
          TOK_SLASHSLASHEQ => "/",
        }
        compound_ops.each do |kind, bin_op|
          if match_tok(kind)
            right = parse_expression
            value = BinaryExpr.new(op: bin_op, left: expr, right: right)
            return AssignmentStmt.new(target: expr, value: value, source_location: location)
          end
        end

        # Expression statement
        ExpressionStmt.new(expr: expr, source_location: location)
      end

      # -- Expression parsing ------------------------------------------------
      # Operator precedence (lowest to highest):
      #   conditional (x if cond else y) — Python ternary
      #   logical or (or)
      #   logical and (and)
      #   logical not (not)
      #   bitwise or (|)
      #   bitwise xor (^)
      #   bitwise and (&)
      #   equality (== !=)
      #   comparison (< <= > >=)
      #   shift (<< >>)
      #   additive (+ -)
      #   multiplicative (* / // %)
      #   unary (- ~ !)
      #   postfix (. [] ())
      #   primary

      def parse_expression
        parse_ternary
      end

      # Python conditional: expr if cond else alternate
      def parse_ternary
        expr = parse_or
        if check_ident("if")
          advance # 'if'
          condition = parse_or
          expect_ident("else")
          alternate = parse_ternary
          return TernaryExpr.new(condition: condition, consequent: expr, alternate: alternate)
        end
        expr
      end

      def parse_or
        left = parse_and
        while match_tok(TOK_PIPEPIPE) # 'or' mapped to TOK_PIPEPIPE
          right = parse_and
          left = BinaryExpr.new(op: "||", left: left, right: right)
        end
        left
      end

      def parse_and
        left = parse_not
        while match_tok(TOK_AMPAMP) # 'and' mapped to TOK_AMPAMP
          right = parse_not
          left = BinaryExpr.new(op: "&&", left: left, right: right)
        end
        left
      end

      def parse_not
        if match_tok(TOK_BANG) # 'not' mapped to TOK_BANG
          operand = parse_not
          return UnaryExpr.new(op: "!", operand: operand)
        end
        parse_bitwise_or
      end

      def parse_bitwise_or
        left = parse_bitwise_xor
        while match_tok(TOK_PIPE)
          right = parse_bitwise_xor
          left = BinaryExpr.new(op: "|", left: left, right: right)
        end
        left
      end

      def parse_bitwise_xor
        left = parse_bitwise_and
        while match_tok(TOK_CARET)
          right = parse_bitwise_and
          left = BinaryExpr.new(op: "^", left: left, right: right)
        end
        left
      end

      def parse_bitwise_and
        left = parse_equality
        while match_tok(TOK_AMP)
          right = parse_equality
          left = BinaryExpr.new(op: "&", left: left, right: right)
        end
        left
      end

      def parse_equality
        left = parse_comparison
        loop do
          if match_tok(TOK_EQEQ)
            right = parse_comparison
            left = BinaryExpr.new(op: "===", left: left, right: right)
          elsif match_tok(TOK_BANGEQ)
            right = parse_comparison
            left = BinaryExpr.new(op: "!==", left: left, right: right)
          else
            break
          end
        end
        left
      end

      def parse_comparison
        left = parse_shift
        loop do
          if match_tok(TOK_LT)
            right = parse_shift
            left = BinaryExpr.new(op: "<", left: left, right: right)
          elsif match_tok(TOK_LTEQ)
            right = parse_shift
            left = BinaryExpr.new(op: "<=", left: left, right: right)
          elsif match_tok(TOK_GT)
            right = parse_shift
            left = BinaryExpr.new(op: ">", left: left, right: right)
          elsif match_tok(TOK_GTEQ)
            right = parse_shift
            left = BinaryExpr.new(op: ">=", left: left, right: right)
          else
            break
          end
        end
        left
      end

      def parse_shift
        left = parse_additive
        loop do
          if match_tok(TOK_LSHIFT)
            right = parse_additive
            left = BinaryExpr.new(op: "<<", left: left, right: right)
          elsif match_tok(TOK_RSHIFT)
            right = parse_additive
            left = BinaryExpr.new(op: ">>", left: left, right: right)
          else
            break
          end
        end
        left
      end

      def parse_additive
        left = parse_multiplicative
        loop do
          if match_tok(TOK_PLUS)
            right = parse_multiplicative
            left = BinaryExpr.new(op: "+", left: left, right: right)
          elsif match_tok(TOK_MINUS)
            right = parse_multiplicative
            left = BinaryExpr.new(op: "-", left: left, right: right)
          else
            break
          end
        end
        left
      end

      def parse_multiplicative
        left = parse_unary
        loop do
          if match_tok(TOK_STAR)
            right = parse_unary
            left = BinaryExpr.new(op: "*", left: left, right: right)
          elsif match_tok(TOK_SLASHSLASH) # Python // -> / in AST
            right = parse_unary
            left = BinaryExpr.new(op: "/", left: left, right: right)
          elsif match_tok(TOK_SLASH)
            right = parse_unary
            left = BinaryExpr.new(op: "/", left: left, right: right)
          elsif match_tok(TOK_PERCENT)
            right = parse_unary
            left = BinaryExpr.new(op: "%", left: left, right: right)
          else
            break
          end
        end
        left
      end

      def parse_unary
        if match_tok(TOK_MINUS)
          operand = parse_unary
          return UnaryExpr.new(op: "-", operand: operand)
        end
        if match_tok(TOK_TILDE)
          operand = parse_unary
          return UnaryExpr.new(op: "~", operand: operand)
        end
        if match_tok(TOK_BANG)
          operand = parse_unary
          return UnaryExpr.new(op: "!", operand: operand)
        end
        parse_postfix
      end

      def parse_postfix
        expr = parse_primary
        loop do
          # Member access: expr.name or expr.name(...)
          if match_tok(TOK_DOT)
            prop_tok = advance
            prop_name = Frontend.py_convert_name(prop_tok.value)

            if check(TOK_LPAREN)
              args = parse_call_args
              if expr.is_a?(Identifier) && expr.name == "this"
                expr = CallExpr.new(
                  callee: MemberExpr.new(
                    object: Identifier.new(name: "this"),
                    property: prop_name
                  ),
                  args: args
                )
              else
                expr = CallExpr.new(
                  callee: MemberExpr.new(object: expr, property: prop_name),
                  args: args
                )
              end
            else
              if expr.is_a?(Identifier) && expr.name == "this"
                expr = PropertyAccessExpr.new(property: prop_name)
              else
                expr = MemberExpr.new(object: expr, property: prop_name)
              end
            end

          # Function call: expr(...)
          elsif check(TOK_LPAREN) && callable?(expr)
            args = parse_call_args
            expr = CallExpr.new(callee: expr, args: args)

          # Index access: expr[index]
          elsif match_tok(TOK_LBRACKET)
            index = parse_expression
            expect(TOK_RBRACKET)
            expr = IndexAccessExpr.new(object: expr, index: index)

          else
            break
          end
        end
        expr
      end

      def callable?(expr)
        expr.is_a?(Identifier) || expr.is_a?(MemberExpr)
      end

      def parse_call_args
        expect(TOK_LPAREN)
        args = []
        while !check(TOK_RPAREN) && !check(TOK_EOF)
          args << parse_expression
          break unless match_tok(TOK_COMMA)
        end
        expect(TOK_RPAREN)
        args
      end

      def parse_primary
        tok = peek

        # Number literal
        if tok.kind == TOK_NUMBER
          advance
          return parse_number(tok.value)
        end

        # Boolean literals
        if tok.kind == TOK_IDENT && tok.value == "True"
          advance
          return BoolLiteral.new(value: true)
        end
        if tok.kind == TOK_IDENT && tok.value == "False"
          advance
          return BoolLiteral.new(value: false)
        end

        # None -> 0
        if tok.kind == TOK_IDENT && tok.value == "None"
          advance
          return BigIntLiteral.new(value: 0)
        end

        # Hex string literal
        if tok.kind == TOK_HEXSTRING
          advance
          return ByteStringLiteral.new(value: tok.value)
        end

        # String literal
        if tok.kind == TOK_STRING
          advance
          return ByteStringLiteral.new(value: tok.value)
        end

        # Array literal: [expr, ...]
        if tok.kind == TOK_LBRACKET
          advance
          elements = []
          while !check(TOK_RBRACKET) && !check(TOK_EOF)
            elements << parse_expression
            break unless match_tok(TOK_COMMA)
          end
          expect(TOK_RBRACKET)
          return CallExpr.new(callee: Identifier.new(name: "FixedArray"), args: elements)
        end

        # bytes.fromhex("...")
        if tok.kind == TOK_IDENT && tok.value == "bytes"
          if peek_next.kind == TOK_DOT
            saved_pos = @pos
            advance # 'bytes'
            advance # '.'
            if check_ident("fromhex")
              advance # 'fromhex'
              expect(TOK_LPAREN)
              str_tok = advance
              expect(TOK_RPAREN)
              return ByteStringLiteral.new(value: str_tok.value)
            else
              @pos = saved_pos
            end
          end
        end

        # self -> this
        if tok.kind == TOK_IDENT && tok.value == "self"
          advance
          return Identifier.new(name: "this")
        end

        # Parenthesized expression
        if tok.kind == TOK_LPAREN
          advance
          expr = parse_expression
          expect(TOK_RPAREN)
          return expr
        end

        # Identifier or function call
        if tok.kind == TOK_IDENT
          advance
          raw_name = tok.value
          name = Frontend.py_convert_name(raw_name)
          return Identifier.new(name: name)
        end

        add_error("line #{tok.line}: unexpected token #{tok.value.inspect}")
        advance
        BigIntLiteral.new(value: 0)
      end

      def parse_number(s)
        val = begin
          Integer(s, 0)
        rescue ArgumentError
          0
        end
        if val > INT64_MAX || val < INT64_MIN
          return BigIntLiteral.new(value: 0)
        end
        BigIntLiteral.new(value: val)
      end
    end

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    # Parse a Python-syntax Runar contract (.runar.py).
    #
    # @param source [String] the source code
    # @param file_name [String] the file name (used in diagnostics)
    # @return [ParseResult]
    def self.parse_python(source, file_name)
      p = PythonParser.new(file_name)
      p.tokens = tokenize_python(source)
      p.pos = 0

      begin
        contract = p.parse_contract
      rescue => e
        return ParseResult.new(
          errors: [Diagnostic.new(message: e.message, severity: Severity::ERROR)]
        )
      end

      if p.errors.any?
        return ParseResult.new(contract: contract, errors: p.errors)
      end

      ParseResult.new(contract: contract)
    end
  end
end
