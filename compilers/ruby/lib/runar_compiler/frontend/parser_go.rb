# frozen_string_literal: true

# Go contract format parser (.runar.go) for the Runar compiler.
#
# Ported from packages/runar-compiler/src/passes/01-parse-go.ts.
# Hand-written tokenizer + recursive descent parser for Go contract syntax.

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"

module RunarCompiler
  module Frontend
    # -------------------------------------------------------------------
    # Go token type constants (namespaced to avoid collisions)
    # -------------------------------------------------------------------

    module GoTokens
      TOK_EOF          = 0
      TOK_IDENT        = 1
      TOK_NUMBER       = 2
      TOK_HEXSTRING    = 3
      TOK_STRING       = 4
      TOK_LBRACE       = 5
      TOK_RBRACE       = 6
      TOK_LPAREN       = 7
      TOK_RPAREN       = 8
      TOK_LBRACKET     = 9
      TOK_RBRACKET     = 10
      TOK_SEMICOLON    = 11
      TOK_COMMA        = 12
      TOK_DOT          = 13
      TOK_COLON        = 14
      TOK_ASSIGN       = 15
      TOK_EQEQ         = 16
      TOK_NOTEQ        = 17
      TOK_LT           = 18
      TOK_LTEQ         = 19
      TOK_GT           = 20
      TOK_GTEQ         = 21
      TOK_PLUS         = 22
      TOK_MINUS        = 23
      TOK_STAR         = 24
      TOK_SLASH        = 25
      TOK_PERCENT      = 26
      TOK_BANG         = 27
      TOK_TILDE        = 28
      TOK_AMP          = 29
      TOK_PIPE         = 30
      TOK_CARET        = 31
      TOK_AMPAMP       = 32
      TOK_PIPEPIPE     = 33
      TOK_PLUSEQ       = 34
      TOK_MINUSEQ      = 35
      TOK_STAREQ       = 36
      TOK_SLASHEQ      = 37
      TOK_PERCENTEQ    = 38
      TOK_PLUSPLUS      = 39
      TOK_MINUSMINUS   = 40
      TOK_COLONEQ      = 41  # :=
      TOK_LSHIFT       = 42  # <<
      TOK_RSHIFT       = 43  # >>
      TOK_BACKTICK     = 44
    end

    # A single token produced by the Go tokenizer.
    GoToken = Struct.new(:kind, :value, :line, :col, keyword_init: true)

    # -------------------------------------------------------------------
    # Go type mapping
    # -------------------------------------------------------------------

    GO_TYPE_MAP = {
      "Int"             => "bigint",
      "Bigint"          => "bigint",
      "BigintBig"       => "bigint",
      "Bool"            => "boolean",
      "bool"            => "boolean",
      "int"             => "bigint",
      "ByteString"      => "ByteString",
      "PubKey"          => "PubKey",
      "Sig"             => "Sig",
      "Sha256"          => "Sha256",
      "Sha256Digest"    => "Sha256",
      "Ripemd160"       => "Ripemd160",
      "Addr"            => "Addr",
      "SigHashPreimage" => "SigHashPreimage",
      "RabinSig"        => "RabinSig",
      "RabinPubKey"     => "RabinPubKey",
      "Point"           => "Point",
    }.freeze

    # -------------------------------------------------------------------
    # PascalCase to camelCase conversion
    # -------------------------------------------------------------------

    def self.go_to_camel(name)
      return name if name.empty?

      first = name[0]
      # Only convert if it starts with an uppercase letter
      if first == first.upcase && first != first.downcase
        return first.downcase + name[1..]
      end
      name
    end

    # -------------------------------------------------------------------
    # Go builtin name mapping (PascalCase -> camelCase)
    # -------------------------------------------------------------------

    GO_BUILTIN_MAP = {
      # Assertions
      "Assert" => "assert",
      # Hashing
      "Hash160" => "hash160", "Hash256" => "hash256", "Sha256" => "sha256", "Sha256Hash" => "sha256", "Ripemd160" => "ripemd160",
      # Signature verification
      "CheckSig" => "checkSig", "CheckMultiSig" => "checkMultiSig",
      "CheckPreimage" => "checkPreimage", "VerifyRabinSig" => "verifyRabinSig",
      # Post-quantum
      "VerifyWOTS" => "verifyWOTS",
      "VerifySLHDSA_SHA2_128s" => "verifySLHDSA_SHA2_128s",
      "VerifySLHDSA_SHA2_128f" => "verifySLHDSA_SHA2_128f",
      "VerifySLHDSA_SHA2_192s" => "verifySLHDSA_SHA2_192s",
      "VerifySLHDSA_SHA2_192f" => "verifySLHDSA_SHA2_192f",
      "VerifySLHDSA_SHA2_256s" => "verifySLHDSA_SHA2_256s",
      "VerifySLHDSA_SHA2_256f" => "verifySLHDSA_SHA2_256f",
      # Byte operations
      "Num2Bin" => "num2bin", "Bin2Num" => "bin2num", "Int2Str" => "int2str",
      "Cat" => "cat", "Substr" => "substr", "Split" => "split",
      "Left" => "left", "Right" => "right",
      "Len" => "len", "Pack" => "pack", "Unpack" => "unpack",
      "ReverseBytes" => "reverseBytes", "ToByteString" => "toByteString",
      "ToBool" => "bool",
      # Preimage extractors
      "ExtractVersion" => "extractVersion",
      "ExtractHashPrevouts" => "extractHashPrevouts",
      "ExtractHashSequence" => "extractHashSequence",
      "ExtractOutpoint" => "extractOutpoint",
      "ExtractScriptCode" => "extractScriptCode",
      "ExtractSequence" => "extractSequence",
      "ExtractSigHashType" => "extractSigHashType",
      "ExtractInputIndex" => "extractInputIndex",
      "ExtractOutputs" => "extractOutputs",
      "ExtractOutputHash" => "extractOutputHash",
      "ExtractAmount" => "extractAmount",
      "ExtractLocktime" => "extractLocktime",
      # Output construction
      "AddOutput" => "addOutput", "AddRawOutput" => "addRawOutput",
      "AddDataOutput" => "addDataOutput",
      "GetStateScript" => "getStateScript",
      # Math builtins
      "Abs" => "abs", "Min" => "min", "Max" => "max", "Within" => "within",
      "Safediv" => "safediv", "Safemod" => "safemod", "Clamp" => "clamp", "Sign" => "sign",
      "Pow" => "pow", "MulDiv" => "mulDiv", "PercentOf" => "percentOf", "Sqrt" => "sqrt",
      "Gcd" => "gcd", "Divmod" => "divmod", "Log2" => "log2",
      # EC builtins
      "EcAdd" => "ecAdd", "EcMul" => "ecMul", "EcMulGen" => "ecMulGen",
      "EcNegate" => "ecNegate", "EcOnCurve" => "ecOnCurve", "EcModReduce" => "ecModReduce",
      "EcEncodeCompressed" => "ecEncodeCompressed", "EcMakePoint" => "ecMakePoint",
      "EcPointX" => "ecPointX", "EcPointY" => "ecPointY",
      # SHA-256 partial
      "Sha256Compress" => "sha256Compress", "Sha256Finalize" => "sha256Finalize",
    }.freeze

    # Known type names used for type cast detection.
    GO_CAST_TYPES = %w[
      Int Bigint BigintBig Bool ByteString PubKey Sig Sha256
      Ripemd160 Addr SigHashPreimage RabinSig RabinPubKey Point
    ].to_set.freeze

    def self.go_map_builtin(name)
      return GO_BUILTIN_MAP[name] if GO_BUILTIN_MAP.key?(name)

      # Default: lowercase first letter
      return name if name.empty?

      name[0].downcase + name[1..]
    end

    # Decode Go string escape sequences (\n, \t, \r, \0, \\, \", \xNN) from the
    # raw text of a Go string literal.
    def self.go_decode_string_escapes(raw)
      out = String.new(encoding: Encoding::ASCII_8BIT)
      i = 0
      n = raw.length
      while i < n
        c = raw[i]
        if c == "\\" && i + 1 < n
          nx = raw[i + 1]
          case nx
          when "n" then out << "\n".b; i += 2
          when "t" then out << "\t".b; i += 2
          when "r" then out << "\r".b; i += 2
          when "0" then out << "\x00".b; i += 2
          when "\\" then out << "\\".b; i += 2
          when '"' then out << '"'.b; i += 2
          when "x"
            if i + 3 < n && raw[i + 2].match?(/[0-9a-fA-F]/) && raw[i + 3].match?(/[0-9a-fA-F]/)
              out << raw[(i + 2)..(i + 3)].to_i(16).chr
              i += 4
            else
              out << c.b
              i += 1
            end
          else
            out << nx.b
            i += 2
          end
        else
          out << c.b
          i += 1
        end
      end
      out
    end

    def self.go_map_type(name)
      mapped = GO_TYPE_MAP[name] || name
      if primitive_type?(mapped)
        return PrimitiveType.new(name: mapped)
      end
      CustomType.new(name: mapped)
    end

    # -------------------------------------------------------------------
    # Tokenizer
    # -------------------------------------------------------------------

    TWO_CHAR_OPS_GO = {
      ":=" => GoTokens::TOK_COLONEQ,
      "==" => GoTokens::TOK_EQEQ,
      "!=" => GoTokens::TOK_NOTEQ,
      "<=" => GoTokens::TOK_LTEQ,
      ">=" => GoTokens::TOK_GTEQ,
      "<<" => GoTokens::TOK_LSHIFT,
      ">>" => GoTokens::TOK_RSHIFT,
      "&&" => GoTokens::TOK_AMPAMP,
      "||" => GoTokens::TOK_PIPEPIPE,
      "++" => GoTokens::TOK_PLUSPLUS,
      "--" => GoTokens::TOK_MINUSMINUS,
      "+=" => GoTokens::TOK_PLUSEQ,
      "-=" => GoTokens::TOK_MINUSEQ,
      "*=" => GoTokens::TOK_STAREQ,
      "/=" => GoTokens::TOK_SLASHEQ,
      "%=" => GoTokens::TOK_PERCENTEQ,
    }.freeze

    ONE_CHAR_OPS_GO = {
      "(" => GoTokens::TOK_LPAREN,
      ")" => GoTokens::TOK_RPAREN,
      "[" => GoTokens::TOK_LBRACKET,
      "]" => GoTokens::TOK_RBRACKET,
      "{" => GoTokens::TOK_LBRACE,
      "}" => GoTokens::TOK_RBRACE,
      "," => GoTokens::TOK_COMMA,
      "." => GoTokens::TOK_DOT,
      ":" => GoTokens::TOK_COLON,
      ";" => GoTokens::TOK_SEMICOLON,
      "=" => GoTokens::TOK_ASSIGN,
      "<" => GoTokens::TOK_LT,
      ">" => GoTokens::TOK_GT,
      "+" => GoTokens::TOK_PLUS,
      "-" => GoTokens::TOK_MINUS,
      "*" => GoTokens::TOK_STAR,
      "/" => GoTokens::TOK_SLASH,
      "%" => GoTokens::TOK_PERCENT,
      "!" => GoTokens::TOK_BANG,
      "~" => GoTokens::TOK_TILDE,
      "&" => GoTokens::TOK_AMP,
      "|" => GoTokens::TOK_PIPE,
      "^" => GoTokens::TOK_CARET,
    }.freeze

    GO_HEX_CHARS = "0123456789abcdefABCDEF"

    def self.go_ident_start?(ch)
      (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch == "_"
    end

    def self.go_ident_part?(ch)
      go_ident_start?(ch) || (ch >= "0" && ch <= "9")
    end

    def self.tokenize_go(source)
      tokens = []
      line = 1
      col = 0
      i = 0
      n = source.length

      while i < n
        ch = source[i]

        # Newlines
        if ch == "\n"
          i += 1
          line += 1
          col = 0
          next
        end
        if ch == "\r"
          i += 1
          if i < n && source[i] == "\n"
            i += 1
          end
          line += 1
          col = 0
          next
        end

        # Whitespace
        if ch == " " || ch == "\t"
          i += 1
          col += 1
          next
        end

        # Single-line comment //
        if ch == "/" && i + 1 < n && source[i + 1] == "/"
          while i < n && source[i] != "\n" && source[i] != "\r"
            i += 1
          end
          next
        end

        # Multi-line comment /* ... */
        if ch == "/" && i + 1 < n && source[i + 1] == "*"
          i += 2
          col += 2
          while i + 1 < n
            if source[i] == "*" && source[i + 1] == "/"
              i += 2
              col += 2
              break
            end
            if source[i] == "\n"
              line += 1
              col = 0
            else
              col += 1
            end
            i += 1
          end
          next
        end

        start_col = col

        # Backtick-delimited struct tags
        if ch == "`"
          i += 1
          col += 1
          tag_start = i
          while i < n && source[i] != "`"
            if source[i] == "\n"
              line += 1
              col = 0
            else
              col += 1
            end
            i += 1
          end
          val = source[tag_start...i]
          if i < n
            i += 1
            col += 1
          end
          tokens << GoToken.new(kind: GoTokens::TOK_BACKTICK, value: val, line: line, col: start_col)
          next
        end

        # String literal
        if ch == '"'
          i += 1
          col += 1
          str_start = i
          while i < n && source[i] != '"'
            if source[i] == "\\"
              i += 1
              col += 1
            end
            if i < n
              i += 1
              col += 1
            end
          end
          val = source[str_start...i]
          if i < n
            i += 1
            col += 1
          end
          tokens << GoToken.new(kind: GoTokens::TOK_STRING, value: val, line: line, col: start_col)
          next
        end

        # Hex literal: 0x...
        if ch == "0" && i + 1 < n && (source[i + 1] == "x" || source[i + 1] == "X")
          i += 2
          col += 2
          hex_start = i
          while i < n && GO_HEX_CHARS.include?(source[i])
            i += 1
            col += 1
          end
          tokens << GoToken.new(kind: GoTokens::TOK_HEXSTRING, value: source[hex_start...i], line: line, col: start_col)
          next
        end

        # Number
        if ch >= "0" && ch <= "9"
          num_start = i
          while i < n && ((source[i] >= "0" && source[i] <= "9") || source[i] == "_")
            i += 1
            col += 1
          end
          tokens << GoToken.new(kind: GoTokens::TOK_NUMBER, value: source[num_start...i].delete("_"), line: line, col: start_col)
          next
        end

        # Identifiers and keywords
        if go_ident_start?(ch)
          id_start = i
          while i < n && go_ident_part?(source[i])
            i += 1
            col += 1
          end
          word = source[id_start...i]
          tokens << GoToken.new(kind: GoTokens::TOK_IDENT, value: word, line: line, col: start_col)
          next
        end

        # Two-character operators
        if i + 1 < n
          two = source[i, 2]
          two_kind = TWO_CHAR_OPS_GO[two]
          unless two_kind.nil?
            tokens << GoToken.new(kind: two_kind, value: two, line: line, col: start_col)
            i += 2
            col += 2
            next
          end
        end

        # Single-character operators
        one_kind = ONE_CHAR_OPS_GO[ch]
        unless one_kind.nil?
          tokens << GoToken.new(kind: one_kind, value: ch, line: line, col: start_col)
          i += 1
          col += 1
          next
        end

        # Skip unknown characters
        i += 1
        col += 1
      end

      tokens << GoToken.new(kind: GoTokens::TOK_EOF, value: "", line: line, col: col)
      tokens
    end

    # -------------------------------------------------------------------
    # Go parser
    # -------------------------------------------------------------------

    class GoParser
      include GoTokens

      def initialize(file_name)
        @file_name = file_name
        @tokens = []
        @pos = 0
        @errors = []
        @self_names = Set.new
        @contract_name = ""
      end

      attr_accessor :tokens, :pos, :errors

      # -- Token helpers --------------------------------------------------

      def peek
        return @tokens[@pos] if @pos < @tokens.length

        GoToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
      end

      def peek_next
        idx = @pos + 1
        return @tokens[idx] if idx < @tokens.length

        GoToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
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

      def loc
        tok = peek
        SourceLocation.new(file: @file_name, line: tok.line, column: tok.col)
      end

      def add_error(msg)
        @errors << Diagnostic.new(message: msg, severity: Severity::ERROR)
      end

      # -- Top-level parsing -----------------------------------------------

      def parse_contract
        # Skip `package contract`
        if check_ident("package")
          advance
          advance if check(TOK_IDENT)
        end

        # Skip imports
        skip_imports

        parent_class = "SmartContract"
        properties = []
        methods = []

        # Parse top-level declarations
        while !check(TOK_EOF)
          if check_ident("type")
            result = parse_struct_decl
            if result
              @contract_name = result[:name]
              parent_class = result[:parent_class]
              properties = result[:properties]
            end
          elsif check_ident("func")
            method = parse_func_decl
            methods << method if method
          else
            advance # skip unknown top-level tokens
          end
        end

        # Process init() method: extract property initializers
        final_methods = []
        methods.each do |m|
          if m.name == "init" && m.params.empty?
            # Extract property assignments as initializers
            m.body.each do |stmt|
              if stmt.is_a?(AssignmentStmt) && stmt.target.is_a?(PropertyAccessExpr)
                prop_name = stmt.target.property
                properties.each_with_index do |prop, idx|
                  if prop.name == prop_name
                    properties[idx] = PropertyNode.new(
                      name: prop.name,
                      type: prop.type,
                      readonly: prop.readonly,
                      initializer: stmt.value,
                      source_location: prop.source_location
                    )
                    break
                  end
                end
              end
            end
          else
            final_methods << m
          end
        end

        # Build auto-generated constructor
        default_loc = SourceLocation.new(file: @file_name, line: 1, column: 0)
        uninit_props = properties.reject { |p| p.initializer }

        super_call = ExpressionStmt.new(
          expr: CallExpr.new(
            callee: Identifier.new(name: "super"),
            args: uninit_props.map { |p| Identifier.new(name: p.name) }
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

        constructor = MethodNode.new(
          name: "constructor",
          params: uninit_props.map { |p| ParamNode.new(name: p.name, type: p.type) },
          body: [super_call] + assignments,
          visibility: "public",
          source_location: default_loc
        )

        contract_name = @contract_name.empty? ? "UnnamedContract" : @contract_name

        ContractNode.new(
          name: contract_name,
          parent_class: parent_class,
          properties: properties,
          constructor: constructor,
          methods: final_methods,
          source_file: @file_name
        )
      end

      # -- Import skipping -------------------------------------------------

      def skip_imports
        while check_ident("import")
          advance
          if check(TOK_LPAREN)
            # import ( ... )
            advance
            while !check(TOK_RPAREN) && !check(TOK_EOF)
              advance
            end
            advance if check(TOK_RPAREN)
          else
            # import ident "string"
            while !check(TOK_EOF)
              t = peek.kind
              break if peek.kind == TOK_IDENT && %w[type func import package var].include?(peek.value)
              advance
            end
          end
        end
      end

      # -- Struct declaration -----------------------------------------------

      def parse_struct_decl
        expect_ident("type")
        name_tok = expect(TOK_IDENT)
        name = name_tok.value
        expect_ident("struct")
        expect(TOK_LBRACE)

        parent_class = "SmartContract"
        properties = []

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          prop_loc = loc

          # Check for embedded type: runar.SmartContract / runar.StatefulSmartContract
          if check_ident("runar") && peek_next.kind == TOK_DOT
            advance # skip 'runar'
            advance # skip '.'
            embed_name = expect(TOK_IDENT).value
            parent_class = "StatefulSmartContract" if embed_name == "StatefulSmartContract"
            next
          end

          # Property: Name Type [`runar:"readonly"`]
          # Handle comma-separated field names: X, Y runar.Bigint
          field_names = []
          field_names << expect(TOK_IDENT).value

          while check(TOK_COMMA)
            advance
            field_names << expect(TOK_IDENT).value
          end

          # Parse type
          prop_type = parse_go_type

          # Check for struct tag
          readonly = false
          if check(TOK_BACKTICK)
            tag_value = peek.value
            readonly = true if tag_value.include?('runar:"readonly"')
            advance
          end

          field_names.each do |field_name|
            properties << PropertyNode.new(
              name: Frontend.go_to_camel(field_name),
              type: prop_type,
              readonly: readonly,
              source_location: prop_loc
            )
          end
        end
        expect(TOK_RBRACE)

        { name: name, parent_class: parent_class, properties: properties }
      end

      def expect_ident(value)
        tok = advance
        if tok.kind != TOK_IDENT || tok.value != value
          add_error("line #{tok.line}: expected '#{value}', got #{tok.value.inspect}")
        end
        tok
      end

      # -- Type parsing -----------------------------------------------------

      def parse_go_type
        # Handle runar.TypeName
        if check_ident("runar") && peek_next.kind == TOK_DOT
          advance # skip 'runar'
          advance # skip '.'
          type_name = expect(TOK_IDENT).value
          return Frontend.go_map_type(type_name)
        end

        # Handle bare types: bool, int, etc.
        if check(TOK_IDENT)
          type_name = advance.value
          return Frontend.go_map_type(type_name)
        end

        # Handle array types: [N]Type
        if check(TOK_LBRACKET)
          advance
          length_tok = expect(TOK_NUMBER)
          length = begin
            Integer(length_tok.value, 10)
          rescue ArgumentError
            0
          end
          expect(TOK_RBRACKET)
          element = parse_go_type
          return FixedArrayType.new(element: element, length: length)
        end

        # Fallback
        advance
        CustomType.new(name: "unknown")
      end

      # -- Function/method declaration --------------------------------------

      def parse_func_decl
        location = loc
        expect_ident("func")

        # Check for receiver: (c *Type)
        has_receiver = false
        recv_name = ""

        if check(TOK_LPAREN)
          advance # '('
          recv_name = expect(TOK_IDENT).value
          # Skip '*'
          if check(TOK_STAR)
            advance
          end
          # Skip type name
          if check(TOK_IDENT)
            advance
          end
          expect(TOK_RPAREN)
          has_receiver = true
        end

        # Method/function name
        func_name = expect(TOK_IDENT).value

        # Set receiver name for this method
        @self_names = has_receiver ? Set.new([recv_name]) : Set.new

        # Parameters
        expect(TOK_LPAREN)
        params = []
        while !check(TOK_RPAREN) && !check(TOK_EOF)
          # Handle grouped params: x, y runar.Bigint
          param_names = []
          param_names << expect(TOK_IDENT).value

          while check(TOK_COMMA)
            saved_pos = @pos
            advance # skip ','

            # Check if this looks like a type (runar.X or bare type)
            if check(TOK_IDENT)
              if peek.value == "runar"
                # This is the type for the current group - don't consume
                @pos = saved_pos
                break
              end
              # Check what follows: if it's a comma or ), it's another name
              next_tok_kind = peek_next.kind
              if next_tok_kind == TOK_COMMA || next_tok_kind == TOK_RPAREN
                param_names << expect(TOK_IDENT).value
              else
                param_names << expect(TOK_IDENT).value
              end
            else
              @pos = saved_pos
              break
            end
          end

          # Parse type
          p_type = parse_go_type

          param_names.each do |p_name|
            params << ParamNode.new(name: Frontend.go_to_camel(p_name), type: p_type)
          end

          match_tok(TOK_COMMA)
        end
        expect(TOK_RPAREN)

        # Optional return type
        unless check(TOK_LBRACE)
          parse_go_type
        end

        # Body
        expect(TOK_LBRACE)
        body = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          body << parse_statement
        end
        expect(TOK_RBRACE)

        # Determine visibility: capitalized = public, lowercase = private
        is_exported = !func_name.empty? &&
                      func_name[0] == func_name[0].upcase &&
                      func_name[0] != func_name[0].downcase
        visibility = is_exported && has_receiver ? "public" : "private"

        # Standalone functions (no receiver) are always private
        visibility = "private" unless has_receiver

        # Convert method name from Go PascalCase to Runar camelCase
        name = Frontend.go_to_camel(func_name)

        MethodNode.new(
          name: name,
          params: params,
          body: body,
          visibility: visibility,
          source_location: location
        )
      end

      # -- Statement parsing -------------------------------------------------

      def parse_statement
        location = loc

        # return
        if check_ident("return")
          advance
          value = nil
          if !check(TOK_RBRACE) && !check(TOK_EOF)
            value = parse_expression
          end
          return ReturnStmt.new(value: value, source_location: location)
        end

        # if
        if check_ident("if")
          return parse_if_statement
        end

        # for
        if check_ident("for")
          return parse_for_statement
        end

        # var declaration: var name Type = expr
        if check_ident("var")
          advance
          var_name = Frontend.go_to_camel(expect(TOK_IDENT).value)
          var_type = parse_go_type
          expect(TOK_ASSIGN)
          init = parse_expression
          return VariableDeclStmt.new(
            name: var_name,
            type: var_type,
            mutable: true,
            init: init,
            source_location: location
          )
        end

        # Short variable declaration: name := expr
        if check(TOK_IDENT) && peek_next.kind == TOK_COLONEQ
          var_name = Frontend.go_to_camel(advance.value)
          advance # skip ':='
          init = parse_expression
          return VariableDeclStmt.new(
            name: var_name,
            mutable: true,
            init: init,
            source_location: location
          )
        end

        # Expression statement (including assignments, inc/dec, calls)
        expr = parse_expression

        # Assignment: expr = expr
        if match_tok(TOK_ASSIGN)
          value = parse_expression
          return AssignmentStmt.new(target: expr, value: value, source_location: location)
        end

        # Compound assignments
        compound_ops = {
          TOK_PLUSEQ    => "+",
          TOK_MINUSEQ   => "-",
          TOK_STAREQ    => "*",
          TOK_SLASHEQ   => "/",
          TOK_PERCENTEQ => "%",
        }
        compound_ops.each do |kind, bin_op|
          if match_tok(kind)
            rhs = parse_expression
            return AssignmentStmt.new(
              target: expr,
              value: BinaryExpr.new(op: bin_op, left: expr, right: rhs),
              source_location: location
            )
          end
        end

        # Postfix ++ / -- as statements
        if match_tok(TOK_PLUSPLUS)
          return ExpressionStmt.new(
            expr: IncrementExpr.new(operand: expr, prefix: false),
            source_location: location
          )
        end
        if match_tok(TOK_MINUSMINUS)
          return ExpressionStmt.new(
            expr: DecrementExpr.new(operand: expr, prefix: false),
            source_location: location
          )
        end

        ExpressionStmt.new(expr: expr, source_location: location)
      end

      def parse_if_statement
        location = loc
        expect_ident("if")

        # Go if condition has no parentheses
        condition = parse_expression
        expect(TOK_LBRACE)
        then_block = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          then_block << parse_statement
        end
        expect(TOK_RBRACE)

        else_block = []
        if check_ident("else")
          advance
          if check_ident("if")
            # else if -- parse as nested if_statement in the else branch
            else_block = [parse_if_statement]
          else
            expect(TOK_LBRACE)
            while !check(TOK_RBRACE) && !check(TOK_EOF)
              else_block << parse_statement
            end
            expect(TOK_RBRACE)
          end
        end

        IfStmt.new(
          condition: condition,
          then: then_block,
          else_: else_block,
          source_location: location
        )
      end

      def parse_for_statement
        location = loc
        expect_ident("for")

        # Init: i := 0 (or var i int = 0)
        if check_ident("var")
          init_stmt = parse_statement
        else
          # Short variable declaration: name := expr
          init_name = Frontend.go_to_camel(expect(TOK_IDENT).value)
          expect(TOK_COLONEQ)
          init_value = parse_expression
          init_stmt = VariableDeclStmt.new(
            name: init_name,
            mutable: true,
            init: init_value,
            source_location: location
          )
        end

        expect(TOK_SEMICOLON)

        # Condition
        condition = parse_expression
        expect(TOK_SEMICOLON)

        # Update: i++ or i-- or expr
        update_expr = parse_expression

        if match_tok(TOK_PLUSPLUS)
          update = ExpressionStmt.new(
            expr: IncrementExpr.new(operand: update_expr, prefix: false),
            source_location: location
          )
        elsif match_tok(TOK_MINUSMINUS)
          update = ExpressionStmt.new(
            expr: DecrementExpr.new(operand: update_expr, prefix: false),
            source_location: location
          )
        elsif match_tok(TOK_PLUSEQ)
          rhs = parse_expression
          update = AssignmentStmt.new(
            target: update_expr,
            value: BinaryExpr.new(op: "+", left: update_expr, right: rhs),
            source_location: location
          )
        elsif match_tok(TOK_MINUSEQ)
          rhs = parse_expression
          update = AssignmentStmt.new(
            target: update_expr,
            value: BinaryExpr.new(op: "-", left: update_expr, right: rhs),
            source_location: location
          )
        else
          update = ExpressionStmt.new(expr: update_expr, source_location: location)
        end

        expect(TOK_LBRACE)
        body = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          body << parse_statement
        end
        expect(TOK_RBRACE)

        ForStmt.new(
          init: init_stmt,
          condition: condition,
          update: update,
          body: body,
          source_location: location
        )
      end

      # -- Expression parsing (precedence climbing) -------------------------

      def parse_expression
        parse_or
      end

      def parse_or
        left = parse_and
        while match_tok(TOK_PIPEPIPE)
          left = BinaryExpr.new(op: "||", left: left, right: parse_and)
        end
        left
      end

      def parse_and
        left = parse_bit_or
        while match_tok(TOK_AMPAMP)
          left = BinaryExpr.new(op: "&&", left: left, right: parse_bit_or)
        end
        left
      end

      def parse_bit_or
        left = parse_bit_xor
        while check(TOK_PIPE) && !(@pos + 1 < @tokens.length && @tokens[@pos + 1].kind == TOK_PIPE)
          advance
          left = BinaryExpr.new(op: "|", left: left, right: parse_bit_xor)
        end
        left
      end

      def parse_bit_xor
        left = parse_bit_and
        while match_tok(TOK_CARET)
          left = BinaryExpr.new(op: "^", left: left, right: parse_bit_and)
        end
        left
      end

      def parse_bit_and
        left = parse_equality
        while check(TOK_AMP) && !(@pos + 1 < @tokens.length && @tokens[@pos + 1].kind == TOK_AMP)
          advance
          left = BinaryExpr.new(op: "&", left: left, right: parse_equality)
        end
        left
      end

      def parse_equality
        left = parse_comparison
        loop do
          if match_tok(TOK_EQEQ)
            left = BinaryExpr.new(op: "===", left: left, right: parse_comparison)
          elsif match_tok(TOK_NOTEQ)
            left = BinaryExpr.new(op: "!==", left: left, right: parse_comparison)
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
            left = BinaryExpr.new(op: "<", left: left, right: parse_shift)
          elsif match_tok(TOK_LTEQ)
            left = BinaryExpr.new(op: "<=", left: left, right: parse_shift)
          elsif match_tok(TOK_GT)
            left = BinaryExpr.new(op: ">", left: left, right: parse_shift)
          elsif match_tok(TOK_GTEQ)
            left = BinaryExpr.new(op: ">=", left: left, right: parse_shift)
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
            left = BinaryExpr.new(op: "<<", left: left, right: parse_additive)
          elsif match_tok(TOK_RSHIFT)
            left = BinaryExpr.new(op: ">>", left: left, right: parse_additive)
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
            left = BinaryExpr.new(op: "+", left: left, right: parse_multiplicative)
          elsif match_tok(TOK_MINUS)
            left = BinaryExpr.new(op: "-", left: left, right: parse_multiplicative)
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
            left = BinaryExpr.new(op: "*", left: left, right: parse_unary)
          elsif match_tok(TOK_SLASH)
            left = BinaryExpr.new(op: "/", left: left, right: parse_unary)
          elsif match_tok(TOK_PERCENT)
            left = BinaryExpr.new(op: "%", left: left, right: parse_unary)
          else
            break
          end
        end
        left
      end

      def parse_unary
        if match_tok(TOK_BANG)
          return UnaryExpr.new(op: "!", operand: parse_unary)
        end
        if match_tok(TOK_MINUS)
          return UnaryExpr.new(op: "-", operand: parse_unary)
        end
        if match_tok(TOK_TILDE)
          return UnaryExpr.new(op: "~", operand: parse_unary)
        end
        # Go uses ^ as bitwise NOT (complement) when used as unary prefix
        if match_tok(TOK_CARET)
          return UnaryExpr.new(op: "~", operand: parse_unary)
        end

        expr = parse_primary
        parse_postfix_chain(expr)
      end

      def parse_postfix_chain(expr)
        loop do
          if check(TOK_LPAREN)
            # Function call
            advance
            args = []
            while !check(TOK_RPAREN) && !check(TOK_EOF)
              args << parse_expression
              match_tok(TOK_COMMA)
            end
            expect(TOK_RPAREN)
            expr = CallExpr.new(callee: expr, args: args)
          elsif match_tok(TOK_DOT)
            raw_prop = peek.value
            advance
            prop = Frontend.go_to_camel(raw_prop)
            # self.property -> PropertyAccessExpr
            if expr.is_a?(Identifier) && @self_names.include?(expr.name)
              expr = PropertyAccessExpr.new(property: prop)
            else
              expr = MemberExpr.new(object: expr, property: prop)
            end
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

      def parse_primary
        tok = peek

        # Number literal
        if tok.kind == TOK_NUMBER
          advance
          val = begin
            Integer(tok.value, 10)
          rescue ArgumentError
            0
          end
          return BigIntLiteral.new(value: val)
        end

        # Hex string literal
        if tok.kind == TOK_HEXSTRING
          advance
          return ByteStringLiteral.new(value: tok.value)
        end

        # String literal -- used for hex-encoded ByteString values in Go contracts
        if tok.kind == TOK_STRING
          advance
          return ByteStringLiteral.new(value: tok.value)
        end

        # Boolean literals
        if tok.kind == TOK_IDENT && tok.value == "true"
          advance
          return BoolLiteral.new(value: true)
        end
        if tok.kind == TOK_IDENT && tok.value == "false"
          advance
          return BoolLiteral.new(value: false)
        end

        # Parenthesized expression
        if tok.kind == TOK_LPAREN
          advance
          expr = parse_expression
          expect(TOK_RPAREN)
          return expr
        end

        # Array literal: [expr, expr, ...]
        if tok.kind == TOK_LBRACKET
          advance
          elements = []
          while !check(TOK_RBRACKET) && !check(TOK_EOF)
            elements << parse_expression
            match_tok(TOK_COMMA)
          end
          expect(TOK_RBRACKET)
          return CallExpr.new(callee: Identifier.new(name: "FixedArray"), args: elements)
        end

        # Identifier -- handles runar.X, receiver.Field, plain idents
        if tok.kind == TOK_IDENT
          advance

          # Check for runar.X(args) -- builtin call or type cast
          if tok.value == "runar" && check(TOK_DOT)
            advance # skip '.'
            member_name = expect(TOK_IDENT).value

            # Special-case runar.ByteString("literal") -> ByteStringLiteral
            # with hex-encoded raw bytes. Any other arg form (e.g. a variable)
            # falls through to the generic type-cast unwrap below.
            if member_name == "ByteString" && check(TOK_LPAREN) && @tokens[@pos + 1]&.kind == TOK_STRING && @tokens[@pos + 2]&.kind == TOK_RPAREN
              advance # consume '('
              str_tok = advance # consume string
              advance # consume ')'
              hex_str = Frontend.go_decode_string_escapes(str_tok.value).bytes.map { |b| format("%02x", b) }.join
              return ByteStringLiteral.new(value: hex_str)
            end

            # Check for type cast: runar.Bigint(expr), runar.Bool(expr), etc.
            if GO_CAST_TYPES.include?(member_name) && check(TOK_LPAREN)
              advance # '('
              inner = parse_expression
              expect(TOK_RPAREN)
              return inner # unwrap type cast
            end

            # Map to builtin name
            builtin_name = Frontend.go_map_builtin(member_name)
            return Identifier.new(name: builtin_name)
          end

          # Receiver name -- will be resolved in postfix chain
          if @self_names.include?(tok.value)
            return Identifier.new(name: tok.value)
          end

          # Non-receiver identifiers get camelCase conversion
          return Identifier.new(name: Frontend.go_to_camel(tok.value))
        end

        # Fallback
        advance
        Identifier.new(name: tok.value)
      end
    end

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    # Parse a Go-format Runar contract (.runar.go).
    #
    # @param source [String] the source code
    # @param file_name [String] the file name (used in diagnostics)
    # @return [ParseResult]
    def self.parse_go(source, file_name)
      p = GoParser.new(file_name)
      p.tokens = tokenize_go(source)
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
