# frozen_string_literal: true

# Move-style format parser (.runar.move) for the Runar compiler.
#
# Ported from packages/runar-compiler/src/passes/01-parse-move.ts.
# Hand-written tokenizer + recursive descent parser for Move-style syntax.

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"

module RunarCompiler
  module Frontend
    # -------------------------------------------------------------------
    # Move token type constants (namespaced to avoid collisions)
    # -------------------------------------------------------------------

    module MoveTokens
      TOK_EOF          = 0
      TOK_IDENT        = 1
      TOK_NUMBER       = 2
      TOK_HEXSTRING    = 3
      TOK_LBRACE       = 4
      TOK_RBRACE       = 5
      TOK_LPAREN       = 6
      TOK_RPAREN       = 7
      TOK_LBRACKET     = 8
      TOK_RBRACKET     = 9
      TOK_SEMICOLON    = 10
      TOK_COMMA        = 11
      TOK_DOT          = 12
      TOK_COLON        = 13
      TOK_COLONCOLON   = 14
      TOK_ARROW        = 15  # ->
      TOK_ASSIGN       = 16
      TOK_EQEQ         = 17  # ==
      TOK_NOTEQ        = 18  # !=
      TOK_LT           = 19
      TOK_LTEQ         = 20  # <=
      TOK_GT           = 21
      TOK_GTEQ         = 22  # >=
      TOK_PLUS         = 23
      TOK_MINUS        = 24
      TOK_STAR         = 25
      TOK_SLASH        = 26
      TOK_PERCENT      = 27
      TOK_BANG         = 28
      TOK_TILDE        = 29
      TOK_AMP          = 30
      TOK_PIPE         = 31
      TOK_CARET        = 32
      TOK_AMPAMP       = 33  # &&
      TOK_PIPEPIPE     = 34  # ||
      TOK_PLUSEQ       = 35  # +=
      TOK_MINUSEQ      = 36  # -=
      TOK_ASSERT_BANG  = 37  # assert!
      TOK_ASSERTEQ_BANG = 38 # assert_eq!
    end

    # A single token produced by the Move tokenizer.
    MoveToken = Struct.new(:kind, :value, :line, :col, keyword_init: true)

    # -------------------------------------------------------------------
    # Move type mapping
    # -------------------------------------------------------------------

    MOVE_TYPE_MAP = {
      "u64"     => "bigint",
      "u128"    => "bigint",
      "u256"    => "bigint",
      "Int"     => "bigint",
      "Bigint"  => "bigint",
      "bool"    => "boolean",
      "Bool"    => "boolean",
      "vector"  => "ByteString",
      "address" => "Addr",
    }.freeze

    # -------------------------------------------------------------------
    # snake_case to camelCase conversion
    # -------------------------------------------------------------------

    def self.move_snake_to_camel(name)
      parts = name.split("_")
      return name if parts.length <= 1

      result = parts[0]
      parts[1..].each do |part|
        next if part.empty?

        result += part[0].upcase + part[1..]
      end
      result
    end

    # -------------------------------------------------------------------
    # Move builtin name mapping
    # -------------------------------------------------------------------

    MOVE_BUILTIN_MAP = {
      # Hashing
      "hash160"  => "hash160",  "hash256"  => "hash256",
      "sha256"   => "sha256",   "ripemd160" => "ripemd160",
      # Signature verification
      "checkSig" => "checkSig", "checkMultiSig" => "checkMultiSig",
      "checkPreimage" => "checkPreimage", "verifyRabinSig" => "verifyRabinSig",
      # Post-quantum
      "verifyWOTS" => "verifyWOTS", "verifyWots" => "verifyWOTS",
      "verifySlhdsaSha2128s" => "verifySLHDSA_SHA2_128s", "verifySlhDsaSha2128s" => "verifySLHDSA_SHA2_128s",
      "verifySlhdsaSha2128f" => "verifySLHDSA_SHA2_128f", "verifySlhDsaSha2128f" => "verifySLHDSA_SHA2_128f",
      "verifySlhdsaSha2192s" => "verifySLHDSA_SHA2_192s", "verifySlhDsaSha2192s" => "verifySLHDSA_SHA2_192s",
      "verifySlhdsaSha2192f" => "verifySLHDSA_SHA2_192f", "verifySlhDsaSha2192f" => "verifySLHDSA_SHA2_192f",
      "verifySlhdsaSha2256s" => "verifySLHDSA_SHA2_256s", "verifySlhDsaSha2256s" => "verifySLHDSA_SHA2_256s",
      "verifySlhdsaSha2256f" => "verifySLHDSA_SHA2_256f", "verifySlhDsaSha2256f" => "verifySLHDSA_SHA2_256f",
      # Byte operations
      "num2bin" => "num2bin", "num2Bin" => "num2bin",
      "bin2num" => "bin2num", "bin2Num" => "bin2num",
      "int2str" => "int2str", "int2Str" => "int2str",
      "reverseByteString" => "reverseBytes", "reverseBytes" => "reverseBytes",
      "toByteString" => "toByteString",
      "cat" => "cat", "substr" => "substr", "split" => "split",
      "left" => "left", "right" => "right",
      "len" => "len", "pack" => "pack", "unpack" => "unpack", "bool" => "bool",
      # Preimage extractors
      "extractVersion" => "extractVersion",
      "extractHashPrevouts" => "extractHashPrevouts",
      "extractHashSequence" => "extractHashSequence",
      "extractOutpoint" => "extractOutpoint",
      "extractScriptCode" => "extractScriptCode",
      "extractSequence" => "extractSequence",
      "extractSigHashType" => "extractSigHashType",
      "extractInputIndex" => "extractInputIndex",
      "extractOutputs" => "extractOutputs",
      "extractAmount" => "extractAmount",
      "extractLocktime" => "extractLocktime",
      "extractOutputHash" => "extractOutputHash",
      # Output construction
      "addOutput" => "addOutput", "addRawOutput" => "addRawOutput",
      # Math builtins
      "abs" => "abs", "min" => "min", "max" => "max", "within" => "within",
      "safediv" => "safediv", "safemod" => "safemod", "clamp" => "clamp", "sign" => "sign",
      "pow" => "pow", "mulDiv" => "mulDiv", "percentOf" => "percentOf", "sqrt" => "sqrt",
      "gcd" => "gcd", "divmod" => "divmod", "log2" => "log2",
      # EC builtins
      "ecAdd" => "ecAdd", "ecMul" => "ecMul", "ecMulGen" => "ecMulGen",
      "ecNegate" => "ecNegate", "ecOnCurve" => "ecOnCurve", "ecModReduce" => "ecModReduce",
      "ecEncodeCompressed" => "ecEncodeCompressed", "ecMakePoint" => "ecMakePoint",
      "ecPointX" => "ecPointX", "ecPointY" => "ecPointY",
      # SHA-256 partial
      "sha256Compress" => "sha256Compress", "sha256Finalize" => "sha256Finalize",
    }.freeze

    def self.move_map_builtin(name)
      MOVE_BUILTIN_MAP[name] || name
    end

    # -------------------------------------------------------------------
    # Move type node helper
    # -------------------------------------------------------------------

    def self.move_map_type(name)
      if MOVE_TYPE_MAP.key?(name)
        return PrimitiveType.new(name: MOVE_TYPE_MAP[name])
      end

      camel = move_snake_to_camel(name)
      return PrimitiveType.new(name: camel) if primitive_type?(camel)
      return PrimitiveType.new(name: name) if primitive_type?(name)

      CustomType.new(name: camel)
    end

    # -------------------------------------------------------------------
    # Tokenizer
    # -------------------------------------------------------------------

    TWO_CHAR_OPS_MOVE = {
      "::" => MoveTokens::TOK_COLONCOLON,
      "->" => MoveTokens::TOK_ARROW,
      "==" => MoveTokens::TOK_EQEQ,
      "!=" => MoveTokens::TOK_NOTEQ,
      "<=" => MoveTokens::TOK_LTEQ,
      ">=" => MoveTokens::TOK_GTEQ,
      "&&" => MoveTokens::TOK_AMPAMP,
      "||" => MoveTokens::TOK_PIPEPIPE,
      "+=" => MoveTokens::TOK_PLUSEQ,
      "-=" => MoveTokens::TOK_MINUSEQ,
    }.freeze

    ONE_CHAR_OPS_MOVE = {
      "(" => MoveTokens::TOK_LPAREN,
      ")" => MoveTokens::TOK_RPAREN,
      "[" => MoveTokens::TOK_LBRACKET,
      "]" => MoveTokens::TOK_RBRACKET,
      "{" => MoveTokens::TOK_LBRACE,
      "}" => MoveTokens::TOK_RBRACE,
      "," => MoveTokens::TOK_COMMA,
      "." => MoveTokens::TOK_DOT,
      ":" => MoveTokens::TOK_COLON,
      ";" => MoveTokens::TOK_SEMICOLON,
      "=" => MoveTokens::TOK_ASSIGN,
      "<" => MoveTokens::TOK_LT,
      ">" => MoveTokens::TOK_GT,
      "+" => MoveTokens::TOK_PLUS,
      "-" => MoveTokens::TOK_MINUS,
      "*" => MoveTokens::TOK_STAR,
      "/" => MoveTokens::TOK_SLASH,
      "%" => MoveTokens::TOK_PERCENT,
      "!" => MoveTokens::TOK_BANG,
      "~" => MoveTokens::TOK_TILDE,
      "&" => MoveTokens::TOK_AMP,
      "|" => MoveTokens::TOK_PIPE,
      "^" => MoveTokens::TOK_CARET,
    }.freeze

    MOVE_KEYWORDS = %w[module use resource struct public fun let mut if else
                       loop while return true false has].to_set.freeze

    MOVE_HEX_CHARS = "0123456789abcdefABCDEF"

    def self.move_ident_start?(ch)
      (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch == "_"
    end

    def self.move_ident_part?(ch)
      move_ident_start?(ch) || (ch >= "0" && ch <= "9")
    end

    def self.tokenize_move(source)
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

        # Hex literal: 0x...
        if ch == "0" && i + 1 < n && (source[i + 1] == "x" || source[i + 1] == "X")
          i += 2
          col += 2
          hex_start = i
          while i < n && MOVE_HEX_CHARS.include?(source[i])
            i += 1
            col += 1
          end
          tokens << MoveToken.new(kind: MoveTokens::TOK_HEXSTRING, value: source[hex_start...i], line: line, col: start_col)
          next
        end

        # Number
        if ch >= "0" && ch <= "9"
          num_start = i
          while i < n && ((source[i] >= "0" && source[i] <= "9") || source[i] == "_")
            i += 1
            col += 1
          end
          tokens << MoveToken.new(kind: MoveTokens::TOK_NUMBER, value: source[num_start...i].delete("_"), line: line, col: start_col)
          next
        end

        # Identifiers and keywords (including assert!/assert_eq!)
        if move_ident_start?(ch)
          id_start = i
          while i < n && move_ident_part?(source[i])
            i += 1
            col += 1
          end
          word = source[id_start...i]

          # Check for assert!/assert_eq!
          if (word == "assert" || word == "assert_eq") && i < n && source[i] == "!"
            word += "!"
            i += 1
            col += 1
            if word == "assert!"
              tokens << MoveToken.new(kind: MoveTokens::TOK_ASSERT_BANG, value: word, line: line, col: start_col)
            else
              tokens << MoveToken.new(kind: MoveTokens::TOK_ASSERTEQ_BANG, value: word, line: line, col: start_col)
            end
            next
          end

          tokens << MoveToken.new(kind: MoveTokens::TOK_IDENT, value: word, line: line, col: start_col)
          next
        end

        # Two-character operators
        if i + 1 < n
          two = source[i, 2]
          two_kind = TWO_CHAR_OPS_MOVE[two]
          unless two_kind.nil?
            tokens << MoveToken.new(kind: two_kind, value: two, line: line, col: start_col)
            i += 2
            col += 2
            next
          end
        end

        # Single-character operators
        one_kind = ONE_CHAR_OPS_MOVE[ch]
        unless one_kind.nil?
          tokens << MoveToken.new(kind: one_kind, value: ch, line: line, col: start_col)
          i += 1
          col += 1
          next
        end

        # Skip unknown characters
        i += 1
        col += 1
      end

      tokens << MoveToken.new(kind: MoveTokens::TOK_EOF, value: "", line: line, col: col)
      tokens
    end

    # -------------------------------------------------------------------
    # Move parser
    # -------------------------------------------------------------------

    class MoveParser
      include MoveTokens

      def initialize(file_name)
        @file_name = file_name
        @tokens = []
        @pos = 0
        @errors = []
      end

      attr_accessor :tokens, :pos, :errors

      # -- Token helpers --------------------------------------------------

      def peek
        return @tokens[@pos] if @pos < @tokens.length

        MoveToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
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
        # module ContractName { ... }
        expect_ident("module")
        name_tok = expect(TOK_IDENT)
        contract_name = name_tok.value
        expect(TOK_LBRACE)

        # Skip use declarations
        while check_ident("use")
          advance
          while !check(TOK_SEMICOLON) && !check(TOK_EOF)
            advance
          end
          match_tok(TOK_SEMICOLON)
        end

        parent_class = "SmartContract"
        properties = []
        methods = []

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          if check_ident("resource") || check_ident("struct")
            is_resource = peek.value == "resource"
            advance
            # "resource struct"
            if check_ident("struct")
              advance
            end

            # Struct name (skip, should match module name)
            if check(TOK_IDENT) && !check_ident("has")
              advance
            end

            # Optional "has key, store" abilities
            if check_ident("has")
              advance
              while !check(TOK_LBRACE) && !check(TOK_EOF)
                advance
              end
            end

            expect(TOK_LBRACE)
            has_mutable = false

            while !check(TOK_RBRACE) && !check(TOK_EOF)
              prop_loc = loc
              prop_name_raw = expect(TOK_IDENT).value
              prop_name = Frontend.move_snake_to_camel(prop_name_raw)
              expect(TOK_COLON)

              # Check for &mut (mutable reference)
              readonly = true
              if check(TOK_AMP)
                advance
                if check_ident("mut")
                  advance
                  readonly = false
                end
              end

              type_node = parse_move_type
              has_mutable = true unless readonly

              # Optional initializer: = value
              initializer = nil
              if check(TOK_ASSIGN)
                advance
                initializer = parse_expression
              end

              properties << PropertyNode.new(
                name: prop_name,
                type: type_node,
                readonly: readonly,
                initializer: initializer,
                source_location: prop_loc
              )

              match_tok(TOK_COMMA)
            end
            expect(TOK_RBRACE)

            parent_class = "StatefulSmartContract" if is_resource || has_mutable
          elsif check_ident("public") || check_ident("fun")
            method, has_mut_recv = parse_function_with_mut
            parent_class = "StatefulSmartContract" if has_mut_recv
            methods << method
          else
            advance # skip unknown
          end
        end
        expect(TOK_RBRACE)

        # Determine parent class from property mutability
        has_mutable = properties.any? { |p| !p.readonly }
        parent_class = "StatefulSmartContract" if has_mutable

        # Build constructor -- only non-initialized properties become params
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

        ContractNode.new(
          name: contract_name,
          parent_class: parent_class,
          properties: properties,
          constructor: constructor,
          methods: methods,
          source_file: @file_name
        )
      end

      # -- Expect an identifier with a specific value -----------------------

      def expect_ident(value)
        tok = advance
        if tok.kind != TOK_IDENT || tok.value != value
          add_error("line #{tok.line}: expected '#{value}', got #{tok.value.inspect}")
        end
        tok
      end

      # -- Type parsing -----------------------------------------------------

      def parse_move_type
        name_tok = expect(TOK_IDENT)
        name = name_tok.value

        # vector<T> => treat as ByteString
        if name == "vector" && check(TOK_LT)
          advance # <
          _inner = parse_move_type
          expect(TOK_GT)
          return PrimitiveType.new(name: "ByteString")
        end

        Frontend.move_map_type(name)
      end

      # -- Function parsing -------------------------------------------------

      # Returns [MethodNode, has_mut_receiver]
      def parse_function_with_mut
        location = loc
        visibility = "private"
        has_mut_receiver = false

        if check_ident("public")
          advance
          visibility = "public"
        end

        # Optional "entry" or "friend"
        if check(TOK_IDENT) && (peek.value == "entry" || peek.value == "friend")
          advance
        end

        expect_ident("fun")
        raw_name = expect(TOK_IDENT).value
        name = Frontend.move_snake_to_camel(raw_name)

        expect(TOK_LPAREN)
        params = []
        while !check(TOK_RPAREN) && !check(TOK_EOF)
          # Skip &self, &mut self, self: &ContractName
          if check(TOK_AMP)
            advance
            if check_ident("mut")
              advance
              has_mut_receiver = true
            end
            if check_ident("self")
              advance
              match_tok(TOK_COMMA)
              next
            end
          end
          if check_ident("self")
            advance
            match_tok(TOK_COMMA)
            next
          end

          p_name_raw = expect(TOK_IDENT).value

          # Check if this is "contract: &Type" pattern (skip it)
          if check(TOK_COLON)
            advance
            # Skip reference markers
            if check(TOK_AMP)
              advance
              if check_ident("mut")
                advance
                # If this is the contract/self param, it indicates statefulness
                has_mut_receiver = true if p_name_raw == "contract" || p_name_raw == "self"
              end
            end
            p_type = parse_move_type

            # If param name is 'contract' or 'self', skip it
            if p_name_raw == "contract" || p_name_raw == "self"
              match_tok(TOK_COMMA)
              next
            end

            params << ParamNode.new(
              name: Frontend.move_snake_to_camel(p_name_raw),
              type: p_type
            )
          end

          match_tok(TOK_COMMA)
        end
        expect(TOK_RPAREN)

        # Optional return type
        if check(TOK_COLON)
          advance
          parse_move_type
        end

        expect(TOK_LBRACE)
        body = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          body << parse_statement
        end
        expect(TOK_RBRACE)

        method = MethodNode.new(
          name: name,
          params: params,
          body: body,
          visibility: visibility,
          source_location: location
        )
        [method, has_mut_receiver]
      end

      # -- Statement parsing -------------------------------------------------

      def parse_statement
        location = loc

        # assert!(expr, code) -> assert(expr)
        if check(TOK_ASSERT_BANG)
          advance
          expect(TOK_LPAREN)
          expr = parse_expression
          # Skip optional error code
          if match_tok(TOK_COMMA)
            parse_expression # skip error code
          end
          expect(TOK_RPAREN)
          match_tok(TOK_SEMICOLON)
          return ExpressionStmt.new(
            expr: CallExpr.new(
              callee: Identifier.new(name: "assert"),
              args: [expr]
            ),
            source_location: location
          )
        end

        # assert_eq!(a, b) -> assert(a === b)
        if check(TOK_ASSERTEQ_BANG)
          advance
          expect(TOK_LPAREN)
          left_expr = parse_expression
          expect(TOK_COMMA)
          right_expr = parse_expression
          expect(TOK_RPAREN)
          match_tok(TOK_SEMICOLON)
          return ExpressionStmt.new(
            expr: CallExpr.new(
              callee: Identifier.new(name: "assert"),
              args: [BinaryExpr.new(op: "===", left: left_expr, right: right_expr)]
            ),
            source_location: location
          )
        end

        # let [mut] name [: type] = expr;
        if check_ident("let")
          advance
          mutable = false
          if check_ident("mut")
            advance
            mutable = true
          end
          var_name = Frontend.move_snake_to_camel(expect(TOK_IDENT).value)
          var_type = nil
          if match_tok(TOK_COLON)
            var_type = parse_move_type
          end
          expect(TOK_ASSIGN)
          init = parse_expression
          match_tok(TOK_SEMICOLON)
          return VariableDeclStmt.new(
            name: var_name,
            type: var_type,
            mutable: mutable,
            init: init,
            source_location: location
          )
        end

        # if
        if check_ident("if")
          return parse_if_statement(location)
        end

        # return
        if check_ident("return")
          advance
          value = nil
          if !check(TOK_SEMICOLON) && !check(TOK_RBRACE) && !check(TOK_EOF)
            value = parse_expression
          end
          match_tok(TOK_SEMICOLON)
          return ReturnStmt.new(value: value, source_location: location)
        end

        # Expression statement
        expr = parse_expression

        # Assignment: expr = value
        if match_tok(TOK_ASSIGN)
          value = parse_expression
          match_tok(TOK_SEMICOLON)
          target = convert_move_expr(expr)
          return AssignmentStmt.new(target: target, value: value, source_location: location)
        end

        # Compound assignment: +=
        if match_tok(TOK_PLUSEQ)
          rhs = parse_expression
          match_tok(TOK_SEMICOLON)
          target = convert_move_expr(expr)
          return AssignmentStmt.new(
            target: target,
            value: BinaryExpr.new(op: "+", left: target, right: rhs),
            source_location: location
          )
        end

        # Compound assignment: -=
        if match_tok(TOK_MINUSEQ)
          rhs = parse_expression
          match_tok(TOK_SEMICOLON)
          target = convert_move_expr(expr)
          return AssignmentStmt.new(
            target: target,
            value: BinaryExpr.new(op: "-", left: target, right: rhs),
            source_location: location
          )
        end

        match_tok(TOK_SEMICOLON)
        ExpressionStmt.new(expr: expr, source_location: location)
      end

      def convert_move_expr(expr)
        # Convert Move-style &contract.field to this.field
        if expr.is_a?(MemberExpr) && expr.object.is_a?(Identifier) && expr.object.name == "contract"
          return PropertyAccessExpr.new(property: Frontend.move_snake_to_camel(expr.property))
        end
        expr
      end

      def parse_if_statement(location)
        expect_ident("if")
        expect(TOK_LPAREN)
        condition = parse_expression
        expect(TOK_RPAREN)
        expect(TOK_LBRACE)

        then_block = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          then_block << parse_statement
        end
        expect(TOK_RBRACE)

        else_block = []
        if check_ident("else")
          advance
          expect(TOK_LBRACE)
          while !check(TOK_RBRACE) && !check(TOK_EOF)
            else_block << parse_statement
          end
          expect(TOK_RBRACE)
        end

        IfStmt.new(
          condition: condition,
          then: then_block,
          else_: else_block,
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
        left = parse_additive
        loop do
          if match_tok(TOK_LT)
            left = BinaryExpr.new(op: "<", left: left, right: parse_additive)
          elsif match_tok(TOK_LTEQ)
            left = BinaryExpr.new(op: "<=", left: left, right: parse_additive)
          elsif match_tok(TOK_GT)
            left = BinaryExpr.new(op: ">", left: left, right: parse_additive)
          elsif match_tok(TOK_GTEQ)
            left = BinaryExpr.new(op: ">=", left: left, right: parse_additive)
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
        # Dereference & -- skip
        if check(TOK_AMP)
          advance
          if check_ident("mut")
            advance
          end
          return parse_postfix
        end
        parse_postfix
      end

      def parse_postfix
        expr = parse_primary
        loop do
          if check(TOK_LPAREN)
            advance
            args = []
            while !check(TOK_RPAREN) && !check(TOK_EOF)
              args << parse_expression
              match_tok(TOK_COMMA)
            end
            expect(TOK_RPAREN)
            expr = CallExpr.new(callee: expr, args: args)
          elsif match_tok(TOK_DOT)
            prop = Frontend.move_snake_to_camel(expect(TOK_IDENT).value)
            if expr.is_a?(Identifier) && (expr.name == "self" || expr.name == "contract")
              expr = PropertyAccessExpr.new(property: prop)
            else
              expr = MemberExpr.new(object: expr, property: prop)
            end
          elsif match_tok(TOK_COLONCOLON)
            member = expect(TOK_IDENT).value
            # module::function -> just function name
            expr = Identifier.new(name: Frontend.move_snake_to_camel(member))
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

        # Array literal
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

        # Identifier
        if tok.kind == TOK_IDENT
          advance
          name = Frontend.move_snake_to_camel(tok.value)
          mapped = Frontend.move_map_builtin(name)
          return Identifier.new(name: mapped)
        end

        # Fallback
        advance
        Identifier.new(name: tok.value)
      end
    end

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    # Parse a Move-style Runar contract (.runar.move).
    #
    # @param source [String] the source code
    # @param file_name [String] the file name (used in diagnostics)
    # @return [ParseResult]
    def self.parse_move(source, file_name)
      p = MoveParser.new(file_name)
      p.tokens = tokenize_move(source)
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
