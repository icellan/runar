# frozen_string_literal: true

# Zig format parser (.runar.zig) for the Runar compiler.
#
# Ported from packages/runar-compiler/src/passes/01-parse-zig.ts.
# Hand-written tokenizer + recursive descent parser for Zig-like syntax.
#
# Zig syntax conventions used in Runar contracts:
#   - `const runar = @import("runar");` -- skipped import
#   - `pub const Name = struct { ... };` -- contract declaration
#   - `pub const Contract = runar.SmartContract;` / `runar.StatefulSmartContract;`
#   - Struct fields with optional `= initializer`
#   - `pub fn init(self: *Name, ...)` -- constructor
#   - `pub fn method(self: *Name, ...)` -- public methods
#   - `fn helper(self: *Name, ...)` -- private methods
#   - `self.property` -> PropertyAccessExpr
#   - `runar.builtin(...)` -> strip `runar.` prefix
#   - Zig types: `i8`-`i128`, `u8`-`u128` -> bigint; `bool` -> boolean
#   - While loops, if/else, compound assignment (`+=`, `-=`, etc.)
#   - `@divTrunc(a, b)` -> `a / b`, `@mod(a, b)` -> `a % b`
#   - `@intCast(x)`, `@truncate(x)` -> just `x`

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"

module RunarCompiler
  module Frontend
    # -----------------------------------------------------------------------
    # Namespaced token constants to avoid collisions with other parsers
    # -----------------------------------------------------------------------

    module ZigTokens
      TOK_EOF       = 0
      TOK_IDENT     = 1
      TOK_NUMBER    = 2
      TOK_STRING    = 3
      TOK_LPAREN    = 4
      TOK_RPAREN    = 5
      TOK_LBRACE    = 6
      TOK_RBRACE    = 7
      TOK_LBRACKET  = 8
      TOK_RBRACKET  = 9
      TOK_SEMICOLON = 10
      TOK_COMMA     = 11
      TOK_DOT       = 12
      TOK_COLON     = 13
      TOK_AT        = 14
      TOK_ASSIGN    = 15
      TOK_EQEQ     = 16
      TOK_NOTEQ     = 17
      TOK_LT        = 18
      TOK_LTEQ      = 19
      TOK_GT        = 20
      TOK_GTEQ      = 21
      TOK_PLUS      = 22
      TOK_MINUS     = 23
      TOK_STAR      = 24
      TOK_SLASH     = 25
      TOK_PERCENT   = 26
      TOK_BANG      = 27
      TOK_TILDE     = 28
      TOK_AMP       = 29
      TOK_PIPE      = 30
      TOK_CARET     = 31
      TOK_AMPAMP    = 32
      TOK_PIPEPIPE  = 33
      TOK_LSHIFT    = 34
      TOK_RSHIFT    = 35
      TOK_PLUSEQ    = 36
      TOK_MINUSEQ   = 37
      TOK_STAREQ    = 38
      TOK_SLASHEQ   = 39
      TOK_PERCENTEQ = 40

      # Keywords
      TOK_PUB    = 50
      TOK_CONST  = 51
      TOK_VAR    = 52
      TOK_FN     = 53
      TOK_STRUCT = 54
      TOK_IF     = 55
      TOK_ELSE   = 56
      TOK_FOR    = 57
      TOK_WHILE  = 58
      TOK_RETURN = 59
      TOK_TRUE   = 60
      TOK_FALSE  = 61
      TOK_VOID   = 62
    end

    # -----------------------------------------------------------------------
    # Type mappings
    # -----------------------------------------------------------------------

    ZIG_TYPE_MAP = {
      "i8"          => "bigint",
      "i16"         => "bigint",
      "i32"         => "bigint",
      "i64"         => "bigint",
      "i128"        => "bigint",
      "isize"       => "bigint",
      "u8"          => "bigint",
      "u16"         => "bigint",
      "u32"         => "bigint",
      "u64"         => "bigint",
      "u128"        => "bigint",
      "usize"       => "bigint",
      "comptime_int" => "bigint",
      "bool"        => "boolean",
      "void"        => "void",
      "Bigint"      => "bigint",
      "ByteString"  => "ByteString",
      "PubKey"      => "PubKey",
      "Sig"         => "Sig",
      "Sha256"      => "Sha256",
      "Sha256Digest" => "Sha256",
      "Ripemd160"   => "Ripemd160",
      "Addr"        => "Addr",
      "SigHashPreimage" => "SigHashPreimage",
      "RabinSig"    => "RabinSig",
      "RabinPubKey" => "RabinPubKey",
      "Point"       => "Point",
      "P256Point"   => "P256Point",
      "P384Point"   => "P384Point",
    }.freeze

    ZIG_KEYWORDS = {
      "pub"    => ZigTokens::TOK_PUB,
      "const"  => ZigTokens::TOK_CONST,
      "var"    => ZigTokens::TOK_VAR,
      "fn"     => ZigTokens::TOK_FN,
      "struct" => ZigTokens::TOK_STRUCT,
      "if"     => ZigTokens::TOK_IF,
      "else"   => ZigTokens::TOK_ELSE,
      "for"    => ZigTokens::TOK_FOR,
      "while"  => ZigTokens::TOK_WHILE,
      "return" => ZigTokens::TOK_RETURN,
      "true"   => ZigTokens::TOK_TRUE,
      "false"  => ZigTokens::TOK_FALSE,
      "void"   => ZigTokens::TOK_VOID,
      "and"    => ZigTokens::TOK_AMPAMP,
      "or"     => ZigTokens::TOK_PIPEPIPE,
    }.freeze

    # -----------------------------------------------------------------------
    # Token struct (reusable across parsers via keyword_init Struct)
    # -----------------------------------------------------------------------

    ZigToken = Struct.new(:kind, :value, :line, :col, keyword_init: true)

    # -----------------------------------------------------------------------
    # Tokenizer
    # -----------------------------------------------------------------------

    TWO_CHAR_ZIG_OPS = {
      "==" => ZigTokens::TOK_EQEQ,
      "!=" => ZigTokens::TOK_NOTEQ,
      "<=" => ZigTokens::TOK_LTEQ,
      ">=" => ZigTokens::TOK_GTEQ,
      "+=" => ZigTokens::TOK_PLUSEQ,
      "-=" => ZigTokens::TOK_MINUSEQ,
      "*=" => ZigTokens::TOK_STAREQ,
      "/=" => ZigTokens::TOK_SLASHEQ,
      "%=" => ZigTokens::TOK_PERCENTEQ,
      "&&" => ZigTokens::TOK_AMPAMP,
      "||" => ZigTokens::TOK_PIPEPIPE,
      "<<" => ZigTokens::TOK_LSHIFT,
      ">>" => ZigTokens::TOK_RSHIFT,
    }.freeze

    ONE_CHAR_ZIG_OPS = {
      "(" => ZigTokens::TOK_LPAREN,
      ")" => ZigTokens::TOK_RPAREN,
      "{" => ZigTokens::TOK_LBRACE,
      "}" => ZigTokens::TOK_RBRACE,
      "[" => ZigTokens::TOK_LBRACKET,
      "]" => ZigTokens::TOK_RBRACKET,
      ";" => ZigTokens::TOK_SEMICOLON,
      "," => ZigTokens::TOK_COMMA,
      "." => ZigTokens::TOK_DOT,
      ":" => ZigTokens::TOK_COLON,
      "@" => ZigTokens::TOK_AT,
      "=" => ZigTokens::TOK_ASSIGN,
      "<" => ZigTokens::TOK_LT,
      ">" => ZigTokens::TOK_GT,
      "+" => ZigTokens::TOK_PLUS,
      "-" => ZigTokens::TOK_MINUS,
      "*" => ZigTokens::TOK_STAR,
      "/" => ZigTokens::TOK_SLASH,
      "%" => ZigTokens::TOK_PERCENT,
      "!" => ZigTokens::TOK_BANG,
      "~" => ZigTokens::TOK_TILDE,
      "&" => ZigTokens::TOK_AMP,
      "|" => ZigTokens::TOK_PIPE,
      "^" => ZigTokens::TOK_CARET,
    }.freeze

    # Tokenize a Zig source string into an array of ZigToken structs.
    #
    # @param source [String]
    # @return [Array<ZigToken>]
    def self.tokenize_zig(source)
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
          found_end = false
          while i + 1 < n
            if source[i] == "*" && source[i + 1] == "/"
              i += 2
              col += 2
              found_end = true
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
          unless found_end
            i += 1 if i < n
          end
          next
        end

        start_col = col

        # String literals (double quotes)
        if ch == '"'
          i += 1
          col += 1
          start = i
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
          val = source[start...i]
          if i < n
            i += 1
            col += 1
          end
          tokens << ZigToken.new(kind: ZigTokens::TOK_STRING, value: val, line: line, col: start_col)
          next
        end

        # Numbers
        if ch >= "0" && ch <= "9"
          start = i
          if ch == "0" && i + 1 < n && (source[i + 1] == "x" || source[i + 1] == "X")
            i += 2
            col += 2
            while i < n && "0123456789abcdefABCDEF".include?(source[i])
              i += 1
              col += 1
            end
          else
            while i < n && ((source[i] >= "0" && source[i] <= "9") || source[i] == "_")
              i += 1
              col += 1
            end
          end
          num_str = source[start...i].delete("_")
          tokens << ZigToken.new(kind: ZigTokens::TOK_NUMBER, value: num_str, line: line, col: start_col)
          next
        end

        # Identifiers and keywords
        if (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch == "_"
          start = i
          while i < n && ((source[i] >= "a" && source[i] <= "z") ||
                          (source[i] >= "A" && source[i] <= "Z") ||
                          (source[i] >= "0" && source[i] <= "9") ||
                          source[i] == "_")
            i += 1
            col += 1
          end
          word = source[start...i]
          kind = ZIG_KEYWORDS[word] || ZigTokens::TOK_IDENT
          tokens << ZigToken.new(kind: kind, value: word, line: line, col: start_col)
          next
        end

        # Two-character operators
        if i + 1 < n
          two = source[i, 2]
          two_kind = TWO_CHAR_ZIG_OPS[two]
          unless two_kind.nil?
            tokens << ZigToken.new(kind: two_kind, value: two, line: line, col: start_col)
            i += 2
            col += 2
            next
          end
        end

        # Single-character operators
        one_kind = ONE_CHAR_ZIG_OPS[ch]
        unless one_kind.nil?
          tokens << ZigToken.new(kind: one_kind, value: ch, line: line, col: start_col)
          i += 1
          col += 1
          next
        end

        # Skip unknown characters
        i += 1
        col += 1
      end

      tokens << ZigToken.new(kind: ZigTokens::TOK_EOF, value: "", line: line, col: col)
      tokens
    end

    # -----------------------------------------------------------------------
    # Helper: map Zig type name to Runar type node
    # -----------------------------------------------------------------------

    def self.map_zig_type(name)
      ZIG_TYPE_MAP[name] || name
    end

    def self.zig_make_type_node(name)
      mapped = map_zig_type(name)
      if PRIMITIVE_TYPE_NAMES.include?(mapped)
        PrimitiveType.new(name: mapped)
      else
        CustomType.new(name: mapped)
      end
    end

    # -----------------------------------------------------------------------
    # Parser
    # -----------------------------------------------------------------------

    class ZigParser
      # Define token constants directly on the class to avoid Ruby's lexical
      # constant lookup finding identically-named constants from other parsers
      # that leak into the Frontend module (e.g., parser_ruby.rb defines
      # TOK_* at the Frontend level). `include ZigTokens` only affects method
      # resolution, not constant resolution in Ruby, so we duplicate here.
      TOK_EOF       = ZigTokens::TOK_EOF
      TOK_IDENT     = ZigTokens::TOK_IDENT
      TOK_NUMBER    = ZigTokens::TOK_NUMBER
      TOK_STRING    = ZigTokens::TOK_STRING
      TOK_LPAREN    = ZigTokens::TOK_LPAREN
      TOK_RPAREN    = ZigTokens::TOK_RPAREN
      TOK_LBRACE    = ZigTokens::TOK_LBRACE
      TOK_RBRACE    = ZigTokens::TOK_RBRACE
      TOK_LBRACKET  = ZigTokens::TOK_LBRACKET
      TOK_RBRACKET  = ZigTokens::TOK_RBRACKET
      TOK_SEMICOLON = ZigTokens::TOK_SEMICOLON
      TOK_COMMA     = ZigTokens::TOK_COMMA
      TOK_DOT       = ZigTokens::TOK_DOT
      TOK_COLON     = ZigTokens::TOK_COLON
      TOK_AT        = ZigTokens::TOK_AT
      TOK_ASSIGN    = ZigTokens::TOK_ASSIGN
      TOK_EQEQ     = ZigTokens::TOK_EQEQ
      TOK_NOTEQ     = ZigTokens::TOK_NOTEQ
      TOK_LT        = ZigTokens::TOK_LT
      TOK_LTEQ      = ZigTokens::TOK_LTEQ
      TOK_GT        = ZigTokens::TOK_GT
      TOK_GTEQ      = ZigTokens::TOK_GTEQ
      TOK_PLUS      = ZigTokens::TOK_PLUS
      TOK_MINUS     = ZigTokens::TOK_MINUS
      TOK_STAR      = ZigTokens::TOK_STAR
      TOK_SLASH     = ZigTokens::TOK_SLASH
      TOK_PERCENT   = ZigTokens::TOK_PERCENT
      TOK_BANG      = ZigTokens::TOK_BANG
      TOK_TILDE     = ZigTokens::TOK_TILDE
      TOK_AMP       = ZigTokens::TOK_AMP
      TOK_PIPE      = ZigTokens::TOK_PIPE
      TOK_CARET     = ZigTokens::TOK_CARET
      TOK_AMPAMP    = ZigTokens::TOK_AMPAMP
      TOK_PIPEPIPE  = ZigTokens::TOK_PIPEPIPE
      TOK_LSHIFT    = ZigTokens::TOK_LSHIFT
      TOK_RSHIFT    = ZigTokens::TOK_RSHIFT
      TOK_PLUSEQ    = ZigTokens::TOK_PLUSEQ
      TOK_MINUSEQ   = ZigTokens::TOK_MINUSEQ
      TOK_STAREQ    = ZigTokens::TOK_STAREQ
      TOK_SLASHEQ   = ZigTokens::TOK_SLASHEQ
      TOK_PERCENTEQ = ZigTokens::TOK_PERCENTEQ
      TOK_PUB       = ZigTokens::TOK_PUB
      TOK_CONST     = ZigTokens::TOK_CONST
      TOK_VAR       = ZigTokens::TOK_VAR
      TOK_FN        = ZigTokens::TOK_FN
      TOK_STRUCT    = ZigTokens::TOK_STRUCT
      TOK_IF        = ZigTokens::TOK_IF
      TOK_ELSE      = ZigTokens::TOK_ELSE
      TOK_FOR       = ZigTokens::TOK_FOR
      TOK_WHILE     = ZigTokens::TOK_WHILE
      TOK_RETURN    = ZigTokens::TOK_RETURN
      TOK_TRUE      = ZigTokens::TOK_TRUE
      TOK_FALSE     = ZigTokens::TOK_FALSE
      TOK_VOID      = ZigTokens::TOK_VOID

      def initialize(file_name)
        @file_name = file_name
        @tokens = []
        @pos = 0
        @errors = []
        @contract_name = "UnnamedContract"
        @parent_class = "SmartContract"
        @properties = []
        @methods = []
        @constructor_node = nil
        @self_names = Set.new
        @stateful_context_names = Set.new
      end

      attr_accessor :tokens, :pos, :errors

      # -- Error helpers ----------------------------------------------------

      def add_error(msg)
        @errors << Diagnostic.new(message: msg, severity: Severity::ERROR)
      end

      # -- Token helpers ----------------------------------------------------

      def peek
        return @tokens[@pos] if @pos < @tokens.length

        ZigToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
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

      def expect_ident(value)
        tok = advance
        if tok.kind != TOK_IDENT || tok.value != value
          add_error("line #{tok.line}: expected '#{value}', got #{tok.value.inspect}")
        end
        tok
      end

      def check(kind)
        peek.kind == kind
      end

      def check_ident(value)
        tok = peek
        tok.kind == TOK_IDENT && tok.value == value
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

      def peek_at(offset)
        idx = @pos + offset
        return @tokens[idx] if idx < @tokens.length

        ZigToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
      end

      # -- Top-level parsing ------------------------------------------------

      def parse_contract
        skip_runar_import

        while !check(TOK_EOF)
          if check(TOK_PUB) &&
             peek_at(1).kind == TOK_CONST &&
             peek_at(3).kind == TOK_ASSIGN
            contract = try_parse_contract_decl
            return contract if contract
          end
          advance
        end

        add_error("Expected Zig contract declaration `pub const Name = struct { ... };`")

        ContractNode.new(
          name: @contract_name,
          parent_class: @parent_class,
          properties: @properties,
          constructor: create_fallback_constructor,
          methods: @methods,
          source_file: @file_name
        )
      end

      # -- Import handling --------------------------------------------------

      def skip_runar_import
        start = @pos
        if check(TOK_CONST)
          advance
          if check_ident("runar")
            advance
            if match_tok(TOK_ASSIGN)
              if match_tok(TOK_AT) &&
                 check_ident("import")
                advance
                expect(TOK_LPAREN)
                advance if check(TOK_STRING)
                expect(TOK_RPAREN)
                match_tok(TOK_SEMICOLON)
                return
              end
            end
          end
        end
        @pos = start
        add_error("Expected `const runar = @import(\"runar\");` at the top of the file")
      end

      # -- Contract declaration ---------------------------------------------

      def try_parse_contract_decl
        start = @pos

        expect(TOK_PUB)
        expect(TOK_CONST)
        name_tok = expect(TOK_IDENT)
        unless check(TOK_ASSIGN)
          @pos = start
          return nil
        end
        expect(TOK_ASSIGN)
        unless check(TOK_STRUCT)
          @pos = start
          return nil
        end

        @contract_name = name_tok.value
        @parent_class = "SmartContract"
        @properties = []
        @methods = []
        @constructor_node = nil

        expect(TOK_STRUCT)
        expect(TOK_LBRACE)

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          # pub const Contract = runar.SmartContract;
          if check(TOK_PUB) &&
             peek_at(1).kind == TOK_CONST &&
             peek_at(2).kind == TOK_IDENT &&
             peek_at(2).value == "Contract"
            parse_contract_marker
            next
          end

          # pub fn ...
          if check(TOK_PUB) && peek_at(1).kind == TOK_FN
            method = parse_method(true)
            @methods << method if method
            next
          end

          # fn ...
          if check(TOK_FN)
            method = parse_method(false)
            @methods << method if method
            next
          end

          # field: Type [= init],
          if check(TOK_IDENT)
            @properties << parse_field
            next
          end

          advance
        end

        expect(TOK_RBRACE)
        match_tok(TOK_SEMICOLON)

        # Collect set of property names mutated in any method body so we can
        # determine readonly flags in stateful contracts (matches TS rule).
        mutated = Set.new
        @methods.each do |m|
          _collect_mutated_properties(m.body, mutated)
        end

        # Constructor param names (used to strip initializer overrides so the
        # AST matches the Zig compiler reference which omits `initialValue`
        # when the field is also an explicit constructor parameter).
        ctor_param_names = Set.new
        if @constructor_node
          @constructor_node.params.each { |p| ctor_param_names.add(p.name) }
        end

        # For SmartContract, all properties are readonly.
        # For StatefulSmartContract: readonly iff explicitly marked OR has
        # no initializer AND is not mutated in any method body.
        @properties = @properties.map do |prop|
          had_initializer = !prop.initializer.nil?
          stripped_initializer = ctor_param_names.include?(prop.name) ? nil : prop.initializer
          readonly = if @parent_class == "SmartContract"
                       true
                     elsif prop.readonly
                       true
                     elsif !had_initializer && !mutated.include?(prop.name)
                       true
                     else
                       false
                     end
          PropertyNode.new(
            name: prop.name,
            type: prop.type,
            readonly: readonly,
            initializer: stripped_initializer,
            source_location: prop.source_location
          )
        end

        method_names = Set.new(@methods.map(&:name))
        @methods = @methods.map { |m| rewrite_bare_method_calls(m, method_names) }
        if @constructor_node
          @constructor_node = rewrite_bare_method_calls(@constructor_node, method_names)
        end

        contract = ContractNode.new(
          name: @contract_name,
          parent_class: @parent_class,
          properties: @properties,
          constructor: @constructor_node || create_fallback_constructor,
          methods: @methods,
          source_file: @file_name
        )

        contract
      end

      # -- Contract marker: pub const Contract = runar.SmartContract; -------

      def parse_contract_marker
        expect(TOK_PUB)
        expect(TOK_CONST)
        expect(TOK_IDENT)
        expect(TOK_ASSIGN)

        if check_ident("runar")
          advance
          expect(TOK_DOT)
          parent_tok = expect(TOK_IDENT)
          @parent_class = parent_tok.value == "StatefulSmartContract" ? "StatefulSmartContract" : "SmartContract"
        end

        match_tok(TOK_SEMICOLON)
      end

      # -- Field parsing ----------------------------------------------------

      def parse_field
        source_location = loc
        name_tok = expect(TOK_IDENT)
        name = name_tok.value
        expect(TOK_COLON)
        parsed_type = parse_type
        initializer = nil

        if check(TOK_ASSIGN)
          advance
          initializer = parse_expression
        end

        match_tok(TOK_COMMA)

        PropertyNode.new(
          name: name,
          type: parsed_type[:type],
          readonly: parsed_type[:readonly] || false,
          initializer: initializer,
          source_location: source_location
        )
      end

      # -- Method parsing ---------------------------------------------------

      def parse_method(is_public)
        source_location = loc
        expect(TOK_PUB) if is_public
        expect(TOK_FN)
        name_tok = expect(TOK_IDENT)
        name = name_tok.value
        param_result = parse_param_list

        # Skip return type if present (not a `{`)
        unless check(TOK_LBRACE)
          parse_type
        end

        prev_self_names = @self_names
        prev_stateful_context_names = @stateful_context_names
        @self_names = param_result[:receiver_name] ? Set.new([param_result[:receiver_name]]) : Set.new
        @stateful_context_names = Set.new(param_result[:stateful_context_names])

        if name == "init"
          @constructor_node = parse_constructor(source_location, param_result[:params])
          @self_names = prev_self_names
          @stateful_context_names = prev_stateful_context_names
          return nil
        end

        body = parse_block_statements
        @self_names = prev_self_names
        @stateful_context_names = prev_stateful_context_names

        MethodNode.new(
          name: name,
          params: param_result[:params],
          body: body,
          visibility: is_public ? "public" : "private",
          source_location: source_location
        )
      end

      def parse_constructor(source_location, params)
        body = parse_constructor_body(params)
        MethodNode.new(
          name: "constructor",
          params: params,
          body: body,
          visibility: "public",
          source_location: source_location
        )
      end

      # -- Parameter list ---------------------------------------------------

      def parse_param_list
        expect(TOK_LPAREN)
        params = []
        receiver_name = nil
        stateful_context_names = Set.new
        index = 0

        while !check(TOK_RPAREN) && !check(TOK_EOF)
          param_name_tok = expect(TOK_IDENT)
          param_name = param_name_tok.value
          expect(TOK_COLON)
          parsed_type = parse_param_type
          is_receiver = index == 0 && parsed_type[:raw_name] == @contract_name

          if is_receiver
            receiver_name = param_name
          else
            if parsed_type[:raw_name] == "StatefulContext"
              stateful_context_names.add(param_name)
            end
            params << ParamNode.new(name: param_name, type: parsed_type[:type])
          end

          index += 1
          match_tok(TOK_COMMA)
        end

        expect(TOK_RPAREN)
        { params: params, receiver_name: receiver_name, stateful_context_names: stateful_context_names }
      end

      def parse_param_type
        # Skip pointer/reference markers: *, &
        while check(TOK_STAR) || check(TOK_AMP)
          advance
        end
        # Skip const keyword
        advance if check(TOK_CONST)
        parse_type
      end

      # -- Type parsing -----------------------------------------------------

      def parse_type
        # Array type: [N]T
        if check(TOK_LBRACKET)
          advance
          size_tok = expect(TOK_NUMBER)
          size = begin
            Integer(size_tok.value, 0)
          rescue ArgumentError
            0
          end
          expect(TOK_RBRACKET)
          element = parse_type
          return { type: FixedArrayType.new(element: element[:type], length: size), raw_name: element[:raw_name] }
        end

        # runar.TypeName
        if check_ident("runar") && peek_at(1).kind == TOK_DOT
          advance
          expect(TOK_DOT)
          name_tok = expect(TOK_IDENT)
          name = name_tok.value

          # runar.Readonly(T)
          if name == "Readonly" && check(TOK_LPAREN)
            expect(TOK_LPAREN)
            inner = parse_type
            expect(TOK_RPAREN)
            return { type: inner[:type], raw_name: inner[:raw_name], readonly: true }
          end

          mapped = Frontend.map_zig_type(name)
          return { type: Frontend.zig_make_type_node(mapped), raw_name: name }
        end

        # void keyword
        if check(TOK_VOID)
          advance
          return { type: PrimitiveType.new(name: "void"), raw_name: "void" }
        end

        # Plain identifier type
        if check(TOK_IDENT)
          name = advance.value
          mapped = Frontend.map_zig_type(name)
          return { type: Frontend.zig_make_type_node(mapped), raw_name: name }
        end

        fallback = advance
        { type: CustomType.new(name: "unknown"), raw_name: fallback.value || "unknown" }
      end

      # -- Block parsing ----------------------------------------------------

      def parse_block_statements
        expect(TOK_LBRACE)
        body = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          stmt = parse_statement
          if stmt
            # Merge `var i = 0; while (i < N) : (i += 1) { ... }` into ForStatement
            last_stmt = body.last
            if stmt.is_a?(ForStmt) &&
               stmt.init.is_a?(VariableDeclStmt) &&
               stmt.init.name == "__while_no_init" &&
               last_stmt.is_a?(VariableDeclStmt) &&
               loop_update_target_name(stmt) == last_stmt.name
              body.pop
              stmt = ForStmt.new(
                init: last_stmt,
                condition: stmt.condition,
                update: stmt.update,
                body: stmt.body,
                source_location: stmt.source_location
              )
            end
            body << stmt
          end
        end
        expect(TOK_RBRACE)
        body
      end

      def loop_update_target_name(stmt)
        return nil unless stmt.is_a?(ForStmt)

        update = stmt.update
        if update.is_a?(AssignmentStmt) && update.target.is_a?(Identifier)
          return update.target.name
        end
        if update.is_a?(ExpressionStmt) && update.expr.is_a?(Identifier)
          return update.expr.name
        end
        nil
      end

      # -- Constructor body -------------------------------------------------

      def parse_constructor_body(params)
        expect(TOK_LBRACE)
        body = [create_super_call(params)]
        found_return_struct = false

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          # return .{ .field = expr, ... };
          if check(TOK_RETURN) &&
             peek_at(1).kind == TOK_DOT &&
             peek_at(2).kind == TOK_LBRACE
            advance # consume 'return'
            body.concat(parse_struct_return_assignments)
            found_return_struct = true
            match_tok(TOK_SEMICOLON)
            next
          end

          stmt = parse_statement
          body << stmt if stmt
        end

        expect(TOK_RBRACE)

        unless found_return_struct
          @properties.each do |prop|
            if params.any? { |p| p.name == prop.name }
              body << create_property_assignment(prop.name, Identifier.new(name: prop.name))
            end
          end
        end

        body
      end

      def parse_struct_return_assignments
        assignments = []
        expect(TOK_DOT)
        expect(TOK_LBRACE)

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          match_tok(TOK_DOT)
          field_tok = expect(TOK_IDENT)
          expect(TOK_ASSIGN)
          value = parse_expression
          assignments << create_property_assignment(field_tok.value, value)
          match_tok(TOK_COMMA)
        end

        expect(TOK_RBRACE)
        assignments
      end

      # -- Statement parsing ------------------------------------------------

      def parse_statement
        source_location = loc

        # return
        if check(TOK_RETURN)
          advance
          value = nil
          unless check(TOK_SEMICOLON)
            value = parse_expression
          end
          match_tok(TOK_SEMICOLON)
          return ReturnStmt.new(value: value, source_location: source_location)
        end

        # if
        if check(TOK_IF)
          return parse_if_statement
        end

        # const / var
        if check(TOK_CONST) || check(TOK_VAR)
          return parse_variable_decl
        end

        # _ = expr; (discard)
        if check(TOK_IDENT) &&
           peek.value == "_" &&
           peek_at(1).kind == TOK_ASSIGN
          advance
          advance
          parse_expression
          match_tok(TOK_SEMICOLON)
          return nil
        end

        # while
        if check(TOK_WHILE)
          return parse_while_statement
        end

        # for (unsupported)
        if check(TOK_FOR)
          add_error("Unsupported Zig 'for' syntax -- use 'while' loops instead")
          skip_unsupported_block
          return nil
        end

        # Expression or assignment
        target = parse_expression

        # Simple assignment
        if check(TOK_ASSIGN)
          advance
          value = parse_expression
          match_tok(TOK_SEMICOLON)
          return AssignmentStmt.new(target: target, value: value, source_location: source_location)
        end

        # Compound assignment
        compound_op = parse_compound_assignment_op
        if compound_op
          rhs = parse_expression
          match_tok(TOK_SEMICOLON)
          return AssignmentStmt.new(
            target: target,
            value: BinaryExpr.new(op: compound_op, left: target, right: rhs),
            source_location: source_location
          )
        end

        match_tok(TOK_SEMICOLON)
        ExpressionStmt.new(expr: target, source_location: source_location)
      end

      def parse_variable_decl
        source_location = loc
        is_mutable = check(TOK_VAR)
        advance # consume const or var
        name_tok = expect(TOK_IDENT)
        type_node = nil

        if check(TOK_COLON)
          advance
          type_node = parse_type[:type]
        end

        expect(TOK_ASSIGN)
        init = parse_expression
        match_tok(TOK_SEMICOLON)

        VariableDeclStmt.new(
          name: name_tok.value,
          type: type_node,
          mutable: is_mutable,
          init: init,
          source_location: source_location
        )
      end

      def parse_if_statement
        source_location = loc
        expect(TOK_IF)
        advance if check(TOK_LPAREN)
        condition = parse_expression
        advance if check(TOK_RPAREN)
        then_branch = parse_block_statements

        else_branch = []
        if check(TOK_ELSE)
          advance
          if check(TOK_IF)
            else_branch = [parse_if_statement]
          else
            else_branch = parse_block_statements
          end
        end

        IfStmt.new(
          condition: condition,
          then: then_branch,
          else_: else_branch,
          source_location: source_location
        )
      end

      def parse_while_statement
        source_location = loc
        expect(TOK_WHILE)

        # Condition: while (condition)
        advance if check(TOK_LPAREN)
        condition = parse_expression
        advance if check(TOK_RPAREN)

        # Continue expression: : (i += 1)
        if check(TOK_COLON)
          advance
          advance if check(TOK_LPAREN)
          update_target = parse_expression
          compound_op = parse_compound_assignment_op
          if compound_op
            rhs = parse_expression
            update = AssignmentStmt.new(
              target: update_target,
              value: BinaryExpr.new(op: compound_op, left: update_target, right: rhs),
              source_location: source_location
            )
          else
            update = ExpressionStmt.new(expr: update_target, source_location: source_location)
          end
          advance if check(TOK_RPAREN)
        else
          update = ExpressionStmt.new(
            expr: BigIntLiteral.new(value: 0),
            source_location: source_location
          )
        end

        body = parse_block_statements

        ForStmt.new(
          init: VariableDeclStmt.new(
            name: "__while_no_init",
            mutable: true,
            init: BigIntLiteral.new(value: 0),
            source_location: source_location
          ),
          condition: condition,
          update: update,
          body: body,
          source_location: source_location
        )
      end

      def parse_compound_assignment_op
        if match_tok(TOK_PLUSEQ) then return "+" end
        if match_tok(TOK_MINUSEQ) then return "-" end
        if match_tok(TOK_STAREQ) then return "*" end
        if match_tok(TOK_SLASHEQ) then return "/" end
        if match_tok(TOK_PERCENTEQ) then return "%" end
        nil
      end

      def skip_unsupported_block
        while !check(TOK_LBRACE) && !check(TOK_SEMICOLON) && !check(TOK_EOF)
          advance
        end

        if check(TOK_SEMICOLON)
          advance
          return
        end

        return unless check(TOK_LBRACE)

        depth = 0
        while !check(TOK_EOF)
          if check(TOK_LBRACE)
            depth += 1
            advance
          elsif check(TOK_RBRACE)
            depth -= 1
            advance
            break if depth <= 0
          else
            advance
          end
        end
      end

      # -- Expression parsing -----------------------------------------------
      # Operator precedence (lowest to highest):
      #   logical or (||)
      #   logical and (&&)
      #   bitwise or (|)
      #   bitwise xor (^)
      #   bitwise and (&)
      #   equality (== !=)
      #   comparison (< <= > >=)
      #   shift (<< >>)
      #   additive (+ -)
      #   multiplicative (* / %)
      #   unary (! - ~)
      #   postfix (. [] ())
      #   primary

      def parse_expression
        parse_or
      end

      def parse_or
        left = parse_and
        while match_tok(TOK_PIPEPIPE)
          right = parse_and
          left = BinaryExpr.new(op: "||", left: left, right: right)
        end
        left
      end

      def parse_and
        left = parse_bitwise_or
        while match_tok(TOK_AMPAMP)
          right = parse_bitwise_or
          left = BinaryExpr.new(op: "&&", left: left, right: right)
        end
        left
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
          elsif match_tok(TOK_NOTEQ)
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
        if match_tok(TOK_BANG)
          operand = parse_unary
          return UnaryExpr.new(op: "!", operand: operand)
        end
        if match_tok(TOK_MINUS)
          operand = parse_unary
          return UnaryExpr.new(op: "-", operand: operand)
        end
        if match_tok(TOK_TILDE)
          operand = parse_unary
          return UnaryExpr.new(op: "~", operand: operand)
        end

        expr = parse_primary
        parse_postfix_chain(expr)
      end

      # -- Primary expressions ----------------------------------------------

      def parse_primary
        tok = peek

        # Struct literal: .{ ... }
        if tok.kind == TOK_DOT && peek_at(1).kind == TOK_LBRACE
          advance # consume .
          advance # consume {
          elements = []
          while !check(TOK_RBRACE) && !check(TOK_EOF)
            elements << parse_expression
            match_tok(TOK_COMMA)
          end
          expect(TOK_RBRACE)
          return ArrayLiteralExpr.new(elements: elements)
        end

        # Number literal
        if tok.kind == TOK_NUMBER
          advance
          val = begin
            Integer(tok.value, 0)
          rescue ArgumentError
            0
          end
          return BigIntLiteral.new(value: val)
        end

        # String literal
        if tok.kind == TOK_STRING
          advance
          return ByteStringLiteral.new(value: tok.value)
        end

        # Boolean literals
        if tok.kind == TOK_TRUE
          advance
          return BoolLiteral.new(value: true)
        end
        if tok.kind == TOK_FALSE
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

        # Array literal: [ ... ]
        if tok.kind == TOK_LBRACKET
          advance
          elements = []
          while !check(TOK_RBRACKET) && !check(TOK_EOF)
            elements << parse_expression
            match_tok(TOK_COMMA)
          end
          expect(TOK_RBRACKET)
          return ArrayLiteralExpr.new(elements: elements)
        end

        # Zig @builtins
        if tok.kind == TOK_AT
          advance
          builtin_tok = expect(TOK_IDENT)
          builtin_name = builtin_tok.value

          # @divTrunc(a, b) -> a / b
          # @mod(a, b) -> a % b
          # @shlExact(a, b) -> a << b
          # @shrExact(a, b) -> a >> b
          if %w[divTrunc mod shlExact shrExact].include?(builtin_name)
            expect(TOK_LPAREN)
            left = parse_expression
            expect(TOK_COMMA)
            right = parse_expression
            expect(TOK_RPAREN)
            op = case builtin_name
                 when "divTrunc" then "/"
                 when "mod" then "%"
                 when "shlExact" then "<<"
                 when "shrExact" then ">>"
                 end
            return BinaryExpr.new(op: op, left: left, right: right)
          end

          # @intCast, @truncate -- return inner expression
          if builtin_name == "intCast" || builtin_name == "truncate"
            expect(TOK_LPAREN)
            inner = parse_expression
            expect(TOK_RPAREN)
            return inner
          end

          # @as(type, expr) -- skip type, return expr
          if builtin_name == "as"
            expect(TOK_LPAREN)
            parse_type # skip type
            expect(TOK_COMMA)
            inner = parse_expression
            expect(TOK_RPAREN)
            return inner
          end

          # @import -- skip (already handled at top-level)
          if builtin_name == "import"
            expect(TOK_LPAREN)
            parse_expression
            expect(TOK_RPAREN)
            return Identifier.new(name: "__import")
          end

          # @embedFile -- treat as string literal placeholder
          if builtin_name == "embedFile"
            expect(TOK_LPAREN)
            arg = parse_expression
            expect(TOK_RPAREN)
            return arg
          end

          # Unknown @builtin with args
          if check(TOK_LPAREN)
            advance
            args = []
            args << parse_expression
            while match_tok(TOK_COMMA)
              args << parse_expression
            end
            expect(TOK_RPAREN)
            add_error("Unsupported Zig builtin '@#{builtin_name}'")
            return CallExpr.new(callee: Identifier.new(name: builtin_name), args: args)
          end

          add_error("Unsupported Zig builtin '@#{builtin_name}'")
          return Identifier.new(name: builtin_name)
        end

        # Identifier
        if tok.kind == TOK_IDENT
          advance

          # runar.foo -- strip the runar. prefix
          if tok.value == "runar" && check(TOK_DOT)
            advance # consume .
            builtin_tok = expect(TOK_IDENT)
            builtin_name = builtin_tok.value

            # runar.bytesEq(a, b) -> a === b
            if builtin_name == "bytesEq" && check(TOK_LPAREN)
              advance
              left = parse_expression
              expect(TOK_COMMA)
              right = parse_expression
              expect(TOK_RPAREN)
              return BinaryExpr.new(op: "===", left: left, right: right)
            end

            return Identifier.new(name: builtin_name)
          end

          return Identifier.new(name: tok.value)
        end

        advance
        Identifier.new(name: tok.value || "unknown")
      end

      # -- Postfix chain (. [] ()) ------------------------------------------

      def parse_postfix_chain(expr)
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

          elsif check(TOK_DOT)
            advance
            prop = peek.value
            advance
            if expr.is_a?(Identifier) && @self_names.include?(expr.name)
              expr = PropertyAccessExpr.new(property: prop)
            elsif expr.is_a?(Identifier) &&
                  @stateful_context_names.include?(expr.name) &&
                  %w[txPreimage getStateScript addOutput addRawOutput addDataOutput].include?(prop)
              expr = PropertyAccessExpr.new(property: prop)
            else
              expr = MemberExpr.new(object: expr, property: prop)
            end

          elsif check(TOK_LBRACKET)
            advance
            index = parse_expression
            expect(TOK_RBRACKET)
            expr = IndexAccessExpr.new(object: expr, index: index)

          else
            break
          end
        end
        expr
      end

      # -- Helper methods ---------------------------------------------------

      def create_super_call(params)
        ExpressionStmt.new(
          expr: CallExpr.new(
            callee: Identifier.new(name: "super"),
            args: params.map { |p| Identifier.new(name: p.name) }
          ),
          source_location: SourceLocation.new(file: @file_name, line: 1, column: 1)
        )
      end

      def create_property_assignment(name, value)
        AssignmentStmt.new(
          target: PropertyAccessExpr.new(property: name),
          value: value,
          source_location: SourceLocation.new(file: @file_name, line: 1, column: 1)
        )
      end

      def create_fallback_constructor
        params = @properties
          .select { |p| p.initializer.nil? }
          .map { |p| ParamNode.new(name: p.name, type: p.type) }

        MethodNode.new(
          name: "constructor",
          params: params,
          body: [
            create_super_call(params),
            *params.map { |p| create_property_assignment(p.name, Identifier.new(name: p.name)) }
          ],
          visibility: "public",
          source_location: SourceLocation.new(file: @file_name, line: 1, column: 1)
        )
      end

      # -- Bare method call rewriting ---------------------------------------
      # In Zig, methods can be called without `self.` prefix. This rewrites
      # bare calls to contract methods into `this.method(...)` form.

      def rewrite_bare_method_calls(method, method_names)
        scope = Set.new(method.params.map(&:name))
        MethodNode.new(
          name: method.name,
          params: method.params,
          body: rewrite_statements(method.body, method_names, scope),
          visibility: method.visibility,
          source_location: method.source_location
        )
      end

      def rewrite_statements(stmts, method_names, scope)
        current_scope = Set.new(scope)
        stmts.map do |stmt|
          result = rewrite_statement(stmt, method_names, current_scope)
          current_scope.add(result.name) if result.is_a?(VariableDeclStmt)
          result
        end
      end

      def rewrite_statement(stmt, method_names, scope)
        case stmt
        when VariableDeclStmt
          VariableDeclStmt.new(
            name: stmt.name,
            type: stmt.type,
            mutable: stmt.mutable,
            init: rewrite_expression(stmt.init, method_names, scope),
            source_location: stmt.source_location
          )
        when AssignmentStmt
          AssignmentStmt.new(
            target: rewrite_expression(stmt.target, method_names, scope),
            value: rewrite_expression(stmt.value, method_names, scope),
            source_location: stmt.source_location
          )
        when IfStmt
          IfStmt.new(
            condition: rewrite_expression(stmt.condition, method_names, scope),
            then: rewrite_statements(stmt.then, method_names, Set.new(scope)),
            else_: stmt.else_ ? rewrite_statements(stmt.else_, method_names, Set.new(scope)) : [],
            source_location: stmt.source_location
          )
        when ForStmt
          loop_scope = Set.new(scope)
          init = rewrite_statement(stmt.init, method_names, loop_scope)
          loop_scope.add(init.name) if init.is_a?(VariableDeclStmt)
          ForStmt.new(
            init: init,
            condition: rewrite_expression(stmt.condition, method_names, loop_scope),
            update: rewrite_statement(stmt.update, method_names, loop_scope),
            body: rewrite_statements(stmt.body, method_names, loop_scope),
            source_location: stmt.source_location
          )
        when ReturnStmt
          ReturnStmt.new(
            value: stmt.value ? rewrite_expression(stmt.value, method_names, scope) : nil,
            source_location: stmt.source_location
          )
        when ExpressionStmt
          ExpressionStmt.new(
            expr: rewrite_expression(stmt.expr, method_names, scope),
            source_location: stmt.source_location
          )
        else
          stmt
        end
      end

      def rewrite_expression(expr, method_names, scope)
        case expr
        when CallExpr
          callee = if expr.callee.is_a?(Identifier) &&
                      method_names.include?(expr.callee.name) &&
                      !scope.include?(expr.callee.name)
                    PropertyAccessExpr.new(property: expr.callee.name)
                  else
                    rewrite_expression(expr.callee, method_names, scope)
                  end
          CallExpr.new(
            callee: callee,
            args: expr.args.map { |a| rewrite_expression(a, method_names, scope) }
          )
        when BinaryExpr
          BinaryExpr.new(
            op: expr.op,
            left: rewrite_expression(expr.left, method_names, scope),
            right: rewrite_expression(expr.right, method_names, scope)
          )
        when UnaryExpr
          UnaryExpr.new(
            op: expr.op,
            operand: rewrite_expression(expr.operand, method_names, scope)
          )
        when TernaryExpr
          TernaryExpr.new(
            condition: rewrite_expression(expr.condition, method_names, scope),
            consequent: rewrite_expression(expr.consequent, method_names, scope),
            alternate: rewrite_expression(expr.alternate, method_names, scope)
          )
        when MemberExpr
          MemberExpr.new(
            object: rewrite_expression(expr.object, method_names, scope),
            property: expr.property
          )
        when IndexAccessExpr
          IndexAccessExpr.new(
            object: rewrite_expression(expr.object, method_names, scope),
            index: rewrite_expression(expr.index, method_names, scope)
          )
        when IncrementExpr
          IncrementExpr.new(
            operand: rewrite_expression(expr.operand, method_names, scope),
            prefix: expr.prefix
          )
        when DecrementExpr
          DecrementExpr.new(
            operand: rewrite_expression(expr.operand, method_names, scope),
            prefix: expr.prefix
          )
        when ArrayLiteralExpr
          ArrayLiteralExpr.new(
            elements: expr.elements.map { |e| rewrite_expression(e, method_names, scope) }
          )
        else
          expr
        end
      end

      # -- Mutation detection ---------------------------------------------
      # Walks method bodies to find `self.<prop> = …` writes so we can
      # correctly mark stateful contract fields as mutable.

      def _collect_mutated_properties(body, out)
        (body || []).each { |stmt| _collect_mutated_in_stmt(stmt, out) }
      end

      def _collect_mutated_in_stmt(stmt, out)
        case stmt
        when AssignmentStmt
          if stmt.target.is_a?(PropertyAccessExpr)
            out.add(stmt.target.property)
          end
          _collect_mutated_in_expr(stmt.target, out)
          _collect_mutated_in_expr(stmt.value, out)
        when VariableDeclStmt
          _collect_mutated_in_expr(stmt.init, out)
        when ExpressionStmt
          _collect_mutated_in_expr(stmt.expr, out)
        when ReturnStmt
          _collect_mutated_in_expr(stmt.value, out)
        when IfStmt
          _collect_mutated_in_expr(stmt.condition, out)
          _collect_mutated_properties(stmt.then, out)
          _collect_mutated_properties(stmt.else_, out)
        when ForStmt
          _collect_mutated_in_expr(stmt.init&.init, out)
          _collect_mutated_in_expr(stmt.condition, out)
          _collect_mutated_in_stmt(stmt.update, out)
          _collect_mutated_properties(stmt.body, out)
        end
      end

      def _collect_mutated_in_expr(expr, out)
        return if expr.nil?
        case expr
        when BinaryExpr
          _collect_mutated_in_expr(expr.left, out)
          _collect_mutated_in_expr(expr.right, out)
        when UnaryExpr
          _collect_mutated_in_expr(expr.operand, out)
        when CallExpr
          _collect_mutated_in_expr(expr.callee, out)
          expr.args.each { |a| _collect_mutated_in_expr(a, out) }
        when MemberExpr
          _collect_mutated_in_expr(expr.object, out)
        when TernaryExpr
          _collect_mutated_in_expr(expr.condition, out)
          _collect_mutated_in_expr(expr.consequent, out)
          _collect_mutated_in_expr(expr.alternate, out)
        when IndexAccessExpr
          _collect_mutated_in_expr(expr.object, out)
          _collect_mutated_in_expr(expr.index, out)
        when IncrementExpr, DecrementExpr
          if expr.operand.is_a?(PropertyAccessExpr)
            out.add(expr.operand.property)
          end
          _collect_mutated_in_expr(expr.operand, out)
        when ArrayLiteralExpr
          expr.elements.each { |e| _collect_mutated_in_expr(e, out) }
        end
      end
    end

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    # Parse a Zig-syntax Runar contract (.runar.zig).
    #
    # @param source [String] the source code
    # @param file_name [String] the file name (used in diagnostics)
    # @return [ParseResult]
    def self.parse_zig(source, file_name)
      p = ZigParser.new(file_name)
      p.tokens = tokenize_zig(source)
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
