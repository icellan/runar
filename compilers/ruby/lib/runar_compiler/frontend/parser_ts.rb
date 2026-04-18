# frozen_string_literal: true

# TypeScript format parser (.runar.ts) for the Runar compiler.
#
# Ported from compilers/python/runar_compiler/frontend/parser_ts.py.
# Hand-written tokenizer + recursive descent parser for TypeScript-like syntax.

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"

module RunarCompiler
  module Frontend
    # -----------------------------------------------------------------------
    # Token types (namespaced to avoid collision with other parsers)
    # -----------------------------------------------------------------------

    module TsTokens
      TOK_EOF          = 0
      TOK_IDENT        = 1
      TOK_NUMBER       = 2
      TOK_STRING       = 3
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
      TOK_ASSIGN       = 14
      TOK_EQEQ         = 15  # ==
      TOK_NOTEQ        = 16  # !=
      TOK_LT           = 17
      TOK_LTEQ         = 18
      TOK_GT           = 19
      TOK_GTEQ         = 20
      TOK_PLUS         = 21
      TOK_MINUS        = 22
      TOK_STAR         = 23
      TOK_SLASH        = 24
      TOK_PERCENT      = 25
      TOK_BANG         = 26
      TOK_TILDE        = 27
      TOK_AMP          = 28
      TOK_PIPE         = 29
      TOK_CARET        = 30
      TOK_AMPAMP       = 31  # &&
      TOK_PIPEPIPE     = 32  # ||
      TOK_PLUSEQ       = 33  # +=
      TOK_MINUSEQ      = 34  # -=
      TOK_STAREQ       = 35  # *=
      TOK_SLASHEQ      = 36  # /=
      TOK_PERCENTEQ    = 37  # %=
      TOK_QUESTION     = 38  # ?
      TOK_PLUSPLUS      = 39  # ++
      TOK_MINUSMINUS   = 40  # --
      TOK_EQEQEQ       = 41  # ===
      TOK_NOTEQEQ      = 42  # !==
      TOK_LSHIFT       = 43  # <<
      TOK_RSHIFT       = 44  # >>
      TOK_ARROW        = 45  # =>

      # A single token produced by the tokenizer.
      Token = Struct.new(:kind, :value, :line, :col, keyword_init: true)
    end

    # -----------------------------------------------------------------------
    # Type mappings
    # -----------------------------------------------------------------------

    TS_TYPE_MAP = {
      "bigint"          => "bigint",
      "boolean"         => "boolean",
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
      "P256Point"       => "P256Point",
      "P384Point"       => "P384Point",
      "void"            => "void",
    }.freeze

    # Map a TypeScript type name to a Runar TypeNode.
    def self.parse_ts_type_name(name)
      if TS_TYPE_MAP.key?(name)
        return PrimitiveType.new(name: TS_TYPE_MAP[name])
      end

      if primitive_type?(name)
        return PrimitiveType.new(name: name)
      end

      return PrimitiveType.new(name: "bigint") if name == "number"

      CustomType.new(name: name)
    end

    # -----------------------------------------------------------------------
    # Tokenizer helpers, operator tables, and tokenizer (namespaced)
    # -----------------------------------------------------------------------

    module TsTokens
      HEX_CHARS = "0123456789abcdefABCDEF"

      module_function

      def ident_start?(ch)
        (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch == "_" || ch == "$"
      end

      def ident_part?(ch)
        ident_start?(ch) || (ch >= "0" && ch <= "9")
      end

      def hex_digit?(ch)
        HEX_CHARS.include?(ch)
      end

      THREE_CHAR_OPS = {
        "===" => TOK_EQEQEQ,
        "!==" => TOK_NOTEQEQ,
      }.freeze

      TWO_CHAR_OPS = {
        "==" => TOK_EQEQ,
        "!=" => TOK_NOTEQ,
        "<=" => TOK_LTEQ,
        ">=" => TOK_GTEQ,
        "+=" => TOK_PLUSEQ,
        "-=" => TOK_MINUSEQ,
        "*=" => TOK_STAREQ,
        "/=" => TOK_SLASHEQ,
        "%=" => TOK_PERCENTEQ,
        "&&" => TOK_AMPAMP,
        "||" => TOK_PIPEPIPE,
        "++" => TOK_PLUSPLUS,
        "--" => TOK_MINUSMINUS,
        "<<" => TOK_LSHIFT,
        ">>" => TOK_RSHIFT,
        "=>" => TOK_ARROW,
      }.freeze

      ONE_CHAR_OPS = {
        "(" => TOK_LPAREN,
        ")" => TOK_RPAREN,
        "[" => TOK_LBRACKET,
        "]" => TOK_RBRACKET,
        "{" => TOK_LBRACE,
        "}" => TOK_RBRACE,
        "," => TOK_COMMA,
        "." => TOK_DOT,
        ":" => TOK_COLON,
        ";" => TOK_SEMICOLON,
        "=" => TOK_ASSIGN,
        "<" => TOK_LT,
        ">" => TOK_GT,
        "+" => TOK_PLUS,
        "-" => TOK_MINUS,
        "*" => TOK_STAR,
        "/" => TOK_SLASH,
        "%" => TOK_PERCENT,
        "!" => TOK_BANG,
        "~" => TOK_TILDE,
        "&" => TOK_AMP,
        "|" => TOK_PIPE,
        "^" => TOK_CARET,
        "?" => TOK_QUESTION,
      }.freeze

      # Tokenize a source string into an array of Token structs.
      #
      # @param source [String]
      # @return [Array<Token>]
      def self.tokenize(source)
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
            # Reached end without finding */
            i += 1 if i < n
          end
          next
        end

        start_col = col

        # Template string literals (backticks)
        if ch == "`"
          i += 1
          col += 1
          start = i
          while i < n && source[i] != "`"
            if source[i] == "\\"
              i += 1
              col += 1
            end
            if i < n
              if source[i] == "\n"
                line += 1
                col = 0
              else
                col += 1
              end
              i += 1
            end
          end
          val = source[start...i]
          if i < n
            i += 1
            col += 1
          end
          tokens << Token.new(kind: TOK_STRING, value: val, line: line, col: start_col)
          next
        end

        # String literals: single or double quotes
        if ch == "'" || ch == '"'
          quote = ch
          i += 1
          col += 1
          start = i
          while i < n && source[i] != quote
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
          tokens << Token.new(kind: TOK_STRING, value: val, line: line, col: start_col)
          next
        end

        # Numbers (including BigInt suffix 'n')
        if ch >= "0" && ch <= "9"
          start = i
          if ch == "0" && i + 1 < n && (source[i + 1] == "x" || source[i + 1] == "X")
            i += 2
            col += 2
            while i < n && hex_digit?(source[i])
              i += 1
              col += 1
            end
          elsif ch == "0" && i + 1 < n && (source[i + 1] == "o" || source[i + 1] == "O")
            i += 2
            col += 2
            while i < n && source[i] >= "0" && source[i] <= "7"
              i += 1
              col += 1
            end
          elsif ch == "0" && i + 1 < n && (source[i + 1] == "b" || source[i + 1] == "B")
            i += 2
            col += 2
            while i < n && (source[i] == "0" || source[i] == "1")
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
          # Strip trailing BigInt suffix 'n'
          if i < n && source[i] == "n"
            i += 1
            col += 1
          end
          tokens << Token.new(kind: TOK_NUMBER, value: num_str, line: line, col: start_col)
          next
        end

        # Identifiers and keywords
        if ident_start?(ch)
          start = i
          while i < n && ident_part?(source[i])
            i += 1
            col += 1
          end
          word = source[start...i]
          tokens << Token.new(kind: TOK_IDENT, value: word, line: line, col: start_col)
          next
        end

        # Three-character operators
        if i + 2 < n
          three = source[i, 3]
          three_kind = THREE_CHAR_OPS[three]
          unless three_kind.nil?
            tokens << Token.new(kind: three_kind, value: three, line: line, col: start_col)
            i += 3
            col += 3
            next
          end
        end

        # Two-character operators
        if i + 1 < n
          two = source[i, 2]
          two_kind = TWO_CHAR_OPS[two]
          unless two_kind.nil?
            tokens << Token.new(kind: two_kind, value: two, line: line, col: start_col)
            i += 2
            col += 2
            next
          end
        end

        # Single-character operators
        one_kind = ONE_CHAR_OPS[ch]
        unless one_kind.nil?
          tokens << Token.new(kind: one_kind, value: ch, line: line, col: start_col)
          i += 1
          col += 1
          next
        end

        # Skip unknown characters
        i += 1
        col += 1
      end

      tokens << Token.new(kind: TOK_EOF, value: "", line: line, col: col)
      tokens
    end
    end # module TsTokens

    # -----------------------------------------------------------------------
    # Parser
    # -----------------------------------------------------------------------

    class TsParser
      include TsTokens
      # Re-define token constants directly on the class so that Ruby's lexical
      # constant lookup finds them here instead of identically-named constants
      # that parser_ruby.rb defines at the Frontend module level.
      TsTokens.constants.each { |c| const_set(c, TsTokens.const_get(c)) unless c == :Token }
      Token = TsTokens::Token

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

        Token.new(kind: TOK_EOF, value: "", line: 0, col: 0)
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

      def match(kind)
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

      def skip_semicolons
        advance while check(TOK_SEMICOLON)
      end

      # -- Top-level parsing ------------------------------------------------

      def parse_contract
        # Skip import statements, export keywords, and other top-level noise
        # until we find a class declaration.
        until check(TOK_EOF)
          # Skip import statements
          if check_ident("import")
            skip_import
            next
          end

          # export class ...
          if check_ident("export")
            advance
            if check_ident("class")
              return parse_class
            end
            # export default class, etc.
            if check_ident("default")
              advance
              if check_ident("class")
                return parse_class
              end
            end
            # Other export statements -- skip to next semicolon or brace
            skip_statement
            next
          end

          # class ...
          if check_ident("class")
            return parse_class
          end

          # Skip anything else at top level
          skip_statement
        end

        raise "no class extending SmartContract or StatefulSmartContract found"
      end

      # -- Skip helpers -----------------------------------------------------

      def skip_import
        # import ... from '...' ;
        advance # consume 'import'
        until check(TOK_EOF)
          tok = peek
          if tok.kind == TOK_SEMICOLON
            advance
            return
          end
          # Detect end of import by seeing next top-level keyword
          if tok.kind == TOK_IDENT && %w[import export class].include?(tok.value)
            return
          end
          advance
        end
      end

      def skip_statement
        depth = 0
        until check(TOK_EOF)
          tok = peek
          if tok.kind == TOK_LBRACE
            depth += 1
            advance
          elsif tok.kind == TOK_RBRACE
            return if depth <= 0

            depth -= 1
            advance
            return if depth == 0
          elsif tok.kind == TOK_SEMICOLON && depth == 0
            advance
            return
          else
            advance
          end
        end
      end

      # -- Class parsing ----------------------------------------------------

      def parse_class
        expect_ident("class")

        name_tok = expect(TOK_IDENT)
        contract_name = name_tok.value

        # extends clause
        parent_class = "SmartContract"
        if match_ident("extends")
          parent_tok = expect(TOK_IDENT)
          parent_class = parent_tok.value
        end

        unless %w[SmartContract StatefulSmartContract].include?(parent_class)
          raise "no class extending SmartContract or StatefulSmartContract found"
        end

        expect(TOK_LBRACE)

        properties = []
        constructor = nil
        methods = []

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          skip_semicolons
          break if check(TOK_RBRACE) || check(TOK_EOF)

          member = parse_class_member(parent_class)
          next if member.nil?

          if member.is_a?(PropertyNode)
            properties << member
          elsif member.is_a?(MethodNode)
            if member.name == "constructor"
              if constructor
                add_error("duplicate constructor")
              end
              constructor = member
            else
              methods << member
            end
          end
        end

        expect(TOK_RBRACE)

        if constructor.nil?
          add_error("contract must have a constructor")
          constructor = MethodNode.new(
            name: "constructor",
            params: [],
            body: [],
            visibility: "public",
            source_location: SourceLocation.new(file: @file_name, line: 1, column: 0)
          )
        end

        ContractNode.new(
          name: contract_name,
          parent_class: parent_class,
          properties: properties,
          constructor: constructor,
          methods: methods,
          source_file: @file_name
        )
      end

      # -- Class members ----------------------------------------------------

      def parse_class_member(parent_class)
        location = loc

        # Collect modifiers: public, private, readonly
        visibility = "private"
        is_readonly = false

        loop do
          if check_ident("public")
            visibility = "public"
            advance
          elsif check_ident("private")
            visibility = "private"
            advance
          elsif check_ident("protected")
            visibility = "private"
            advance
          elsif check_ident("readonly")
            is_readonly = true
            advance
          else
            break
          end
        end

        # constructor(...) { ... }
        if check_ident("constructor")
          return parse_constructor_method(location)
        end

        # name followed by ( means method
        # name followed by : or ; means property
        if peek.kind != TOK_IDENT
          # Skip unknown token
          advance
          return nil
        end

        name_tok = advance
        member_name = name_tok.value

        # Method: name(...)
        if check(TOK_LPAREN)
          return parse_method(member_name, visibility, location)
        end

        # Property: name: Type (possibly with ; at end)
        if check(TOK_COLON)
          advance # consume :
          type_node = parse_type

          # Parse optional initializer: = value
          initializer = nil
          if check(TOK_ASSIGN)
            advance # consume '='
            initializer = parse_expression
          end

          skip_semicolons

          return PropertyNode.new(
            name: member_name,
            type: type_node,
            readonly: is_readonly,
            initializer: initializer,
            source_location: location
          )
        end

        # Property with no type annotation (just name;)
        if check(TOK_SEMICOLON)
          advance
          add_error("property '#{member_name}' must have an explicit type annotation")
          return PropertyNode.new(
            name: member_name,
            type: CustomType.new(name: "unknown"),
            readonly: is_readonly,
            source_location: location
          )
        end

        # Skip unknown
        skip_to_next_member
        nil
      end

      def skip_to_next_member
        depth = 0
        until check(TOK_EOF)
          tok = peek
          if tok.kind == TOK_LBRACE
            depth += 1
            advance
          elsif tok.kind == TOK_RBRACE
            return if depth <= 0

            depth -= 1
            advance
          elsif tok.kind == TOK_SEMICOLON && depth == 0
            advance
            return
          else
            advance
          end
        end
      end

      # -- Constructor ------------------------------------------------------

      def parse_constructor_method(location)
        expect_ident("constructor")
        params = parse_params

        # Skip optional return type annotation
        if check(TOK_COLON)
          advance
          parse_type
        end

        body = parse_block

        MethodNode.new(
          name: "constructor",
          params: params,
          body: body,
          visibility: "public",
          source_location: location
        )
      end

      # -- Methods ----------------------------------------------------------

      def parse_method(name, visibility, location)
        params = parse_params

        # Skip optional return type annotation
        if check(TOK_COLON)
          advance
          parse_type
        end

        body = parse_block

        MethodNode.new(
          name: name,
          params: params,
          body: body,
          visibility: visibility,
          source_location: location
        )
      end

      # -- Parameters -------------------------------------------------------

      def parse_params
        expect(TOK_LPAREN)
        params = []

        while !check(TOK_RPAREN) && !check(TOK_EOF)
          # Skip modifiers in constructor params (public, private, readonly)
          while peek.kind == TOK_IDENT && %w[public private protected readonly].include?(peek.value)
            advance
          end

          name_tok = expect(TOK_IDENT)
          param_name = name_tok.value

          # Optional ? for optional params
          match(TOK_QUESTION)

          typ = nil
          if match(TOK_COLON)
            typ = parse_type
          end

          if typ.nil?
            add_error("parameter '#{param_name}' must have an explicit type annotation")
            typ = CustomType.new(name: "unknown")
          end

          params << ParamNode.new(name: param_name, type: typ)

          break unless match(TOK_COMMA)
        end

        expect(TOK_RPAREN)
        params
      end

      # -- Type parsing -----------------------------------------------------

      def parse_type
        tok = peek

        if tok.kind != TOK_IDENT
          add_error("line #{tok.line}: expected type name, got #{tok.value.inspect}")
          advance
          return CustomType.new(name: "unknown")
        end

        name = tok.value
        advance

        # FixedArray<T, N>
        if name == "FixedArray"
          if match(TOK_LT)
            elem_type = parse_type
            expect(TOK_COMMA)
            size_tok = expect(TOK_NUMBER)
            size = begin
              Integer(size_tok.value, 0)
            rescue ArgumentError
              add_error("line #{size_tok.line}: FixedArray size must be a non-negative integer literal")
              0
            end
            expect(TOK_GT)
            return FixedArrayType.new(element: elem_type, length: size)
          end
          return CustomType.new(name: name)
        end

        # Generic types we don't support -- skip type args
        if check(TOK_LT)
          skip_type_args
        end

        # Array type: bigint[] etc.
        if check(TOK_LBRACKET) && peek_next_kind == TOK_RBRACKET
          advance # [
          advance # ]
          # Treat T[] as unknown, we only support FixedArray
          add_error("use FixedArray<T, N> instead of #{name}[]")
        end

        Frontend.parse_ts_type_name(name)
      end

      def skip_type_args
        return unless match(TOK_LT)

        depth = 1
        while depth > 0 && !check(TOK_EOF)
          if check(TOK_LT)
            depth += 1
          elsif check(TOK_GT)
            depth -= 1
          end
          advance
        end
      end

      def peek_next_kind
        return @tokens[@pos + 1].kind if @pos + 1 < @tokens.length

        TOK_EOF
      end

      # -- Block parsing ----------------------------------------------------

      def parse_block
        expect(TOK_LBRACE)
        stmts = []

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          skip_semicolons
          break if check(TOK_RBRACE) || check(TOK_EOF)

          stmt = parse_statement
          stmts << stmt unless stmt.nil?
        end

        expect(TOK_RBRACE)
        stmts
      end

      # -- Statement parsing ------------------------------------------------

      def parse_statement
        location = loc
        tok = peek

        # Variable declarations: const, let
        if tok.kind == TOK_IDENT && (tok.value == "const" || tok.value == "let")
          return parse_variable_decl(location)
        end

        # If statement
        if tok.kind == TOK_IDENT && tok.value == "if"
          return parse_if(location)
        end

        # For statement
        if tok.kind == TOK_IDENT && tok.value == "for"
          return parse_for(location)
        end

        # Return statement
        if tok.kind == TOK_IDENT && tok.value == "return"
          return parse_return(location)
        end

        # Expression statement (including assignments and calls)
        parse_expression_statement(location)
      end

      def parse_variable_decl(location)
        keyword = advance # const or let
        is_mutable = keyword.value == "let"

        name_tok = expect(TOK_IDENT)
        var_name = name_tok.value

        type_node = nil
        if match(TOK_COLON)
          type_node = parse_type
        end

        init = nil
        if match(TOK_ASSIGN)
          init = parse_expression
        end

        init = BigIntLiteral.new(value: 0) if init.nil?

        skip_semicolons

        VariableDeclStmt.new(
          name: var_name,
          type: type_node,
          mutable: is_mutable,
          init: init,
          source_location: location
        )
      end

      def parse_if(location)
        expect_ident("if")
        expect(TOK_LPAREN)
        condition = parse_expression
        expect(TOK_RPAREN)

        then_block = parse_block_or_statement

        else_block = []
        if match_ident("else")
          if check_ident("if")
            # else if ...
            elif_loc = loc
            elif_stmt = parse_if(elif_loc)
            else_block = [elif_stmt]
          else
            else_block = parse_block_or_statement
          end
        end

        IfStmt.new(
          condition: condition,
          then: then_block,
          else_: else_block,
          source_location: location
        )
      end

      def parse_block_or_statement
        if check(TOK_LBRACE)
          return parse_block
        end

        stmt = parse_statement
        return [stmt] unless stmt.nil?

        []
      end

      def parse_for(location)
        expect_ident("for")
        expect(TOK_LPAREN)

        # Initializer: let i: bigint = 0n  or  let i = 0n
        init_loc = loc
        if check_ident("let") || check_ident("const")
          init_stmt = parse_variable_decl(init_loc)
          unless init_stmt.is_a?(VariableDeclStmt)
            init_stmt = VariableDeclStmt.new(
              name: "_i",
              mutable: true,
              init: BigIntLiteral.new(value: 0),
              source_location: init_loc
            )
          end
        else
          # Expression initializer -- not standard for Runar for-loops
          init_stmt = VariableDeclStmt.new(
            name: "_i",
            mutable: true,
            init: BigIntLiteral.new(value: 0),
            source_location: init_loc
          )
          # Skip to the semicolon
          while !check(TOK_SEMICOLON) && !check(TOK_EOF)
            advance
          end
        end

        # The variable_decl already consumed the semicolon if it was there,
        # but we need to make sure we're past it.
        match(TOK_SEMICOLON)

        # Condition
        if check(TOK_SEMICOLON)
          condition = BoolLiteral.new(value: false)
        else
          condition = parse_expression
        end
        expect(TOK_SEMICOLON)

        # Update
        update_loc = loc
        if check(TOK_RPAREN)
          update = ExpressionStmt.new(
            expr: BigIntLiteral.new(value: 0),
            source_location: update_loc
          )
        else
          update_expr = parse_expression
          update = ExpressionStmt.new(expr: update_expr, source_location: update_loc)
        end

        expect(TOK_RPAREN)

        body = parse_block_or_statement

        ForStmt.new(
          init: init_stmt,
          condition: condition,
          update: update,
          body: body,
          source_location: location
        )
      end

      def parse_return(location)
        expect_ident("return")

        value = nil
        if !check(TOK_SEMICOLON) && !check(TOK_RBRACE) && !check(TOK_EOF)
          value = parse_expression
        end

        skip_semicolons
        ReturnStmt.new(value: value, source_location: location)
      end

      def parse_expression_statement(location)
        expr = parse_expression

        # Check for assignment: expr = value
        if match(TOK_ASSIGN)
          value = parse_expression
          skip_semicolons
          return AssignmentStmt.new(target: expr, value: value, source_location: location)
        end

        # Compound assignments: +=, -=, *=, /=, %=
        compound_ops = {
          TOK_PLUSEQ    => "+",
          TOK_MINUSEQ   => "-",
          TOK_STAREQ    => "*",
          TOK_SLASHEQ   => "/",
          TOK_PERCENTEQ => "%",
        }
        compound_ops.each do |kind, bin_op|
          if match(kind)
            right = parse_expression
            skip_semicolons
            value = BinaryExpr.new(op: bin_op, left: expr, right: right)
            return AssignmentStmt.new(target: expr, value: value, source_location: location)
          end
        end

        skip_semicolons
        ExpressionStmt.new(expr: expr, source_location: location)
      end

      # -- Expression parsing -----------------------------------------------
      # Operator precedence (lowest to highest):
      #   ternary (? :)
      #   logical or (||)
      #   logical and (&&)
      #   bitwise or (|)
      #   bitwise xor (^)
      #   bitwise and (&)
      #   equality (=== !==)
      #   comparison (< <= > >=)
      #   shift (<< >>)
      #   additive (+ -)
      #   multiplicative (* / %)
      #   unary (! - ~)
      #   postfix (. [] () ++ --)
      #   primary

      def parse_expression
        parse_ternary
      end

      def parse_ternary
        expr = parse_or
        if match(TOK_QUESTION)
          consequent = parse_ternary
          expect(TOK_COLON)
          alternate = parse_ternary
          return TernaryExpr.new(
            condition: expr,
            consequent: consequent,
            alternate: alternate
          )
        end
        expr
      end

      def parse_or
        left = parse_and
        while match(TOK_PIPEPIPE)
          right = parse_and
          left = BinaryExpr.new(op: "||", left: left, right: right)
        end
        left
      end

      def parse_and
        left = parse_bitwise_or
        while match(TOK_AMPAMP)
          right = parse_bitwise_or
          left = BinaryExpr.new(op: "&&", left: left, right: right)
        end
        left
      end

      def parse_bitwise_or
        left = parse_bitwise_xor
        while match(TOK_PIPE)
          right = parse_bitwise_xor
          left = BinaryExpr.new(op: "|", left: left, right: right)
        end
        left
      end

      def parse_bitwise_xor
        left = parse_bitwise_and
        while match(TOK_CARET)
          right = parse_bitwise_and
          left = BinaryExpr.new(op: "^", left: left, right: right)
        end
        left
      end

      def parse_bitwise_and
        left = parse_equality
        while match(TOK_AMP)
          right = parse_equality
          left = BinaryExpr.new(op: "&", left: left, right: right)
        end
        left
      end

      def parse_equality
        left = parse_comparison
        loop do
          if match(TOK_EQEQEQ)
            right = parse_comparison
            left = BinaryExpr.new(op: "===", left: left, right: right)
          elsif match(TOK_NOTEQEQ)
            right = parse_comparison
            left = BinaryExpr.new(op: "!==", left: left, right: right)
          elsif match(TOK_EQEQ)
            right = parse_comparison
            left = BinaryExpr.new(op: "===", left: left, right: right)
          elsif match(TOK_NOTEQ)
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
          if match(TOK_LT)
            right = parse_shift
            left = BinaryExpr.new(op: "<", left: left, right: right)
          elsif match(TOK_LTEQ)
            right = parse_shift
            left = BinaryExpr.new(op: "<=", left: left, right: right)
          elsif match(TOK_GT)
            right = parse_shift
            left = BinaryExpr.new(op: ">", left: left, right: right)
          elsif match(TOK_GTEQ)
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
          if match(TOK_LSHIFT)
            right = parse_additive
            left = BinaryExpr.new(op: "<<", left: left, right: right)
          elsif match(TOK_RSHIFT)
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
          if match(TOK_PLUS)
            right = parse_multiplicative
            left = BinaryExpr.new(op: "+", left: left, right: right)
          elsif match(TOK_MINUS)
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
          if match(TOK_STAR)
            right = parse_unary
            left = BinaryExpr.new(op: "*", left: left, right: right)
          elsif match(TOK_SLASH)
            right = parse_unary
            left = BinaryExpr.new(op: "/", left: left, right: right)
          elsif match(TOK_PERCENT)
            right = parse_unary
            left = BinaryExpr.new(op: "%", left: left, right: right)
          else
            break
          end
        end
        left
      end

      def parse_unary
        if match(TOK_BANG)
          operand = parse_unary
          return UnaryExpr.new(op: "!", operand: operand)
        end
        if match(TOK_MINUS)
          operand = parse_unary
          return UnaryExpr.new(op: "-", operand: operand)
        end
        if match(TOK_TILDE)
          operand = parse_unary
          return UnaryExpr.new(op: "~", operand: operand)
        end
        # Prefix ++ and --
        if match(TOK_PLUSPLUS)
          operand = parse_unary
          return IncrementExpr.new(operand: operand, prefix: true)
        end
        if match(TOK_MINUSMINUS)
          operand = parse_unary
          return DecrementExpr.new(operand: operand, prefix: true)
        end
        parse_postfix
      end

      def parse_postfix
        expr = parse_primary
        loop do
          # Member access: expr.name
          if match(TOK_DOT)
            prop_tok = expect(TOK_IDENT)
            prop_name = prop_tok.value

            # Check for call: expr.name(...)
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

          # Index access: expr[index]
          elsif match(TOK_LBRACKET)
            index = parse_expression
            expect(TOK_RBRACKET)
            expr = IndexAccessExpr.new(object: expr, index: index)

          # Direct call: expr(...)
          elsif check(TOK_LPAREN) && callable?(expr)
            args = parse_call_args
            expr = CallExpr.new(callee: expr, args: args)

          # Postfix ++
          elsif match(TOK_PLUSPLUS)
            expr = IncrementExpr.new(operand: expr, prefix: false)

          # Postfix --
          elsif match(TOK_MINUSMINUS)
            expr = DecrementExpr.new(operand: expr, prefix: false)

          # TypeScript 'as' type assertion -- skip the type, return expression
          elsif check_ident("as")
            advance
            parse_type

          else
            break
          end
        end
        expr
      end

      def callable?(expr)
        expr.is_a?(Identifier)
      end

      def parse_call_args
        expect(TOK_LPAREN)
        args = []
        while !check(TOK_RPAREN) && !check(TOK_EOF)
          arg = parse_expression
          args << arg
          break unless match(TOK_COMMA)
        end
        expect(TOK_RPAREN)
        args
      end

      def parse_primary
        tok = peek

        # Number literal
        if tok.kind == TOK_NUMBER
          advance
          return TsParser.parse_number(tok.value)
        end

        # String literal
        if tok.kind == TOK_STRING
          advance
          return ByteStringLiteral.new(value: tok.value)
        end

        # Identifier, keyword, or call
        if tok.kind == TOK_IDENT
          advance
          name = tok.value

          return BoolLiteral.new(value: true) if name == "true"
          return BoolLiteral.new(value: false) if name == "false"
          return Identifier.new(name: "this") if name == "this"
          return Identifier.new(name: "super") if name == "super"

          # Function call: name(...)
          if check(TOK_LPAREN)
            args = parse_call_args
            return CallExpr.new(callee: Identifier.new(name: name), args: args)
          end

          return Identifier.new(name: name)
        end

        # Parenthesized expression
        if tok.kind == TOK_LPAREN
          advance
          expr = parse_expression
          expect(TOK_RPAREN)
          return expr
        end

        # Array literal: [a, b, c]
        if tok.kind == TOK_LBRACKET
          return parse_array_literal
        end

        add_error("line #{tok.line}: unexpected token #{tok.value.inspect}")
        advance
        BigIntLiteral.new(value: 0)
      end

      def parse_array_literal
        expect(TOK_LBRACKET)
        elements = []
        while !check(TOK_RBRACKET) && !check(TOK_EOF)
          elem = parse_expression
          elements << elem
          break unless match(TOK_COMMA)
        end
        expect(TOK_RBRACKET)
        CallExpr.new(callee: Identifier.new(name: "FixedArray"), args: elements)
      end

      # -- Number parsing ---------------------------------------------------

      INT64_MAX = 9_223_372_036_854_775_807
      INT64_MIN = -9_223_372_036_854_775_808

      def self.parse_number(s)
        val = begin
          Integer(s, 0)
        rescue ArgumentError
          0
        end
        # Check int64 overflow
        if val > INT64_MAX || val < INT64_MIN
          return BigIntLiteral.new(value: 0)
        end
        BigIntLiteral.new(value: val)
      end
    end

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    # Parse a TypeScript-syntax Runar contract (.runar.ts).
    #
    # @param source [String] the source code
    # @param file_name [String] the file name (used in diagnostics)
    # @return [ParseResult]
    def self.parse_ts(source, file_name)
      p = TsParser.new(file_name)
      p.tokens = TsTokens.tokenize(source)
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
