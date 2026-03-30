# frozen_string_literal: true

# Solidity format parser (.runar.sol) for the Runar compiler.
#
# Ported from compilers/python/runar_compiler/frontend/parser_sol.py.
# Hand-written tokenizer + recursive descent parser for Solidity-like syntax.
#
# Solidity-like conventions used in Runar contracts:
#   - +pragma runar ^0.1.0;+ (skipped)
#   - +contract Name is SmartContract { ... }+
#   - +stateful contract Name is StatefulSmartContract { ... }+
#   - +constructor(Type name, ...) { super(name, ...); }+
#   - +function methodName(Type name, ...) public { ... }+
#   - +immutable+ for readonly properties
#   - +require(condition)+ maps to +assert(condition)+
#   - +let Type name = expr;+ for variable declarations

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"

module RunarCompiler
  module Frontend
    # -----------------------------------------------------------------------
    # Token types (namespaced to avoid collision with other parsers)
    # -----------------------------------------------------------------------

    module SolTokens
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
      TOK_PLUSPLUS      = 33  # ++
      TOK_MINUSMINUS   = 34  # --
      TOK_PLUSEQ       = 35  # +=
      TOK_MINUSEQ      = 36  # -=
      TOK_STAREQ       = 37  # *=
      TOK_SLASHEQ      = 38  # /=
      TOK_PERCENTEQ    = 39  # %=
      TOK_QUESTION     = 40  # ?
      TOK_LSHIFT       = 41  # <<
      TOK_RSHIFT       = 42  # >>

      # A single token produced by the tokenizer.
      Token = Struct.new(:kind, :value, :line, :col, keyword_init: true)

      # -------------------------------------------------------------------
      # Tokenizer helpers
      # -------------------------------------------------------------------

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

      # -------------------------------------------------------------------
      # Operator lookup tables
      # -------------------------------------------------------------------

      TWO_CHAR_OPS = {
        "==" => TOK_EQEQ,
        "!=" => TOK_NOTEQ,
        "<=" => TOK_LTEQ,
        ">=" => TOK_GTEQ,
        "&&" => TOK_AMPAMP,
        "||" => TOK_PIPEPIPE,
        "++" => TOK_PLUSPLUS,
        "--" => TOK_MINUSMINUS,
        "+=" => TOK_PLUSEQ,
        "-=" => TOK_MINUSEQ,
        "*=" => TOK_STAREQ,
        "/=" => TOK_SLASHEQ,
        "%=" => TOK_PERCENTEQ,
        "<<" => TOK_LSHIFT,
        ">>" => TOK_RSHIFT,
      }.freeze

      ONE_CHAR_OPS = {
        "{" => TOK_LBRACE,
        "}" => TOK_RBRACE,
        "(" => TOK_LPAREN,
        ")" => TOK_RPAREN,
        "[" => TOK_LBRACKET,
        "]" => TOK_RBRACKET,
        ";" => TOK_SEMICOLON,
        "," => TOK_COMMA,
        "." => TOK_DOT,
        ":" => TOK_COLON,
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

      # -------------------------------------------------------------------
      # Tokenizer
      # -------------------------------------------------------------------

      # Tokenize a Solidity-like source string into an array of Token structs.
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
              i += 1 if i < n
            end
            next
          end

          start_col = col

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

          # Numbers (including hex 0x... and BigInt suffix 'n')
          if ch >= "0" && ch <= "9"
            start = i
            if ch == "0" && i + 1 < n && (source[i + 1] == "x" || source[i + 1] == "X")
              i += 2
              col += 2
              while i < n && hex_digit?(source[i])
                i += 1
                col += 1
              end
            else
              while i < n && source[i] >= "0" && source[i] <= "9"
                i += 1
                col += 1
              end
            end
            # Skip trailing BigInt suffix 'n' (from TS syntax)
            if i < n && source[i] == "n"
              i += 1
              col += 1
            end
            tokens << Token.new(kind: TOK_NUMBER, value: source[start...i], line: line, col: start_col)
            next
          end

          # Identifiers and keywords
          if ident_start?(ch)
            start = i
            while i < n && ident_part?(source[i])
              i += 1
              col += 1
            end
            tokens << Token.new(kind: TOK_IDENT, value: source[start...i], line: line, col: start_col)
            next
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
    end # module SolTokens

    # -----------------------------------------------------------------------
    # Solidity type mapping
    # -----------------------------------------------------------------------

    SOL_TYPE_MAP = {
      "uint"     => "bigint",
      "uint256"  => "bigint",
      "int"      => "bigint",
      "int256"   => "bigint",
      "bool"     => "boolean",
      "bytes"    => "ByteString",
      "address"  => "Addr",
    }.freeze

    # Map a Solidity-style type name to a Runar TypeNode.
    def self.parse_sol_type_name(name)
      mapped = SOL_TYPE_MAP[name]
      return PrimitiveType.new(name: mapped) if mapped

      return PrimitiveType.new(name: name) if primitive_type?(name)

      CustomType.new(name: name)
    end

    # Return true if +name+ resolves to a known Solidity/Runar primitive type.
    def self.known_sol_type?(name)
      SOL_TYPE_MAP.key?(name) || primitive_type?(name)
    end

    # -----------------------------------------------------------------------
    # Parser
    # -----------------------------------------------------------------------

    class SolParser
      include SolTokens

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

      def peek_next_kind
        return @tokens[@pos + 1].kind if @pos + 1 < @tokens.length

        TOK_EOF
      end

      # -- Contract parsing ------------------------------------------------

      def parse_contract
        # Skip pragma
        if check_ident("pragma")
          while !check(TOK_SEMICOLON) && !check(TOK_EOF)
            advance
          end
          match(TOK_SEMICOLON)
        end

        # Skip import statements
        while check_ident("import")
          while !check(TOK_SEMICOLON) && !check(TOK_EOF)
            advance
          end
          match(TOK_SEMICOLON)
        end

        # Optional 'stateful' keyword before 'contract'
        # (not standard Solidity but supported in Runar .sol format)
        is_stateful_keyword = match_ident("stateful")

        # contract Name is ParentClass {
        unless match_ident("contract")
          raise "expected 'contract' keyword"
        end

        name_tok = expect(TOK_IDENT)
        contract_name = name_tok.value

        parent_class = "SmartContract"
        if match_ident("is")
          parent_tok = expect(TOK_IDENT)
          parent_class = parent_tok.value
        end

        # If 'stateful' keyword was used, override parent class
        if is_stateful_keyword && parent_class == "SmartContract"
          parent_class = "StatefulSmartContract"
        end

        unless %w[SmartContract StatefulSmartContract].include?(parent_class)
          raise "unknown parent class: #{parent_class}"
        end

        expect(TOK_LBRACE)

        properties = []
        constructor = nil
        methods = []

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          if check_ident("function")
            methods << parse_function
          elsif check_ident("constructor")
            constructor = parse_sol_constructor(properties)
          else
            # Try to parse as property: Type [immutable] name;
            prop = parse_sol_property
            properties << prop unless prop.nil?
          end
        end

        expect(TOK_RBRACE)

        # Auto-generate constructor if not explicitly defined
        if constructor.nil?
          default_loc = SourceLocation.new(file: @file_name, line: 1, column: 0)
          # Only non-initialized properties become constructor params
          uninit_props = properties.select { |p| p.initializer.nil? }
          constructor = MethodNode.new(
            name: "constructor",
            params: uninit_props.map { |p| ParamNode.new(name: p.name, type: p.type) },
            body: [
              ExpressionStmt.new(
                expr: CallExpr.new(
                  callee: Identifier.new(name: "super"),
                  args: uninit_props.map { |p| Identifier.new(name: p.name) }
                ),
                source_location: default_loc
              ),
              *uninit_props.map do |p|
                AssignmentStmt.new(
                  target: PropertyAccessExpr.new(property: p.name),
                  value: Identifier.new(name: p.name),
                  source_location: default_loc
                )
              end,
            ],
            visibility: "public",
            source_location: default_loc
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

      # -- Property parsing: Type [immutable] name [= value]; ---------------

      def parse_sol_property
        location = loc

        type_tok = advance
        if type_tok.kind != TOK_IDENT
          # Skip unknown tokens
          return nil
        end
        type_name = type_tok.value

        # Check for array type: Type[N]
        type_node = parse_sol_type_from_name(type_name)

        # Check for immutable keyword
        is_readonly = false
        if check_ident("immutable")
          advance
          is_readonly = true
        end

        # Property name
        name_tok = expect(TOK_IDENT)
        prop_name = name_tok.value

        # Optional initializer: = value
        initializer = nil
        if match(TOK_ASSIGN)
          initializer = parse_expression
        end

        expect(TOK_SEMICOLON)

        PropertyNode.new(
          name: prop_name,
          type: type_node,
          readonly: is_readonly,
          initializer: initializer,
          source_location: location
        )
      end

      # -- Type parsing -----------------------------------------------------

      def parse_sol_type_from_name(name)
        mapped = Frontend.parse_sol_type_name(name)

        # Check for array type: Type[N]
        if check(TOK_LBRACKET)
          advance # [
          size_tok = expect(TOK_NUMBER)
          size = begin
            Integer(size_tok.value, 0)
          rescue ArgumentError
            add_error("line #{size_tok.line}: array size must be a non-negative integer literal")
            0
          end
          expect(TOK_RBRACKET)
          return FixedArrayType.new(element: mapped, length: size)
        end

        mapped
      end

      # -- Constructor parsing: constructor(Type _name, ...) { ... } --------

      def parse_sol_constructor(properties)
        location = loc
        expect_ident("constructor")
        params = parse_sol_params
        body = parse_sol_block

        # Build proper constructor body with super() call and assignments
        constructor_body = []

        # super(...) call with all param names
        super_args = params.map { |p| Identifier.new(name: p.name) }
        constructor_body << ExpressionStmt.new(
          expr: CallExpr.new(
            callee: Identifier.new(name: "super"),
            args: super_args
          ),
          source_location: location
        )

        # Build a rename map for _-prefixed param names (e.g., _pubKeyHash -> pubKeyHash).
        # parse_sol_params already stripped the underscore from param names, but the
        # body was parsed with the original _-prefixed identifiers still in place.
        rename_map = {}
        params.each do |p|
          original = "_" + p.name
          rename_map[original] = p.name
        end

        # Append any additional statements from the body:
        # 1. Rename _-prefixed identifiers to their stripped versions
        # 2. Convert bare property name assignments to this.property form
        prop_names = properties.map(&:name).to_set
        body.each do |stmt|
          stmt = Frontend.sol_rename_identifiers_in_stmt(stmt, rename_map) unless rename_map.empty?
          if stmt.is_a?(AssignmentStmt) && stmt.target.is_a?(Identifier)
            if prop_names.include?(stmt.target.name)
              stmt = AssignmentStmt.new(
                target: PropertyAccessExpr.new(property: stmt.target.name),
                value: stmt.value,
                source_location: stmt.source_location
              )
            end
          end
          constructor_body << stmt
        end

        MethodNode.new(
          name: "constructor",
          params: params,
          body: constructor_body,
          visibility: "public",
          source_location: location
        )
      end

      # -- Function parsing: function name(Type name, ...) [public|private] { ... }

      def parse_function
        location = loc
        expect_ident("function")

        name_tok = expect(TOK_IDENT)
        name = name_tok.value

        params = parse_sol_params

        # Parse visibility modifiers and other qualifiers
        visibility = "private"
        while check_ident("public") || check_ident("private") ||
              check_ident("external") || check_ident("internal") ||
              check_ident("view") || check_ident("pure") ||
              check_ident("returns") || check_ident("payable")
          tok = advance
          visibility = "public" if tok.value == "public" || tok.value == "external"
          # Skip 'returns (Type)' clause
          if tok.value == "returns" && check(TOK_LPAREN)
            advance # (
            depth = 1
            while depth > 0 && !check(TOK_EOF)
              depth += 1 if check(TOK_LPAREN)
              depth -= 1 if check(TOK_RPAREN)
              advance
            end
          end
        end

        body = parse_sol_block

        MethodNode.new(
          name: name,
          params: params,
          body: body,
          visibility: visibility,
          source_location: location
        )
      end

      # -- Parameter parsing: (Type name, Type name, ...) -------------------

      def parse_sol_params
        expect(TOK_LPAREN)
        params = []

        while !check(TOK_RPAREN) && !check(TOK_EOF)
          type_tok = expect(TOK_IDENT)
          type_name = type_tok.value

          # Skip memory/storage/calldata qualifiers
          while check_ident("memory") || check_ident("storage") || check_ident("calldata")
            advance
          end

          name_tok = expect(TOK_IDENT)
          param_name = name_tok.value
          # Strip leading underscore (Solidity convention)
          param_name = param_name[1..] if param_name.start_with?("_")

          params << ParamNode.new(
            name: param_name,
            type: Frontend.parse_sol_type_name(type_name)
          )

          break unless match(TOK_COMMA)
        end

        expect(TOK_RPAREN)
        params
      end

      # -- Block parsing: { statements... } ---------------------------------

      def parse_sol_block
        expect(TOK_LBRACE)
        stmts = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          stmt = parse_sol_statement
          stmts << stmt unless stmt.nil?
        end
        expect(TOK_RBRACE)
        stmts
      end

      # -- Statement parsing -------------------------------------------------

      def parse_sol_statement
        location = loc

        # require(...) -> assert(...)
        if check_ident("require")
          return parse_require(location)
        end

        # if (...) { ... } [else { ... }]
        if check_ident("if")
          return parse_if_statement(location)
        end

        # for (...) { ... }
        if check_ident("for")
          return parse_for_statement(location)
        end

        # return ...;
        if check_ident("return")
          return parse_return_statement(location)
        end

        # Variable declarations: let Type name = expr;
        if check_ident("let")
          return parse_let_decl(location)
        end

        # Variable declarations: Type name = expr;
        if peek.kind == TOK_IDENT && is_type_start?
          return parse_var_decl(location)
        end

        # Assignment or expression statement
        parse_expr_statement(location)
      end

      def is_type_start?
        return false if @pos + 1 >= @tokens.length

        next_tok = @tokens[@pos + 1]
        # If next token is an identifier, this might be a type
        if next_tok.kind == TOK_IDENT
          name = peek.value
          return true if Frontend.known_sol_type?(name)
          # Capitalized names are likely type names
          return true if !name.empty? && name[0] =~ /[A-Z]/
          # Common Solidity types
          return true if %w[uint uint256 int int256 bool bytes address string].include?(name)
        end
        false
      end

      def parse_require(location)
        expect_ident("require")
        expect(TOK_LPAREN)
        expr = parse_expression
        # Skip optional error message parameter
        if match(TOK_COMMA)
          parse_expression
        end
        expect(TOK_RPAREN)
        expect(TOK_SEMICOLON)
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
        expect(TOK_LPAREN)
        condition = parse_expression
        expect(TOK_RPAREN)

        then_block = parse_sol_block

        else_block = []
        if match_ident("else")
          if check_ident("if")
            # else if -- recurse
            else_stmt = parse_if_statement(loc)
            else_block = [else_stmt]
          else
            else_block = parse_sol_block
          end
        end

        IfStmt.new(
          condition: condition,
          then: then_block,
          else_: else_block,
          source_location: location
        )
      end

      def parse_for_statement(location)
        expect_ident("for")
        expect(TOK_LPAREN)

        # Initializer
        if is_type_start? || check_ident("uint") || check_ident("int") || check_ident("let")
          if check_ident("let")
            advance # skip 'let'
          end
          type_tok = advance
          name_tok = expect(TOK_IDENT)
          expect(TOK_ASSIGN)
          init_expr = parse_expression
          expect(TOK_SEMICOLON)
          init_stmt = VariableDeclStmt.new(
            name: name_tok.value,
            type: Frontend.parse_sol_type_name(type_tok.value),
            mutable: true,
            init: init_expr,
            source_location: location
          )
        else
          expect(TOK_SEMICOLON)
          init_stmt = VariableDeclStmt.new(
            name: "_i",
            mutable: true,
            init: BigIntLiteral.new(value: 0),
            source_location: location
          )
        end

        # Condition
        condition = parse_expression
        expect(TOK_SEMICOLON)

        # Update
        update_expr = parse_expression
        update = ExpressionStmt.new(expr: update_expr, source_location: location)

        expect(TOK_RPAREN)

        body = parse_sol_block

        ForStmt.new(
          init: init_stmt,
          condition: condition,
          update: update,
          body: body,
          source_location: location
        )
      end

      def parse_return_statement(location)
        expect_ident("return")
        value = nil
        unless check(TOK_SEMICOLON)
          value = parse_expression
        end
        expect(TOK_SEMICOLON)
        ReturnStmt.new(value: value, source_location: location)
      end

      def parse_let_decl(location)
        advance # 'let'
        type_tok = advance # type
        type_name = type_tok.value
        name_tok = expect(TOK_IDENT)
        var_name = name_tok.value
        init = nil
        if match(TOK_ASSIGN)
          init = parse_expression
        end
        init = BigIntLiteral.new(value: 0) if init.nil?
        expect(TOK_SEMICOLON)
        VariableDeclStmt.new(
          name: var_name,
          type: Frontend.parse_sol_type_name(type_name),
          mutable: true,
          init: init,
          source_location: location
        )
      end

      def parse_var_decl(location)
        type_tok = advance
        type_name = type_tok.value

        name_tok = expect(TOK_IDENT)
        var_name = name_tok.value

        init = nil
        if match(TOK_ASSIGN)
          init = parse_expression
        end
        init = BigIntLiteral.new(value: 0) if init.nil?

        expect(TOK_SEMICOLON)

        VariableDeclStmt.new(
          name: var_name,
          type: Frontend.parse_sol_type_name(type_name),
          mutable: true,
          init: init,
          source_location: location
        )
      end

      def parse_expr_statement(location)
        expr = parse_expression

        # Check for assignment
        if match(TOK_ASSIGN)
          value = parse_expression
          expect(TOK_SEMICOLON)
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
          if match(kind)
            right = parse_expression
            expect(TOK_SEMICOLON)
            value = BinaryExpr.new(op: bin_op, left: expr, right: right)
            return AssignmentStmt.new(target: expr, value: value, source_location: location)
          end
        end

        expect(TOK_SEMICOLON)
        ExpressionStmt.new(expr: expr, source_location: location)
      end

      # -- Expression parsing (recursive descent with precedence) -----------

      def parse_expression
        parse_ternary
      end

      def parse_ternary
        expr = parse_or
        if match(TOK_QUESTION)
          consequent = parse_expression
          expect(TOK_COLON)
          alternate = parse_expression
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
          if match(TOK_EQEQ)
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
        # Prefix increment/decrement
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
          if match(TOK_DOT)
            prop_tok = expect(TOK_IDENT)
            prop_name = prop_tok.value

            # Check if this is a method call: obj.method(...)
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
              # Property access
              if expr.is_a?(Identifier) && expr.name == "this"
                expr = PropertyAccessExpr.new(property: prop_name)
              else
                expr = MemberExpr.new(object: expr, property: prop_name)
              end
            end

          elsif match(TOK_LBRACKET)
            index = parse_expression
            expect(TOK_RBRACKET)
            expr = IndexAccessExpr.new(object: expr, index: index)

          elsif match(TOK_PLUSPLUS)
            expr = IncrementExpr.new(operand: expr, prefix: false)

          elsif match(TOK_MINUSMINUS)
            expr = DecrementExpr.new(operand: expr, prefix: false)

          else
            break
          end
        end
        expr
      end

      def parse_primary
        tok = peek

        if tok.kind == TOK_NUMBER
          advance
          return parse_sol_number(tok.value)
        end

        if tok.kind == TOK_STRING
          advance
          return ByteStringLiteral.new(value: tok.value)
        end

        if tok.kind == TOK_IDENT
          advance
          name = tok.value

          # Boolean literals
          return BoolLiteral.new(value: true) if name == "true"
          return BoolLiteral.new(value: false) if name == "false"
          return Identifier.new(name: "this") if name == "this"

          # Function call
          if check(TOK_LPAREN)
            args = parse_call_args
            return CallExpr.new(callee: Identifier.new(name: name), args: args)
          end

          return Identifier.new(name: name)
        end

        if tok.kind == TOK_LPAREN
          advance
          expr = parse_expression
          expect(TOK_RPAREN)
          return expr
        end

        if tok.kind == TOK_LBRACKET
          return parse_array_literal
        end

        add_error("line #{tok.line}: unexpected token #{tok.value.inspect}")
        advance
        BigIntLiteral.new(value: 0)
      end

      def parse_call_args
        expect(TOK_LPAREN)
        args = []
        while !check(TOK_RPAREN) && !check(TOK_EOF)
          args << parse_expression
          break unless match(TOK_COMMA)
        end
        expect(TOK_RPAREN)
        args
      end

      def parse_array_literal
        expect(TOK_LBRACKET)
        elements = []
        while !check(TOK_RBRACKET) && !check(TOK_EOF)
          elements << parse_expression
          break unless match(TOK_COMMA)
        end
        expect(TOK_RBRACKET)
        CallExpr.new(callee: Identifier.new(name: "FixedArray"), args: elements)
      end

      def parse_sol_number(s)
        # Strip trailing 'n' suffix
        s = s[0...-1] if s.end_with?("n")
        val = begin
          Integer(s, 0)
        rescue ArgumentError
          0
        end
        BigIntLiteral.new(value: val)
      end
    end

    # -----------------------------------------------------------------------
    # Constructor identifier renaming helpers
    # -----------------------------------------------------------------------

    # Recursively rename identifiers in an expression using +rename_map+.
    # Used to fix _-prefixed constructor param references in the body
    # (e.g. +_pubKeyHash+ -> +pubKeyHash+).
    def self.sol_rename_identifiers_in_expr(expr, rename_map)
      rn = lambda { |e| sol_rename_identifiers_in_expr(e, rename_map) }
      case expr
      when Identifier
        new_name = rename_map[expr.name]
        return Identifier.new(name: new_name) if new_name
        expr
      when BinaryExpr
        BinaryExpr.new(op: expr.op, left: rn.call(expr.left), right: rn.call(expr.right))
      when UnaryExpr
        UnaryExpr.new(op: expr.op, operand: rn.call(expr.operand))
      when CallExpr
        CallExpr.new(callee: rn.call(expr.callee), args: expr.args.map { |a| rn.call(a) })
      when MemberExpr
        MemberExpr.new(object: rn.call(expr.object), property: expr.property)
      when TernaryExpr
        TernaryExpr.new(
          condition: rn.call(expr.condition),
          consequent: rn.call(expr.consequent),
          alternate: rn.call(expr.alternate)
        )
      when IndexAccessExpr
        IndexAccessExpr.new(object: rn.call(expr.object), index: rn.call(expr.index))
      when IncrementExpr
        IncrementExpr.new(operand: rn.call(expr.operand), prefix: expr.prefix)
      when DecrementExpr
        DecrementExpr.new(operand: rn.call(expr.operand), prefix: expr.prefix)
      else
        # PropertyAccessExpr, literals, etc. -- no identifiers to rename
        expr
      end
    end

    # Recursively rename identifiers in a statement tree.
    # Used to fix _-prefixed constructor params in the body.
    def self.sol_rename_identifiers_in_stmt(stmt, rename_map)
      return stmt if rename_map.empty?
      rn = lambda { |e| sol_rename_identifiers_in_expr(e, rename_map) }
      rs = lambda { |s| sol_rename_identifiers_in_stmt(s, rename_map) }
      case stmt
      when AssignmentStmt
        AssignmentStmt.new(target: rn.call(stmt.target), value: rn.call(stmt.value), source_location: stmt.source_location)
      when ExpressionStmt
        ExpressionStmt.new(expr: rn.call(stmt.expr), source_location: stmt.source_location)
      when VariableDeclStmt
        VariableDeclStmt.new(
          name: stmt.name, type: stmt.type, mutable: stmt.mutable,
          init: stmt.init ? rn.call(stmt.init) : nil,
          source_location: stmt.source_location
        )
      when IfStmt
        IfStmt.new(
          condition: rn.call(stmt.condition),
          then: stmt.then.map { |s| rs.call(s) },
          else_: stmt.else_ ? stmt.else_.map { |s| rs.call(s) } : [],
          source_location: stmt.source_location
        )
      when ForStmt
        ForStmt.new(
          init: stmt.init ? rs.call(stmt.init) : nil,
          condition: stmt.condition ? rn.call(stmt.condition) : nil,
          update: stmt.update ? rs.call(stmt.update) : nil,
          body: stmt.body.map { |s| rs.call(s) },
          source_location: stmt.source_location
        )
      when ReturnStmt
        ReturnStmt.new(value: stmt.value ? rn.call(stmt.value) : nil, source_location: stmt.source_location)
      else
        stmt
      end
    end

    # -----------------------------------------------------------------------
    # Property rewriting helpers
    # -----------------------------------------------------------------------

    # Recursively rewrite bare Identifier(name) -> PropertyAccessExpr(property)
    # for property names, and bare method calls -> this.method() for contract
    # method names in Solidity-format contracts.
    def self.rewrite_sol_expr(expr, prop_names, param_names, method_names)
      rw = lambda { |e| rewrite_sol_expr(e, prop_names, param_names, method_names) }
      case expr
      when Identifier
        if prop_names.include?(expr.name) && !param_names.include?(expr.name)
          return PropertyAccessExpr.new(property: expr.name)
        end
        expr
      when BinaryExpr
        BinaryExpr.new(op: expr.op, left: rw.call(expr.left), right: rw.call(expr.right))
      when UnaryExpr
        UnaryExpr.new(op: expr.op, operand: rw.call(expr.operand))
      when CallExpr
        if expr.callee.is_a?(Identifier) && method_names.include?(expr.callee.name)
          return CallExpr.new(
            callee: MemberExpr.new(
              object: Identifier.new(name: "this"),
              property: expr.callee.name
            ),
            args: expr.args.map { |a| rw.call(a) }
          )
        end
        CallExpr.new(callee: rw.call(expr.callee), args: expr.args.map { |a| rw.call(a) })
      when TernaryExpr
        TernaryExpr.new(
          condition: rw.call(expr.condition),
          consequent: rw.call(expr.consequent),
          alternate: rw.call(expr.alternate)
        )
      when IndexAccessExpr
        IndexAccessExpr.new(object: rw.call(expr.object), index: rw.call(expr.index))
      when IncrementExpr
        IncrementExpr.new(operand: rw.call(expr.operand), prefix: expr.prefix)
      when DecrementExpr
        DecrementExpr.new(operand: rw.call(expr.operand), prefix: expr.prefix)
      else
        expr
      end
    end

    def self.rewrite_sol_stmt(stmt, prop_names, param_names, method_names)
      rw = lambda { |e| rewrite_sol_expr(e, prop_names, param_names, method_names) }
      rs = lambda { |s| rewrite_sol_stmt(s, prop_names, param_names, method_names) }
      case stmt
      when ExpressionStmt
        ExpressionStmt.new(expr: rw.call(stmt.expr), source_location: stmt.source_location)
      when VariableDeclStmt
        new_params = param_names | Set[stmt.name]
        VariableDeclStmt.new(
          name: stmt.name, type: stmt.type, mutable: stmt.mutable,
          init: stmt.init ? rewrite_sol_expr(stmt.init, prop_names, new_params, method_names) : nil,
          source_location: stmt.source_location
        )
      when AssignmentStmt
        AssignmentStmt.new(target: rw.call(stmt.target), value: rw.call(stmt.value), source_location: stmt.source_location)
      when ReturnStmt
        ReturnStmt.new(value: stmt.value ? rw.call(stmt.value) : nil, source_location: stmt.source_location)
      when IfStmt
        IfStmt.new(
          condition: rw.call(stmt.condition),
          then: stmt.then.map { |s| rs.call(s) },
          else_: stmt.else_ ? stmt.else_.map { |s| rs.call(s) } : [],
          source_location: stmt.source_location
        )
      when ForStmt
        ForStmt.new(
          init: stmt.init ? rs.call(stmt.init) : nil,
          condition: stmt.condition ? rw.call(stmt.condition) : nil,
          update: stmt.update ? rs.call(stmt.update) : nil,
          body: stmt.body.map { |s| rs.call(s) },
          source_location: stmt.source_location
        )
      else
        stmt
      end
    end

    def self.rewrite_sol_contract_props(contract)
      prop_names = contract.properties.map(&:name).to_set
      method_names = contract.methods.map(&:name).to_set
      return if prop_names.empty? && method_names.empty?

      contract.methods.each do |method|
        param_names = method.params.map(&:name).to_set
        method.body.replace(
          method.body.map { |s| rewrite_sol_stmt(s, prop_names, param_names, method_names) }
        )
      end
    end

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    # Parse a Solidity-syntax Runar contract (.runar.sol).
    #
    # @param source [String] the source code
    # @param file_name [String] the file name (used in diagnostics)
    # @return [ParseResult]
    def self.parse_sol(source, file_name = "contract.runar.sol")
      p = SolParser.new(file_name)
      p.tokens = SolTokens.tokenize(source)
      p.pos = 0

      begin
        contract = p.parse_contract
      rescue => e
        return ParseResult.new(
          errors: [Diagnostic.new(message: e.message, severity: Severity::ERROR)]
        )
      end

      rewrite_sol_contract_props(contract) unless contract.nil?

      if p.errors.any?
        return ParseResult.new(contract: contract, errors: p.errors)
      end

      ParseResult.new(contract: contract)
    end
  end
end
