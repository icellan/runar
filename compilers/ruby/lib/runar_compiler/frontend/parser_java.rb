# frozen_string_literal: true

# Java contract format parser (.runar.java) for the Runar compiler.
#
# Ported from the authoritative surface spec:
#   compilers/java/src/main/java/runar/compiler/frontend/JavaParser.java
# Worked examples:
#   compilers/java/src/test/java/runar/compiler/frontend/JavaParserTest.java
#   examples/java/src/main/java/runar/examples/p2pkh/P2PKH.runar.java
# Format docs:
#   docs/formats/java.md
#
# Hand-written tokenizer + recursive descent parser for Java contract syntax.
#
# Java syntax conventions used in Runar contracts:
#   - +package foo.bar;+ + +import ...;+ (consumed for parity, ignored)
#   - Package-private class extending +SmartContract+ or +StatefulSmartContract+
#   - +@Readonly+ on fields, +@Public+ on methods
#   - Constructor with +super(...)+ as the first statement
#   - Typed parameters, +void+ return for public methods
#   - Statements: variable decl, assignment, if/else, for, return, expression
#   - Expressions: identifier, int/bool literal, +X.fromHex("hex")+ ->
#     ByteStringLiteral, +BigInteger.valueOf(N)+ + +BigInteger.{ZERO,ONE,TWO,TEN}+
#     -> BigIntLiteral, binary ops, unary (+!+, +-+, +~+, prefix/postfix +++/+--+),
#     method calls, member access, +this.foo+ -> PropertyAccess, ternary,
#     array access, array literal
#   - Types: +boolean+/+Boolean+, +BigInteger+/+Bigint+, Runar domain types,
#     +FixedArray<T, N>+ with integer-literal +N+

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"
require_relative "input_limits"
require_relative "sighash_directive"

module RunarCompiler
  module Frontend
    # -----------------------------------------------------------------------
    # Namespaced token constants for the Java parser
    # -----------------------------------------------------------------------

    module JavaTokens
      TOK_EOF         = 0
      TOK_IDENT       = 1
      TOK_NUMBER      = 2
      TOK_STRING      = 3
      TOK_CHAR        = 4
      TOK_LPAREN      = 5   # (
      TOK_RPAREN      = 6   # )
      TOK_LBRACE      = 7   # {
      TOK_RBRACE      = 8   # }
      TOK_LBRACKET    = 9   # [
      TOK_RBRACKET    = 10  # ]
      TOK_SEMI        = 11  # ;
      TOK_COMMA       = 12  # ,
      TOK_DOT         = 13  # .
      TOK_COLON       = 14  # :
      TOK_QUESTION    = 15  # ?
      TOK_AT          = 16  # @
      TOK_PLUS        = 17  # +
      TOK_MINUS       = 18  # -
      TOK_STAR        = 19  # *
      TOK_SLASH       = 20  # /
      TOK_PERCENT     = 21  # %
      TOK_EQEQ        = 22  # ==
      TOK_BANGEQ      = 23  # !=
      TOK_LT          = 24  # <
      TOK_LTEQ        = 25  # <=
      TOK_GT          = 26  # >
      TOK_GTEQ        = 27  # >=
      TOK_AMPAMP      = 28  # &&
      TOK_PIPEPIPE    = 29  # ||
      TOK_AMP         = 30  # &
      TOK_PIPE        = 31  # |
      TOK_CARET       = 32  # ^
      TOK_TILDE       = 33  # ~
      TOK_BANG        = 34  # !
      TOK_EQ          = 35  # =
      TOK_PLUSEQ      = 36  # +=
      TOK_MINUSEQ     = 37  # -=
      TOK_STAREQ      = 38  # *=
      TOK_SLASHEQ     = 39  # /=
      TOK_PERCENTEQ   = 40  # %=
      TOK_PLUSPLUS    = 41  # ++
      TOK_MINUSMINUS  = 42  # --
      TOK_LSHIFT      = 43  # <<
      TOK_RSHIFT      = 44  # >>
      TOK_LSHIFTEQ    = 45  # <<=
      TOK_RSHIFTEQ    = 46  # >>=
      TOK_AMPEQ       = 47  # &=
      TOK_PIPEEQ      = 48  # |=
      TOK_CARETEQ     = 49  # ^=
      # Keywords
      TOK_PACKAGE          = 60
      TOK_IMPORT           = 61
      TOK_CLASS            = 62
      TOK_EXTENDS          = 63
      TOK_IMPLEMENTS       = 64
      TOK_PUBLIC           = 65
      TOK_PRIVATE          = 66
      TOK_PROTECTED        = 67
      TOK_STATIC           = 68
      TOK_FINAL            = 69
      TOK_ABSTRACT         = 70
      TOK_RETURN           = 71
      TOK_IF               = 72
      TOK_ELSE             = 73
      TOK_FOR              = 74
      TOK_WHILE            = 75
      TOK_TRUE             = 76
      TOK_FALSE            = 77
      TOK_NULL             = 78
      TOK_THIS             = 79
      TOK_SUPER            = 80
      TOK_NEW              = 81
      TOK_VOID             = 82
    end

    # A single token produced by the Java tokenizer.
    # F-026: +raw+ is a number token's text as written; +neg_only+ marks
    # `2147483648` / `9223372036854775808L`, legal only under a unary minus.
    JavaToken = Struct.new(:kind, :value, :line, :col, :raw, :neg_only, keyword_init: true)

    # -----------------------------------------------------------------------
    # Java type mapping -- Java/Runar type name -> Runar canonical type
    # -----------------------------------------------------------------------

    JAVA_TYPE_MAP = {
      # BigInteger and friends
      "BigInteger"      => "bigint",
      "Bigint"          => "bigint",
      # Boolean
      "boolean"         => "boolean",
      "Boolean"         => "boolean",
      # Direct domain types (pass-through)
      "ByteString"      => "ByteString",
      "PubKey"          => "PubKey",
      "Sig"             => "Sig",
      "Sha256"          => "Sha256",
      "Sha256Digest"    => "Sha256",
      "Ripemd160"       => "Ripemd160",
      "Hash160"         => "Ripemd160",
      "Addr"            => "Addr",
      "SigHashPreimage" => "SigHashPreimage",
      "RabinSig"        => "RabinSig",
      "RabinPubKey"     => "RabinPubKey",
      "Point"           => "Point",
      "P256Point"       => "P256Point",
      "P384Point"       => "P384Point",
      "OpCodeType"      => "OpCodeType",
    }.freeze

    def self.java_map_type(name)
      mapped = JAVA_TYPE_MAP[name] || name
      if primitive_type?(mapped)
        return PrimitiveType.new(name: mapped)
      end
      CustomType.new(name: mapped)
    end

    # -----------------------------------------------------------------------
    # Tokenizer
    # -----------------------------------------------------------------------

    JAVA_KEYWORDS = {
      "package"    => JavaTokens::TOK_PACKAGE,
      "import"     => JavaTokens::TOK_IMPORT,
      "class"      => JavaTokens::TOK_CLASS,
      "extends"    => JavaTokens::TOK_EXTENDS,
      "implements" => JavaTokens::TOK_IMPLEMENTS,
      "public"     => JavaTokens::TOK_PUBLIC,
      "private"    => JavaTokens::TOK_PRIVATE,
      "protected"  => JavaTokens::TOK_PROTECTED,
      "static"     => JavaTokens::TOK_STATIC,
      "final"      => JavaTokens::TOK_FINAL,
      "abstract"   => JavaTokens::TOK_ABSTRACT,
      "return"     => JavaTokens::TOK_RETURN,
      "if"         => JavaTokens::TOK_IF,
      "else"       => JavaTokens::TOK_ELSE,
      "for"        => JavaTokens::TOK_FOR,
      "while"      => JavaTokens::TOK_WHILE,
      "true"       => JavaTokens::TOK_TRUE,
      "false"      => JavaTokens::TOK_FALSE,
      "null"       => JavaTokens::TOK_NULL,
      "this"       => JavaTokens::TOK_THIS,
      "super"      => JavaTokens::TOK_SUPER,
      "new"        => JavaTokens::TOK_NEW,
      "void"       => JavaTokens::TOK_VOID,
    }.freeze

    JAVA_MODIFIER_KINDS = [
      JavaTokens::TOK_PUBLIC,
      JavaTokens::TOK_PRIVATE,
      JavaTokens::TOK_PROTECTED,
      JavaTokens::TOK_STATIC,
      JavaTokens::TOK_FINAL,
      JavaTokens::TOK_ABSTRACT,
    ].freeze

    def self.java_ident_start?(ch)
      (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch == "_" || ch == "$"
    end

    def self.java_ident_part?(ch)
      java_ident_start?(ch) || (ch >= "0" && ch <= "9")
    end

    def self.tokenize_java(source, lex = [], file_name = "")
      tokens = []
      n = source.length
      i = 0
      line = 1
      col = 0

      while i < n
        ch = source[i]

        # Whitespace
        if ch == " " || ch == "\t" || ch == "\r"
          i += 1
          col += 1
          next
        end
        if ch == "\n"
          i += 1
          line += 1
          col = 0
          next
        end

        # Line comment //
        if ch == "/" && i + 1 < n && source[i + 1] == "/"
          while i < n && source[i] != "\n"
            i += 1
          end
          next
        end

        # Block comment /* ... */
        if ch == "/" && i + 1 < n && source[i + 1] == "*"
          i += 2
          col += 2
          while i + 1 < n
            if source[i] == "\n"
              line += 1
              col = 0
              i += 1
              next
            end
            if source[i] == "*" && source[i + 1] == "/"
              i += 2
              col += 2
              break
            end
            i += 1
            col += 1
          end
          next
        end

        start_line = line
        start_col = col

        # String literal
        if ch == '"'
          i += 1
          col += 1
          val = +""
          # F-011: a Java string literal cannot span lines; one that reaches
          # a line break (escaped or not) or end of file is unterminated.
          while i < n && source[i] != '"' && source[i] != "\n" && source[i] != "\r"
            break if source[i] == "\\" && (i + 1 >= n || source[i + 1] == "\n" || source[i + 1] == "\r")

            if source[i] == "\\" && i + 1 < n
              nx = source[i + 1]
              case nx
              when "n" then val << "\n"
              when "t" then val << "\t"
              when "r" then val << "\r"
              when "\\" then val << "\\"
              when '"' then val << '"'
              when "'" then val << "'"
              when "0" then val << "\x00"
              else val << nx
              end
              i += 2
              col += 2
            else
              val << source[i]
              i += 1
              col += 1
            end
          end
          if i < n && source[i] == '"'
            i += 1 # closing quote
          else
            lex << Frontend.lex_error(UNTERMINATED_STRING_LITERAL, file_name, start_line, start_col)
          end
          col += 1
          tokens << JavaToken.new(kind: JavaTokens::TOK_STRING, value: val, line: start_line, col: start_col)
          next
        end

        # Character literal (parsed but not used in Runar subset; rejected later)
        if ch == "'"
          # F-011: refused exactly as the TS reference refuses it.
          lex << Frontend.lex_error(JAVA_CHAR_LITERAL, file_name, start_line, start_col)
          i += 1
          col += 1
          val = +""
          while i < n && source[i] != "'"
            if source[i] == "\\" && i + 1 < n
              val << source[i, 2]
              i += 2
              col += 2
            else
              val << source[i]
              i += 1
              col += 1
            end
          end
          i += 1 if i < n
          col += 1
          tokens << JavaToken.new(kind: JavaTokens::TOK_CHAR, value: val, line: start_line, col: start_col)
          next
        end

        # Number (F-026): the whole glued [0-9A-Za-z_] run is one Java integer
        # literal (JLS 3.10.1), with Java's value: hex / octal / binary int and
        # long literals wrap to two's complement.
        if ch >= "0" && ch <= "9"
          stop, val, lit, raw = IntLiteral.lex_number("java", source, i, lex, file_name, start_line, start_col)
          col += stop - i
          i = stop
          tokens << JavaToken.new(kind: JavaTokens::TOK_NUMBER, value: val, line: start_line, col: start_col,
                                  raw: raw, neg_only: lit&.neg_only || false)
          next
        end

        # Identifier / keyword
        if java_ident_start?(ch)
          id_start = i
          while i < n && java_ident_part?(source[i])
            i += 1
            col += 1
          end
          word = source[id_start...i]
          kw = JAVA_KEYWORDS[word]
          if kw
            tokens << JavaToken.new(kind: kw, value: word, line: start_line, col: start_col)
          else
            tokens << JavaToken.new(kind: JavaTokens::TOK_IDENT, value: word, line: start_line, col: start_col)
          end
          next
        end

        # Three-character operators: <<= and >>= (N-134). `>>>` / `>>>=` are
        # not supported and fall through to two-character tokens, as before.
        three = source[i, 3]
        if three == "<<=" || three == ">>="
          kind = three == "<<=" ? JavaTokens::TOK_LSHIFTEQ : JavaTokens::TOK_RSHIFTEQ
          tokens << JavaToken.new(kind: kind, value: three, line: start_line, col: start_col)
          i += 3
          col += 3
          next
        end

        # Two-character operators (check longer first)
        if i + 1 < n
          two = source[i, 2]
          two_kind = case two
                     when "==" then JavaTokens::TOK_EQEQ
                     when "!=" then JavaTokens::TOK_BANGEQ
                     when "<=" then JavaTokens::TOK_LTEQ
                     when ">=" then JavaTokens::TOK_GTEQ
                     when "&&" then JavaTokens::TOK_AMPAMP
                     when "||" then JavaTokens::TOK_PIPEPIPE
                     when "+=" then JavaTokens::TOK_PLUSEQ
                     when "-=" then JavaTokens::TOK_MINUSEQ
                     when "*=" then JavaTokens::TOK_STAREQ
                     when "/=" then JavaTokens::TOK_SLASHEQ
                     when "%=" then JavaTokens::TOK_PERCENTEQ
                     when "&=" then JavaTokens::TOK_AMPEQ
                     when "|=" then JavaTokens::TOK_PIPEEQ
                     when "^=" then JavaTokens::TOK_CARETEQ
                     when "++" then JavaTokens::TOK_PLUSPLUS
                     when "--" then JavaTokens::TOK_MINUSMINUS
                     when "<<" then JavaTokens::TOK_LSHIFT
                     when ">>" then JavaTokens::TOK_RSHIFT
                     end
          if two_kind
            tokens << JavaToken.new(kind: two_kind, value: two, line: start_line, col: start_col)
            i += 2
            col += 2
            next
          end
        end

        # Single-character tokens
        single_kind = case ch
                      when "(" then JavaTokens::TOK_LPAREN
                      when ")" then JavaTokens::TOK_RPAREN
                      when "{" then JavaTokens::TOK_LBRACE
                      when "}" then JavaTokens::TOK_RBRACE
                      when "[" then JavaTokens::TOK_LBRACKET
                      when "]" then JavaTokens::TOK_RBRACKET
                      when ";" then JavaTokens::TOK_SEMI
                      when "," then JavaTokens::TOK_COMMA
                      when "." then JavaTokens::TOK_DOT
                      when ":" then JavaTokens::TOK_COLON
                      when "?" then JavaTokens::TOK_QUESTION
                      when "@" then JavaTokens::TOK_AT
                      when "+" then JavaTokens::TOK_PLUS
                      when "-" then JavaTokens::TOK_MINUS
                      when "*" then JavaTokens::TOK_STAR
                      when "/" then JavaTokens::TOK_SLASH
                      when "%" then JavaTokens::TOK_PERCENT
                      when "<" then JavaTokens::TOK_LT
                      when ">" then JavaTokens::TOK_GT
                      when "&" then JavaTokens::TOK_AMP
                      when "|" then JavaTokens::TOK_PIPE
                      when "^" then JavaTokens::TOK_CARET
                      when "~" then JavaTokens::TOK_TILDE
                      when "!" then JavaTokens::TOK_BANG
                      when "=" then JavaTokens::TOK_EQ
                      end
        if single_kind
          tokens << JavaToken.new(kind: single_kind, value: ch, line: start_line, col: start_col)
          i += 1
          col += 1
          next
        end

        # Skip unknown
        i += 1
        col += 1
      end

      tokens << JavaToken.new(kind: JavaTokens::TOK_EOF, value: "", line: line, col: col)
      tokens
    end

    # -----------------------------------------------------------------------
    # Parser
    # -----------------------------------------------------------------------

    class JavaParser
      include InputLimits::NestingCounter

      include JavaTokens

      INT64_MAX = 9_223_372_036_854_775_807
      INT64_MIN = -9_223_372_036_854_775_808

      def initialize(file_name)
        @file_name = file_name
        @tokens = []
        @pos = 0
        @errors = []
        @contract_name = ""
      end

      attr_accessor :tokens, :pos, :errors

      # -- Error helpers ---------------------------------------------------

      def add_error(msg)
        @errors << Diagnostic.new(message: msg, severity: Severity::ERROR)
      end

      # Fatal parse error: abort the parse like the Java reference does.
      def fatal(msg)
        raise RuntimeError, msg
      end

      # -- Token helpers ---------------------------------------------------

      def peek
        return @tokens[@pos] if @pos < @tokens.length

        JavaToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
      end

      def peek_next
        idx = @pos + 1
        return @tokens[idx] if idx < @tokens.length

        JavaToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
      end

      def advance
        tok = peek
        @pos += 1 if @pos < @tokens.length
        tok
      end

      def expect(kind, label = nil)
        tok = advance
        if tok.kind != kind
          name = label || kind.to_s
          fatal("line #{tok.line}: expected #{name}, got #{tok.value.inspect}")
        end
        tok
      end

      def check(kind)
        peek.kind == kind
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

      def loc_at(tok)
        SourceLocation.new(file: @file_name, line: tok.line, column: tok.col)
      end

      # -- Top-level parsing ------------------------------------------------

      def parse_contract
        skip_package_and_imports

        class_tok = nil
        modifiers_seen = false
        # Skip top-level annotations/modifiers on the class itself
        while !check(TOK_EOF)
          if check(TOK_AT)
            # Skip annotation
            parse_annotation
            modifiers_seen = true
            next
          end
          if JAVA_MODIFIER_KINDS.include?(peek.kind)
            advance
            modifiers_seen = true
            next
          end
          if check(TOK_CLASS)
            class_tok = peek
            break
          end
          # Unknown top-level token: advance to avoid infinite loop
          advance
        end

        if class_tok.nil?
          fatal("no class declaration found in #{@file_name}")
        end

        expect(TOK_CLASS, "'class'")
        class_name_tok = expect(TOK_IDENT, "class name")
        @contract_name = class_name_tok.value

        # extends <BaseClass>
        parent_class = nil
        if check(TOK_EXTENDS)
          advance
          base_name = expect_type_simple_name
          parent_class = case base_name
                         when "SmartContract"         then "SmartContract"
                         when "StatefulSmartContract" then "StatefulSmartContract"
                         when "UnsafeSmartContract"   then "UnsafeSmartContract"
                         else
                           fatal("contract class in #{@file_name} must extend " \
                                 "SmartContract, StatefulSmartContract, or UnsafeSmartContract, got #{base_name}")
                         end
        else
          fatal("contract class in #{@file_name} must extend " \
                "SmartContract, StatefulSmartContract, or UnsafeSmartContract")
        end

        # Skip implements clause (parity with Java compiler: disallowed by
        # validator, but we accept it at parse time to match JavaParser.java
        # which runs javac first).
        if check(TOK_IMPLEMENTS)
          advance
          expect_type_simple_name
          while match_tok(TOK_COMMA)
            expect_type_simple_name
          end
        end

        expect(TOK_LBRACE, "'{'")

        properties = []
        constructor_method = nil
        methods = []

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          member = parse_class_member
          next if member.nil?

          if member[:kind] == :property
            properties << member[:node]
          elsif member[:kind] == :constructor
            if constructor_method
              fatal("#{@contract_name} has more than one constructor")
            end
            constructor_method = member[:node]
          elsif member[:kind] == :method
            methods << member[:node]
          end
        end
        expect(TOK_RBRACE, "'}'")

        constructor = constructor_method || synthetic_constructor(properties)

        contract = ContractNode.new(
          name: @contract_name,
          parent_class: parent_class,
          properties: properties,
          constructor: constructor,
          methods: methods,
          source_file: @file_name
        )
        check_bare_property_assignments(contract)
        contract
      end

      # N-023 (R49). In Java a bare name inside a method that no local or
      # parameter shadows IS the field, so `count = ...`, `count += ...`,
      # `count++` and `--count` write contract state. Lowering them as a local
      # rebind dropped the state write silently, so the bare form is refused
      # (mirrors the TS reference's checkBarePropertyAssignments). Shadowing
      # follows Java block scope: parameters, a local from its declaration to
      # the end of its block, a for-loop variable inside the loop. Bare reads
      # are not touched.
      def check_bare_property_assignments(contract)
        # F-213 measure (B) before the recursive walk below.
        InputLimits.assert_ast_nesting!(contract)
        props = contract.properties.map(&:name)
        return if props.empty?

        ([contract.constructor] + contract.methods).each do |m|
          bare_walk_block(m.body || [], [(m.params || []).map(&:name)], props)
        end
      end

      def bare_check_target(expr, scope, props, loc)
        return unless expr.is_a?(Identifier) && props.include?(expr.name)
        return if scope.any? { |s| s.include?(expr.name) }

        @errors << Diagnostic.new(message: Frontend.bare_java_property_assignment_message(expr.name),
                                  severity: Severity::ERROR, loc: loc)
      end

      def bare_walk_block(body, outer, props)
        scope = outer + [[]]
        body.each { |s| bare_walk_stmt(s, scope, props) }
      end

      def bare_walk_stmt(stmt, scope, props)
        return if stmt.nil?

        loc = stmt.respond_to?(:source_location) ? stmt.source_location : nil
        case stmt
        when VariableDeclStmt
          bare_walk_expr(stmt.init, scope, props, loc)
          scope.last << stmt.name
        when AssignmentStmt
          bare_check_target(stmt.target, scope, props, loc)
          bare_walk_expr(stmt.target, scope, props, loc)
          bare_walk_expr(stmt.value, scope, props, loc)
        when IfStmt
          bare_walk_expr(stmt.condition, scope, props, loc)
          bare_walk_block(stmt.then || [], scope, props)
          bare_walk_block(stmt.else_, scope, props) if stmt.else_
        when ForStmt
          loop_scope = scope + [[]]
          bare_walk_stmt(stmt.init, loop_scope, props)
          bare_walk_expr(stmt.condition, loop_scope, props, loc)
          bare_walk_stmt(stmt.update, loop_scope, props)
          bare_walk_block(stmt.body || [], loop_scope, props)
        when ReturnStmt
          bare_walk_expr(stmt.value, scope, props, loc)
        when ExpressionStmt
          bare_walk_expr(stmt.expr, scope, props, loc)
        end
      end

      def bare_walk_expr(expr, scope, props, loc)
        case expr
        when IncrementExpr, DecrementExpr
          bare_check_target(expr.operand, scope, props, loc)
          bare_walk_expr(expr.operand, scope, props, loc)
        when BinaryExpr
          bare_walk_expr(expr.left, scope, props, loc)
          bare_walk_expr(expr.right, scope, props, loc)
        when UnaryExpr
          bare_walk_expr(expr.operand, scope, props, loc)
        when CallExpr
          bare_walk_expr(expr.callee, scope, props, loc)
          (expr.args || []).each { |a| bare_walk_expr(a, scope, props, loc) }
        when MemberExpr
          bare_walk_expr(expr.object, scope, props, loc)
        when TernaryExpr
          bare_walk_expr(expr.condition, scope, props, loc)
          bare_walk_expr(expr.consequent, scope, props, loc)
          bare_walk_expr(expr.alternate, scope, props, loc)
        when IndexAccessExpr
          bare_walk_expr(expr.object, scope, props, loc)
          bare_walk_expr(expr.index, scope, props, loc)
        when ArrayLiteralExpr
          (expr.elements || []).each { |e| bare_walk_expr(e, scope, props, loc) }
        end
      end

      # -- Package and imports ---------------------------------------------

      def skip_package_and_imports
        if check(TOK_PACKAGE)
          advance
          # Consume dotted identifier to semicolon
          until check(TOK_SEMI) || check(TOK_EOF)
            advance
          end
          match_tok(TOK_SEMI)
        end
        while check(TOK_IMPORT)
          advance
          # Optional static, and dotted identifier(/*), until semicolon
          until check(TOK_SEMI) || check(TOK_EOF)
            advance
          end
          match_tok(TOK_SEMI)
        end
      end

      # -- Annotation parsing -----------------------------------------------

      # Parse an annotation: @Name [(args)]
      # Returns the simple annotation name string. N-093: the argument tokens
      # (`(` ... `)`, or empty) are kept in +@last_annotation_args+ for
      # `@Sighash("FLAGS")`.
      def parse_annotation
        expect(TOK_AT, "'@'")
        name = expect_type_simple_name
        arg_start = @pos
        # Optional annotation arguments (consumed; only @Sighash reads them).
        if check(TOK_LPAREN)
          advance
          depth = 1
          while depth > 0 && !check(TOK_EOF)
            case peek.kind
            when TOK_LPAREN then depth += 1
            when TOK_RPAREN
              depth -= 1
              advance
              break if depth == 0

              next
            end
            advance
          end
        end
        @last_annotation_args = @tokens[arg_start...@pos] || []
        name
      end

      # Parse a simple dotted type name and return its rightmost simple name.
      # For "com.foo.Bar" -> "Bar".
      def expect_type_simple_name
        first = expect(TOK_IDENT, "type name")
        simple = first.value
        while check(TOK_DOT) && peek_next.kind == TOK_IDENT
          advance # .
          simple = advance.value
        end
        simple
      end

      # -- Class member parsing --------------------------------------------

      # Returns { kind: :property|:method|:constructor, node: ... } or nil.
      def parse_class_member
        member_loc = loc
        readonly = false
        is_public_annotated = false
        is_stateful_annotated = false
        # N-093: `@EmbedAlways` / `@Sighash("FLAGS")`, the native spellings of
        # the `@embedAlways` / `@sighash` directives.
        embed_always_loc = nil
        sighash_specs = []
        sighash_loc = nil

        # Annotations. F-205: an annotation whose simple name Rúnar does not
        # recognize is a loud "unsupported annotation" diagnostic, matching
        # the TS reference (01-parse-java.ts, parseMember) — never a silent
        # visibility downgrade.
        while check(TOK_AT)
          ann_loc = loc
          ann_name = parse_annotation
          args = @last_annotation_args
          case ann_name
          when "Readonly" then readonly = true
          when "Public"   then is_public_annotated = true
          when "Stateful" then is_stateful_annotated = true
          when "EmbedAlways" then embed_always_loc = ann_loc
          when "Sighash"
            sighash_loc ||= ann_loc
            sighash_specs << (args.length == 3 && args[1].kind == TOK_STRING ? args[1].value : nil)
          when "Override", "SuppressWarnings"
            # accepted but ignored
          else
            @errors << Diagnostic.new(message: "unsupported annotation @#{ann_name}",
                                      severity: Severity::ERROR, loc: ann_loc)
          end
        end

        # Modifiers (public/private/protected/static/final/abstract)
        is_static = false
        while JAVA_MODIFIER_KINDS.include?(peek.kind)
          is_static = true if peek.kind == TOK_STATIC
          advance
        end

        # Skip stray semicolons (empty member declarations)
        return nil if match_tok(TOK_SEMI)

        # Constructor: IDENT == class name, followed by (
        if check(TOK_IDENT) && peek.value == @contract_name && peek_next.kind == TOK_LPAREN
          advance # ctor name
          ctor = parse_method_body(is_constructor: true, visibility: "public",
                                    location: member_loc)
          # N-093: the constructor is neither a spending entry point nor a field.
          unless sighash_loc.nil?
            @errors << Diagnostic.new(message: SighashDirective.lost_directive_message("@sighash"),
                                      severity: Severity::ERROR, loc: sighash_loc)
          end
          unless embed_always_loc.nil?
            @errors << Diagnostic.new(message: SighashDirective.lost_directive_message("@embedAlways"),
                                      severity: Severity::ERROR, loc: embed_always_loc)
          end
          return { kind: :constructor, node: ctor }
        end

        # A member starts with a type. That type can be:
        #   void                       -> method
        #   boolean / BigInteger / etc -> field or method
        # Parse a type, then decide based on whether the next token after
        # the IDENT is '(' (method) or ';'/'=' (field).

        type_node = parse_type
        name_tok = expect(TOK_IDENT, "member name")
        name = name_tok.value

        if check(TOK_LPAREN)
          # Method
          if is_static
            # N-050: a static method is not a contract method (`@Public
            # static` used to become a spending entry point).
            @errors << Diagnostic.new(message: Frontend.static_method_message(name),
                                      severity: Severity::ERROR, loc: member_loc)
          end
          visibility = is_public_annotated ? "public" : "private"
          method = parse_method_body(
            is_constructor: false,
            method_name: name,
            return_type: type_node,
            visibility: visibility,
            location: member_loc
          )
          unless embed_always_loc.nil?
            @errors << Diagnostic.new(message: SighashDirective.lost_directive_message("@embedAlways"),
                                      severity: Severity::ERROR, loc: embed_always_loc)
          end
          sighash = SighashDirective.resolve_native_sighash(name, is_public_annotated, sighash_specs)
          if sighash && sighash[:error]
            @errors << Diagnostic.new(message: sighash[:error], severity: Severity::ERROR, loc: member_loc)
          elsif sighash
            method.sighash_type = sighash[:value]
          end
          return { kind: :method, node: method }
        end
        unless sighash_loc.nil?
          @errors << Diagnostic.new(message: SighashDirective.lost_directive_message("@sighash"),
                                    severity: Severity::ERROR, loc: sighash_loc)
        end

        # Field: optional initializer, terminated by ';'
        initializer = nil
        if match_tok(TOK_EQ)
          initializer = parse_expression
        end
        expect(TOK_SEMI, "';'")

        prop = PropertyNode.new(
          name: name,
          type: type_node,
          readonly: readonly,
          initializer: initializer,
          embed_always: !embed_always_loc.nil?,
          source_location: member_loc
        )
        { kind: :property, node: prop }
      end

      # Parse parameter list and method body.
      def parse_method_body(is_constructor:, visibility:, location:,
                            method_name: nil, return_type: nil)
        # The AST keeps no return type; N-331 refuses an unknown name.
        Frontend.reject_unknown_return_type(@errors, return_type, method_name, location) unless is_constructor
        expect(TOK_LPAREN, "'('")
        params = []
        while !check(TOK_RPAREN) && !check(TOK_EOF)
          # Optional 'final' modifier on parameter
          advance if check(TOK_FINAL)
          p_type = parse_type
          p_name_tok = expect(TOK_IDENT, "parameter name")
          params << ParamNode.new(name: p_name_tok.value, type: p_type)
          break unless match_tok(TOK_COMMA)
        end
        expect(TOK_RPAREN, "')'")

        # Optional 'throws' clause -- consume identifiers until body/semicolon.
        if check(TOK_IDENT) && peek.value == "throws"
          advance
          while check(TOK_IDENT)
            advance
            match_tok(TOK_COMMA)
          end
        end

        expect(TOK_LBRACE, "'{'")
        body = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          stmt = parse_statement
          body << stmt if stmt
        end
        expect(TOK_RBRACE, "'}'")

        name = is_constructor ? "constructor" : method_name
        MethodNode.new(
          name: name,
          params: params,
          body: body,
          visibility: visibility,
          source_location: location
        )
      end

      # Build an auto-generated constructor when the source omits one.
      def synthetic_constructor(properties)
        default_loc = SourceLocation.new(file: @file_name, line: 0, column: 0)
        uninit_props = properties.reject { |p| p.initializer }

        params = uninit_props.map { |p| ParamNode.new(name: p.name, type: p.type) }

        super_args = uninit_props.map { |p| Identifier.new(name: p.name) }
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

      # -- Type parsing -----------------------------------------------------

      # Parse a Java type: primitive, identifier (dotted), or generic
      # FixedArray<T, N>. Returns a TypeNode.
      def parse_type
        if match_tok(TOK_VOID)
          return PrimitiveType.new(name: "void")
        end

        tok = peek
        unless tok.kind == TOK_IDENT
          fatal("line #{tok.line}: expected type name, got #{tok.value.inspect}")
        end

        # Dotted type name -- take the rightmost simple name for mapping.
        simple = expect_type_simple_name

        # Generic: FixedArray<T, N>
        if check(TOK_LT)
          if simple == "FixedArray"
            advance # <
            element = nested { parse_type }
            expect(TOK_COMMA, "','")
            # Length must be an integer literal
            if !check(TOK_NUMBER)
              fatal("FixedArray length must be an integer literal in #{@file_name}")
            end
            len_tok = advance
            length = begin
              Integer(len_tok.value, 0)
            rescue ArgumentError
              fatal("FixedArray length must be an integer literal in #{@file_name}")
            end
            expect(TOK_GT, "'>'")
            return FixedArrayType.new(element: element, length: length)
          end
          # Any other generic rejected: parity with JavaParser.java
          fatal("unsupported generic type #{simple} in #{@file_name}")
        end

        Frontend.java_map_type(simple)
      end

      # -- Statement parsing ------------------------------------------------

      def parse_statement
        nested { parse_statement_inner }
      end

      def parse_statement_inner
        location = loc

        # N-053: an empty statement `;` is a no-op, as in the TS reference.
        if check(TOK_SEMI)
          advance
          return nil
        end

        # return [expr];
        if check(TOK_RETURN)
          advance
          value = nil
          if !check(TOK_SEMI) && !check(TOK_EOF)
            value = parse_expression
          end
          match_tok(TOK_SEMI)
          return ReturnStmt.new(value: value, source_location: location)
        end

        # if (...) ... [else ...]
        if check(TOK_IF)
          return parse_if_statement(location)
        end

        # for (init; cond; update) body
        if check(TOK_FOR)
          return parse_for_statement(location)
        end

        # Block -- flatten to its statements. (The Java reference explicitly
        # rejects bare nested blocks; here we flatten for tolerance, but
        # inside if/for bodies we handle blocks directly in their parsers.)
        if check(TOK_LBRACE)
          fatal("nested blocks are unsupported in #{@file_name} " \
                "(line #{peek.line})")
        end

        # Heuristic: variable declaration vs. expression statement.
        # A variable declaration starts with a type token followed by an
        # identifier and then one of '=' or ';'. Since the parser has no
        # symbol table, we disambiguate by looking ahead.
        if looks_like_var_decl?
          return parse_variable_decl(location)
        end

        # Expression statement (maybe an assignment)
        expr = parse_expression
        return build_expression_stmt(expr, location)
      end

      # Look ahead to decide whether the next tokens form a local variable
      # declaration: Type IDENT ('=' | ';'), with possible generics/dots.
      def looks_like_var_decl?
        save = @pos
        ok = false
        begin
          # void is not a legal local var type, but harmless to peek.
          return false if check(TOK_VOID)

          return false unless check(TOK_IDENT)

          advance # first ident
          # Dotted name
          while check(TOK_DOT) && peek_next.kind == TOK_IDENT
            advance
            advance
          end
          # Optional generic: <...> with matched <>
          if check(TOK_LT)
            depth = 0
            # Only attempt to match a closing > if what follows looks like a
            # generic type list (a rough heuristic: first token after '<' is
            # an identifier or another '<').
            lookahead = peek_next
            return false unless lookahead.kind == TOK_IDENT ||
                                lookahead.kind == TOK_LT ||
                                lookahead.kind == TOK_NUMBER

            while !check(TOK_EOF)
              case peek.kind
              when TOK_LT
                depth += 1
                advance
              when TOK_GT
                depth -= 1
                advance
                break if depth == 0
              else
                advance
              end
            end
          end

          # Now we expect IDENT
          return false unless check(TOK_IDENT)

          advance # var name
          if check(TOK_EQ) || check(TOK_SEMI)
            ok = true
          end
        ensure
          @pos = save
        end
        ok
      end

      def parse_variable_decl(location)
        type_node = parse_type
        name_tok = expect(TOK_IDENT, "variable name")
        expect(TOK_EQ, "'='")
        init = parse_expression
        expect(TOK_SEMI, "';'")
        VariableDeclStmt.new(
          name: name_tok.value,
          type: type_node,
          mutable: true,
          init: init,
          source_location: location
        )
      end

      # N-134: compound assignment token -> binary operator, exactly TS's ten
      # (01-parse-java.ts finishExpressionStatement). `t op= e` lowers to
      # `t = t op e`.
      COMPOUND_OPS = {
        TOK_PLUSEQ    => "+",
        TOK_MINUSEQ   => "-",
        TOK_STAREQ    => "*",
        TOK_SLASHEQ   => "/",
        TOK_PERCENTEQ => "%",
        TOK_AMPEQ     => "&",
        TOK_PIPEEQ    => "|",
        TOK_CARETEQ   => "^",
        TOK_LSHIFTEQ  => "<<",
        TOK_RSHIFTEQ  => ">>",
      }.freeze

      # Turn a top-level expression into a statement, handling assignments
      # and postfix ++/-- as statement forms.
      def build_expression_stmt(expr, location)
        # Plain '=' assignment
        if match_tok(TOK_EQ)
          value = parse_expression
          expect(TOK_SEMI, "';'")
          return AssignmentStmt.new(
            target: expr, value: value, source_location: location
          )
        end

        # Compound assignments
        COMPOUND_OPS.each do |kind, bin_op|
          if match_tok(kind)
            rhs = parse_expression
            expect(TOK_SEMI, "';'")
            return AssignmentStmt.new(
              target: expr,
              value: BinaryExpr.new(op: bin_op, left: expr, right: rhs),
              source_location: location
            )
          end
        end

        # Postfix ++ / -- as statement
        if match_tok(TOK_PLUSPLUS)
          expect(TOK_SEMI, "';'")
          return ExpressionStmt.new(
            expr: IncrementExpr.new(operand: expr, prefix: false),
            source_location: location
          )
        end
        if match_tok(TOK_MINUSMINUS)
          expect(TOK_SEMI, "';'")
          return ExpressionStmt.new(
            expr: DecrementExpr.new(operand: expr, prefix: false),
            source_location: location
          )
        end

        expect(TOK_SEMI, "';'")
        ExpressionStmt.new(expr: expr, source_location: location)
      end

      def parse_if_statement(location)
        expect(TOK_IF, "'if'")
        expect(TOK_LPAREN, "'('")
        condition = parse_expression
        expect(TOK_RPAREN, "')'")

        then_block = parse_block_or_single_statement

        else_block = nil
        if match_tok(TOK_ELSE)
          if check(TOK_IF)
            # +1 as a statement of the else branch: the TS reference reaches
            # this if through parseBlockOrSingle -> parseStatement.
            else_block = [nested { parse_if_statement(loc) }]
          else
            else_block = parse_block_or_single_statement
          end
        end

        IfStmt.new(
          condition: condition,
          then: then_block,
          else_: else_block || [],
          source_location: location
        )
      end

      def parse_block_or_single_statement
        if match_tok(TOK_LBRACE)
          block = []
          while !check(TOK_RBRACE) && !check(TOK_EOF)
            stmt = parse_statement
            block << stmt if stmt
          end
          expect(TOK_RBRACE, "'}'")
          return block
        end
        stmt = parse_statement
        stmt ? [stmt] : []
      end

      # for (init; cond; update) body
      def parse_for_statement(location)
        expect(TOK_FOR, "'for'")
        expect(TOK_LPAREN, "'('")

        # Init: must be a variable declaration (for loop variable).
        unless looks_like_var_decl?
          fatal("for-loop must declare a single loop variable in #{@file_name}")
        end
        init_stmt = parse_variable_decl(loc)

        # Condition
        condition = parse_expression
        expect(TOK_SEMI, "';'")

        # Update expression (single)
        update_loc = loc
        update_expr = parse_expression
        if match_tok(TOK_PLUSPLUS)
          update = ExpressionStmt.new(
            expr: IncrementExpr.new(operand: update_expr, prefix: false),
            source_location: update_loc
          )
        elsif match_tok(TOK_MINUSMINUS)
          update = ExpressionStmt.new(
            expr: DecrementExpr.new(operand: update_expr, prefix: false),
            source_location: update_loc
          )
        elsif match_tok(TOK_EQ)
          rhs = parse_expression
          update = AssignmentStmt.new(
            target: update_expr, value: rhs, source_location: update_loc
          )
        elsif (bin_op = COMPOUND_OPS[peek.kind])
          advance
          rhs = parse_expression
          update = AssignmentStmt.new(
            target: update_expr,
            value: BinaryExpr.new(op: bin_op, left: update_expr, right: rhs),
            source_location: update_loc
          )
        else
          update = ExpressionStmt.new(
            expr: update_expr, source_location: update_loc
          )
        end

        expect(TOK_RPAREN, "')'")

        body = parse_block_or_single_statement

        ForStmt.new(
          init: init_stmt,
          condition: condition,
          update: update,
          body: body,
          source_location: location
        )
      end

      # -- Expression parsing (precedence climbing) -----------------------
      # Java precedence (low to high):
      #   ternary (? :)
      #   || &&
      #   |, ^, &
      #   ==, !=
      #   <, <=, >, >=
      #   <<, >>
      #   +, -
      #   *, /, %
      #   unary (! - ~ prefix ++ --)
      #   postfix (. [] () postfix ++ --)

      def parse_expression
        nested { parse_ternary }
      end

      def parse_ternary
        cond = parse_or
        if match_tok(TOK_QUESTION)
          consequent = parse_expression
          expect(TOK_COLON, "':'")
          alternate = parse_expression
          return TernaryExpr.new(
            condition: cond,
            consequent: consequent,
            alternate: alternate
          )
        end
        cond
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
        left = parse_bit_or
        while match_tok(TOK_AMPAMP)
          right = parse_bit_or
          left = BinaryExpr.new(op: "&&", left: left, right: right)
        end
        left
      end

      def parse_bit_or
        left = parse_bit_xor
        while match_tok(TOK_PIPE)
          right = parse_bit_xor
          left = BinaryExpr.new(op: "|", left: left, right: right)
        end
        left
      end

      def parse_bit_xor
        left = parse_bit_and
        while match_tok(TOK_CARET)
          right = parse_bit_and
          left = BinaryExpr.new(op: "^", left: left, right: right)
        end
        left
      end

      def parse_bit_and
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
            left = fold_compare_to_zero("===", left, parse_comparison)
          elsif match_tok(TOK_BANGEQ)
            left = fold_compare_to_zero("!==", left, parse_comparison)
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
            left = fold_compare_to_zero("<", left, parse_shift)
          elsif match_tok(TOK_LTEQ)
            left = fold_compare_to_zero("<=", left, parse_shift)
          elsif match_tok(TOK_GT)
            left = fold_compare_to_zero(">", left, parse_shift)
          elsif match_tok(TOK_GTEQ)
            left = fold_compare_to_zero(">=", left, parse_shift)
          else
            break
          end
        end
        left
      end

      # Fold +<a>.compareTo(<b>) <cmp> 0+ to +<a> <cmp> <b>+ (and the
      # symmetric +0 <cmp> <a>.compareTo(<b>)+ to +<b> <cmp> <a>+). Java's
      # +BigInteger#compareTo+ returns -1/0/1, so the comparison-against-zero
      # idiom is the standard JDK spelling for ordered comparison on
      # BigInteger; we collapse to a single BinaryExpr so the canonical
      # Rúnar AST matches the IR produced by +<a> <cmp> <b>+ in other
      # formats. Any other shape leaves +compareTo+ as an unknown call
      # (which the typechecker rejects loudly).
      def fold_compare_to_zero(op, left, right)
        if left_pair = compare_to_receiver_arg(left)
          if right.is_a?(BigIntLiteral) && right.value == 0
            return BinaryExpr.new(op: op, left: left_pair[0], right: left_pair[1])
          end
        end
        if right_pair = compare_to_receiver_arg(right)
          if left.is_a?(BigIntLiteral) && left.value == 0
            return BinaryExpr.new(op: op, left: right_pair[1], right: right_pair[0])
          end
        end
        BinaryExpr.new(op: op, left: left, right: right)
      end

      def compare_to_receiver_arg(e)
        return nil unless e.is_a?(CallExpr)
        return nil unless e.callee.is_a?(MemberExpr)
        return nil unless e.callee.property == "compareTo" && e.args.length == 1
        [e.callee.object, e.args[0]]
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
          return UnaryExpr.new(op: "!", operand: nested { parse_unary })
        end
        if match_tok(TOK_MINUS)
          # F-026 / JLS 3.10.1: `2147483648` and `9223372036854775808L` are
          # legal only as the direct operand of this minus.
          peek.neg_only = false if check(TOK_NUMBER)
          return UnaryExpr.new(op: "-", operand: nested { parse_unary })
        end
        if match_tok(TOK_PLUS)
          # Unary plus is a no-op in Java (+x == x).
          return nested { parse_unary }
        end
        if match_tok(TOK_TILDE)
          return UnaryExpr.new(op: "~", operand: nested { parse_unary })
        end
        if match_tok(TOK_PLUSPLUS)
          return IncrementExpr.new(operand: nested { parse_unary }, prefix: true)
        end
        if match_tok(TOK_MINUSMINUS)
          return DecrementExpr.new(operand: nested { parse_unary }, prefix: true)
        end
        parse_postfix(parse_primary)
      end

      def parse_postfix(expr)
        loop do
          if match_tok(TOK_DOT)
            prop_tok = expect(TOK_IDENT, "member name")
            prop = prop_tok.value
            if check(TOK_LPAREN)
              args = parse_call_args
              # Special-case BigInteger.valueOf(<int>) -> BigIntLiteral,
              # and xxx.fromHex("hex") -> ByteStringLiteral.
              lit = try_lower_special_call(expr, prop, args)
              if lit
                expr = lit
                next
              end

              expr = CallExpr.new(
                callee: MemberExpr.new(object: expr, property: prop),
                args: args
              )
              next
            end

            # Special-case BigInteger.{ZERO,ONE,TWO,TEN} or
            # Bigint.{ZERO,ONE,TWO,TEN} -> BigIntLiteral. The Bigint
            # wrapper re-exports BigInteger's constants so both spellings
            # are accepted (matches JavaParser.convertExpression).
            if expr.is_a?(Identifier) && (expr.name == "BigInteger" || expr.name == "Bigint")
              big = case prop
                    when "ZERO" then 0
                    when "ONE"  then 1
                    when "TWO"  then 2
                    when "TEN"  then 10
                    end
              if big
                expr = BigIntLiteral.new(value: big)
                next
              end
            end

            # this.foo -> PropertyAccessExpr
            if expr.is_a?(Identifier) && expr.name == "this"
              expr = PropertyAccessExpr.new(property: prop)
            else
              expr = MemberExpr.new(object: expr, property: prop)
            end
          elsif check(TOK_LPAREN) && callable?(expr)
            args = parse_call_args
            # Static-imported `assertThat(cond)` is a builtin alias for
            # `assert` in the canonical Java BuiltinRegistry. Peer
            # typecheckers only know `assert`, so rewrite the callee here.
            if expr.is_a?(Identifier) && expr.name == "assertThat"
              expr = CallExpr.new(callee: Identifier.new(name: "assert"), args: args)
            else
              expr = CallExpr.new(callee: expr, args: args)
            end
          elsif match_tok(TOK_LBRACKET)
            index = parse_expression
            expect(TOK_RBRACKET, "']'")
            expr = IndexAccessExpr.new(object: expr, index: index)
          elsif match_tok(TOK_PLUSPLUS)
            expr = IncrementExpr.new(operand: expr, prefix: false)
          elsif match_tok(TOK_MINUSMINUS)
            expr = DecrementExpr.new(operand: expr, prefix: false)
          else
            break
          end
        end
        expr
      end

      # Bigint-wrapper method-name -> canonical Rúnar BinaryOp string. Mirrors
      # JavaParser.BIGINT_BINARY_METHODS; unary +neg+/+abs+ are handled at the
      # call site. Receiver type is not consulted; the typechecker rejects
      # misuse.
      #
      # The map covers two spellings:
      # * Bigint wrapper (plus, minus, times, div, mod, shl, shr, ...)
      # * JDK BigInteger (add, subtract, multiply, divide, shiftLeft, shiftRight)
      # Both lower to the same canonical BinaryExpr.
      BIGINT_BINARY_METHODS = {
        # Bigint wrapper spellings.
        "plus"  => "+",
        "minus" => "-",
        "times" => "*",
        "div"   => "/",
        "mod"   => "%",
        "shl"   => "<<",
        "shr"   => ">>",
        "and"   => "&",
        "or"    => "|",
        "xor"   => "^",
        "gt"    => ">",
        "lt"    => "<",
        "ge"    => ">=",
        "le"    => "<=",
        "eq"    => "===",
        "neq"   => "!==",
        # JDK BigInteger spellings.
        "add"        => "+",
        "subtract"   => "-",
        "multiply"   => "*",
        "divide"     => "/",
        "shiftLeft"  => "<<",
        "shiftRight" => ">>",
      }.freeze

      # Recognise special calls on a member:
      #   xxx.fromHex("deadbeef")             -> ByteStringLiteral("deadbeef")
      #   BigInteger.valueOf(<int literal>)   -> BigIntLiteral(n)
      #   Bigint.of(<int literal>)            -> BigIntLiteral(n)
      #   Bigint.of(<expr>)                   -> <expr>   (identity wrap)
      #   BigInteger.valueOf(<expr>)          -> <expr>   (identity wrap)
      #   <expr>.value()                      -> <expr>   (identity unwrap)
      #   a.plus(b) / a.minus(b) / ...        -> BinaryExpr (Bigint arith)
      #   a.neg()                             -> UnaryExpr(-)
      #   a.abs()                             -> CallExpr(abs, a)
      # Returns the lowered expression or nil if none applies.
      def try_lower_special_call(object, method_name, args)
        if method_name == "fromHex" && args.length == 1
          arg = args[0]
          if arg.is_a?(ByteStringLiteral)
            return ByteStringLiteral.new(value: arg.value)
          end
          # fromHex with a non-literal string is not supported here; fall
          # through to a regular call expression.
        end
        # BigInteger.valueOf(<int literal>) / Bigint.of(<int literal>) -> BigIntLiteral.
        # Both the bare `BigInteger.valueOf` and the fully-qualified
        # `java.math.BigInteger.valueOf` spellings are accepted.
        if args.length == 1 && args[0].is_a?(BigIntLiteral) &&
           (java_biginteger_value_of?(object, method_name) ||
            java_bigint_of?(object, method_name))
          return BigIntLiteral.new(value: args[0].value)
        end
        # Bigint.of(<arbitrary expression>) / BigInteger.valueOf(<arbitrary expression>)
        # — identity at the Rúnar AST level. Bigint and BigInteger collapse to
        # the same BIGINT primitive, so the wrap is a no-op: lower to the
        # inner expression. Mirrors JavaParser.java's identity branch. Both
        # bare and `java.math.BigInteger.valueOf` are accepted.
        if args.length == 1 &&
           (java_biginteger_value_of?(object, method_name) ||
            java_bigint_of?(object, method_name))
          return args[0]
        end
        # <expr>.value() — unwrapping a Bigint back to its underlying
        # BigInteger. Symmetric no-op to Bigint.of(...) above.
        if method_name == "value" && args.empty?
          return object
        end
        # <expr>.toByteString() — Java-side coercion of Point / Bigint / Sig /
        # PubKey wrappers to their raw byte form. Runar Point is structurally
        # a ByteString so the TS canonical sources pass Points directly to
        # builtins like `cat`. Lower to a no-op (drop the call, keep the
        # receiver) so the Java IR matches the canonical IR byte-for-byte.
        if method_name == "toByteString" && args.empty?
          return object
        end
        # Bigint-wrapper arithmetic: a.plus(b) -> BinaryExpr(+, a, b),
        # a.neg() -> UnaryExpr(-, a), a.abs() -> CallExpr(abs, a). Matched by
        # method name + arity; receiver type is not consulted (parser has no
        # type info at this stage); the typechecker rejects misuse. Mirrors
        # JavaParser.tryLowerBigintMethod.
        if args.length == 1 && (op = BIGINT_BINARY_METHODS[method_name])
          return BinaryExpr.new(op: op, left: object, right: args[0])
        end
        if args.empty? && (method_name == "neg" || method_name == "negate")
          return UnaryExpr.new(op: "-", operand: object)
        end
        # a.not() -> UnaryExpr(~, a). Mirrors java.math.BigInteger#not(); the
        # Bigint wrapper exposes the same method so Runar Java sources can use
        # it natively.
        if args.empty? && method_name == "not"
          return UnaryExpr.new(op: "~", operand: object)
        end
        if args.empty? && method_name == "abs"
          return CallExpr.new(callee: Identifier.new(name: "abs"), args: [object])
        end
        # <expr>.equals(<expr>) — Java's value-equality method. Lower to the
        # canonical BinaryExpr(===, a, b). Receiver type is not consulted; the
        # typechecker rejects misuse.
        if args.length == 1 && method_name == "equals"
          return BinaryExpr.new(op: "===", left: object, right: args[0])
        end
        nil
      end

      # True if +object+/+method+ name +BigInteger.valueOf+ or the
      # fully-qualified +java.math.BigInteger.valueOf+.
      def java_biginteger_value_of?(object, method_name)
        return false unless method_name == "valueOf"
        return true if object.is_a?(Identifier) && object.name == "BigInteger"
        # java.math.BigInteger
        return false unless object.is_a?(MemberExpr) && object.property == "BigInteger"
        return false unless object.object.is_a?(MemberExpr) && object.object.property == "math"
        object.object.object.is_a?(Identifier) && object.object.object.name == "java"
      end

      # True if +object+/+method+ name +Bigint.of+.
      def java_bigint_of?(object, method_name)
        method_name == "of" && object.is_a?(Identifier) && object.name == "Bigint"
      end

      def callable?(expr)
        expr.is_a?(Identifier) || expr.is_a?(MemberExpr) || expr.is_a?(PropertyAccessExpr)
      end

      def parse_call_args
        expect(TOK_LPAREN, "'('")
        args = []
        while !check(TOK_RPAREN) && !check(TOK_EOF)
          args << parse_expression
          break unless match_tok(TOK_COMMA)
        end
        expect(TOK_RPAREN, "')'")
        args
      end

      def parse_primary
        tok = peek

        # Parenthesized expression
        if tok.kind == TOK_LPAREN
          advance
          expr = parse_expression
          expect(TOK_RPAREN, "')'")
          return expr
        end

        # Number literal -> BigIntLiteral (Rúnar has no Number type)
        if tok.kind == TOK_NUMBER
          @errors << Frontend.lex_error(IntLiteral.invalid_integer_literal("java", tok.raw), @file_name, tok.line, tok.col) if tok.neg_only
          advance
          return parse_number(tok.value)
        end

        # String literal -- bare strings are rejected, parity with Java.
        if tok.kind == TOK_STRING
          # Accept string literals as ByteStringLiteral with the raw hex string
          # when the caller is fromHex(...). Outside that context, reject.
          # The postfix layer rewrites X.fromHex("hex") by consuming this
          # ByteStringLiteral as the sole arg. If seen standalone, callers
          # downstream will reject it at typecheck. We emit a ByteStringLiteral
          # so that the common fromHex use-case works byte-for-byte with
          # the authoritative Java parser.
          advance
          return ByteStringLiteral.new(value: tok.value)
        end

        # Character literal -- rejected.
        if tok.kind == TOK_CHAR
          fatal(JAVA_CHAR_LITERAL)
        end

        # Booleans
        if tok.kind == TOK_TRUE
          advance
          return BoolLiteral.new(value: true)
        end
        if tok.kind == TOK_FALSE
          advance
          return BoolLiteral.new(value: false)
        end

        # null -- rejected.
        if tok.kind == TOK_NULL
          fatal("null literals are unsupported in #{@file_name}")
        end

        # this / super
        if tok.kind == TOK_THIS
          advance
          return Identifier.new(name: "this")
        end
        if tok.kind == TOK_SUPER
          advance
          return Identifier.new(name: "super")
        end

        # new Type[] { ... } or new Type[n] -- we only support the array
        # initializer form, which we lower to ArrayLiteralExpr. Any other
        # 'new' use is rejected.
        if tok.kind == TOK_NEW
          advance
          # `new T[] { expr, ... }` array literal OR
          # `new BigInteger("decimal" [, radix])` oversize-bigint escape hatch.
          first_name_tok = expect(TOK_IDENT, "type name after 'new'")
          final_name = first_name_tok.value
          while check(TOK_DOT) && peek_next.kind == TOK_IDENT
            advance # '.'
            seg = peek
            advance # ident
            final_name = seg.value
          end
          # Optional generic <...>
          if match_tok(TOK_LT)
            depth = 1
            while depth > 0 && !check(TOK_EOF)
              case peek.kind
              when TOK_LT then depth += 1
              when TOK_GT then depth -= 1
              end
              advance
            end
          end
          # `new BigInteger("decimal" [, radix])` — fold to BigIntLiteral so
          # contracts can express 256-bit constants (e.g. secp256k1 group
          # order) that don't fit in a Java `long`.
          if final_name == "BigInteger" && check(TOK_LPAREN)
            advance
            if peek.kind == TOK_STRING
              str_tok = peek
              advance
              radix = 10
              if match_tok(TOK_COMMA)
                if peek.kind == TOK_NUMBER
                  num_tok = peek
                  advance
                  begin
                    radix = Integer(num_tok.value, 0)
                  rescue ArgumentError
                    radix = 10
                  end
                end
              end
              match_tok(TOK_RPAREN)
              cleaned = str_tok.value.tr("_", "")
              begin
                value = Integer(cleaned, radix)
              rescue ArgumentError => e
                fatal("cannot parse 'new BigInteger(#{str_tok.value.inspect}, #{radix})': #{e.message} in #{@file_name}")
              end
              return BigIntLiteral.new(value: value)
            end
            # Skip balanced parens for diagnostic purposes.
            depth = 1
            while depth > 0 && !check(TOK_EOF)
              case peek.kind
              when TOK_LPAREN then depth += 1
              when TOK_RPAREN then depth -= 1
              end
              advance
            end
            fatal("`new BigInteger(...)` only supports string-literal forms in #{@file_name}")
          end
          # Array markers []
          while check(TOK_LBRACKET)
            advance
            # Consume length expression if present
            parse_expression unless check(TOK_RBRACKET)
            expect(TOK_RBRACKET, "']'")
          end

          if match_tok(TOK_LBRACE)
            elements = []
            while !check(TOK_RBRACE) && !check(TOK_EOF)
              elements << parse_expression
              break unless match_tok(TOK_COMMA)
            end
            expect(TOK_RBRACE, "'}'")
            return ArrayLiteralExpr.new(elements: elements)
          end
          fatal("unsupported 'new' expression in #{@file_name}")
        end

        # Array literal using braces (rare in expression position -- Java
        # allows this only in initializer position, but support it for
        # tolerance).
        if tok.kind == TOK_LBRACE
          advance
          elements = []
          while !check(TOK_RBRACE) && !check(TOK_EOF)
            elements << parse_expression
            break unless match_tok(TOK_COMMA)
          end
          expect(TOK_RBRACE, "'}'")
          return ArrayLiteralExpr.new(elements: elements)
        end

        # Identifier
        if tok.kind == TOK_IDENT
          advance
          return Identifier.new(name: tok.value)
        end

        # Fallback: consume to avoid infinite loop, surface as zero.
        advance
        BigIntLiteral.new(value: 0)
      end

      def parse_number(s)
        base = 10
        text = s
        if text.start_with?("0x", "0X")
          base = 16
          text = text[2..]
        elsif text.start_with?("0b", "0B")
          base = 2
          text = text[2..]
        end
        val = begin
          Integer(text, base)
        rescue ArgumentError
          0
        end
        # No int64 clamp: BigIntLiteral carries arbitrary-precision Integer
        # values end-to-end. _make_load_const_int promotes oversize values to
        # a `"...n"` decimal-string for cross-tier JSON round-trip parity.
        BigIntLiteral.new(value: val)
      end
    end

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    # Parse a Java-syntax Runar contract (.runar.java).
    #
    # @param source [String] the source code
    # @param file_name [String] the file name (used in diagnostics)
    # @return [ParseResult]
    def self.parse_java(source, file_name)
      # F-011: run the parser below and keep its tokenizer's diagnostics.
      # DoS-bound size guard, enforced at every exported parser entry, not
      # just _parse_source. N-136.
      RunarCompiler::Frontend::InputLimits.assert_source_bytes_under_limit(source)
      lex = []
      Frontend.with_lex_errors(
        InputLimits.with_nesting_limit(file_name) { _parse_java_tokens(source, file_name, lex) }, lex
      )
    end

    def self._parse_java_tokens(source, file_name, lex)
      p = JavaParser.new(file_name)
      p.tokens = tokenize_java(source, lex, file_name)
      p.pos = 0

      begin
        contract = p.parse_contract
      rescue InputLimits::SourceNestingError
        raise
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
