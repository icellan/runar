# frozen_string_literal: true

# Ruby format parser (.runar.rb) for the Runar compiler.
#
# Ported from compilers/python/runar_compiler/frontend/parser_ruby.py.
# Hand-written tokenizer + recursive descent parser.
#
# Ruby syntax conventions used in Runar contracts:
#   - +class Foo < Runar::SmartContract+ /
#     +class Foo < Runar::StatefulSmartContract+
#   - +runar_public+ marker for public methods (with optional param types)
#   - +@instance_var+ for property access (maps to +this.prop+)
#   - +prop :name, Type [, readonly: true]+ for typed property declarations
#   - +assert expr+ for assertions (keyword, no parentheses required)
#   - snake_case names converted to camelCase in AST
#   - +and+/+or+/+not+ for boolean operators alongside +&&+/+||+/+!+
#   - +end+ keyword terminates blocks (no significant whitespace)
#   - +unless+ maps to if with negated condition
#   - +for i in 0...n+ / +for i in 0..n+ for bounded loops

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"

module RunarCompiler
  module Frontend
    # -----------------------------------------------------------------------
    # Token types (namespaced to avoid collision with other parsers)
    # -----------------------------------------------------------------------

    module RubyTokens
      TOK_EOF        = 0
      TOK_IDENT      = 1
      TOK_NUMBER     = 2
      TOK_HEXSTRING  = 3   # single-quoted string -> hex ByteString
      TOK_STRING     = 4   # double-quoted string
      TOK_SYMBOL     = 5   # :name
      TOK_IVAR       = 6   # @name
      TOK_LPAREN     = 7   # (
      TOK_RPAREN     = 8   # )
      TOK_LBRACKET   = 9   # [
      TOK_RBRACKET   = 10  # ]
      TOK_COMMA      = 11  # ,
      TOK_DOT        = 12  # .
      TOK_COLON      = 13  # :
      TOK_COLONCOLON = 14  # ::
      TOK_ASSIGN     = 15  # =
      TOK_EQEQ       = 16  # ==
      TOK_NOTEQ      = 17  # !=
      TOK_LT         = 18  # <
      TOK_LTEQ       = 19  # <=
      TOK_GT         = 20  # >
      TOK_GTEQ       = 21  # >=
      TOK_PLUS       = 22  # +
      TOK_MINUS      = 23  # -
      TOK_STAR       = 24  # *
      TOK_SLASH      = 25  # /
      TOK_PERCENT    = 26  # %
      TOK_STARSTAR   = 27  # **
      TOK_BANG       = 28  # !
      TOK_TILDE      = 29  # ~
      TOK_AMP        = 30  # &
      TOK_PIPE       = 31  # |
      TOK_CARET      = 32  # ^
      TOK_AMPAMP     = 33  # &&
      TOK_PIPEPIPE   = 34  # ||
      TOK_LSHIFT     = 35  # <<
      TOK_RSHIFT     = 36  # >>
      TOK_PLUSEQ     = 37  # +=
      TOK_MINUSEQ    = 38  # -=
      TOK_STAREQ     = 39  # *=
      TOK_SLASHEQ    = 40  # /=
      TOK_PERCENTEQ  = 41  # %=
      TOK_DOTDOT     = 42  # ..
      TOK_DOTDOTDOT  = 43  # ...
      TOK_QUESTION   = 44  # ?
      TOK_NEWLINE    = 45

      # Keywords
      TOK_CLASS   = 50
      TOK_DEF     = 51
      TOK_IF      = 52
      TOK_ELSIF   = 53
      TOK_ELSE    = 54
      TOK_UNLESS  = 55
      TOK_FOR     = 56
      TOK_IN      = 57
      TOK_END     = 58
      TOK_RETURN  = 59
      TOK_TRUE    = 60
      TOK_FALSE   = 61
      TOK_NIL     = 62
      TOK_AND     = 63
      TOK_OR      = 64
      TOK_NOT     = 65
      TOK_SUPER   = 66
      TOK_REQUIRE = 67
      TOK_ASSERT  = 68
      TOK_DO      = 69

      KEYWORDS = {
        "class"   => TOK_CLASS,
        "def"     => TOK_DEF,
        "if"      => TOK_IF,
        "elsif"   => TOK_ELSIF,
        "else"    => TOK_ELSE,
        "unless"  => TOK_UNLESS,
        "for"     => TOK_FOR,
        "in"      => TOK_IN,
        "end"     => TOK_END,
        "return"  => TOK_RETURN,
        "true"    => TOK_TRUE,
        "false"   => TOK_FALSE,
        "nil"     => TOK_NIL,
        "and"     => TOK_AND,
        "or"      => TOK_OR,
        "not"     => TOK_NOT,
        "super"   => TOK_SUPER,
        "require" => TOK_REQUIRE,
        "assert"  => TOK_ASSERT,
        "do"      => TOK_DO,
      }.freeze

      # A single token produced by the tokenizer.
      Token = Struct.new(:kind, :value, :line, :col, keyword_init: true)
    end # module RubyTokens (token constants, keywords, Token struct)

    # -----------------------------------------------------------------------
    # Special name mappings (snake_case -> camelCase)
    # -----------------------------------------------------------------------

    SPECIAL_NAMES = {
      "initialize"                 => "constructor",
      "check_sig"                  => "checkSig",
      "check_multi_sig"            => "checkMultiSig",
      "check_preimage"             => "checkPreimage",
      "verify_wots"                => "verifyWOTS",
      "verify_slh_dsa_sha2_128s"   => "verifySLHDSA_SHA2_128s",
      "verify_slh_dsa_sha2_128f"   => "verifySLHDSA_SHA2_128f",
      "verify_slh_dsa_sha2_192s"   => "verifySLHDSA_SHA2_192s",
      "verify_slh_dsa_sha2_192f"   => "verifySLHDSA_SHA2_192f",
      "verify_slh_dsa_sha2_256s"   => "verifySLHDSA_SHA2_256s",
      "verify_slh_dsa_sha2_256f"   => "verifySLHDSA_SHA2_256f",
      "verify_rabin_sig"           => "verifyRabinSig",
      "ec_add"                     => "ecAdd",
      "ec_mul"                     => "ecMul",
      "ec_mul_gen"                 => "ecMulGen",
      "ec_negate"                  => "ecNegate",
      "ec_on_curve"                => "ecOnCurve",
      "ec_mod_reduce"              => "ecModReduce",
      "ec_encode_compressed"       => "ecEncodeCompressed",
      "ec_make_point"              => "ecMakePoint",
      "ec_point_x"                 => "ecPointX",
      "ec_point_y"                 => "ecPointY",
      "add_output"                 => "addOutput",
      "add_raw_output"             => "addRawOutput",
      "get_state_script"           => "getStateScript",
      "extract_locktime"           => "extractLocktime",
      "extract_output_hash"        => "extractOutputHash",
      "extract_amount"             => "extractAmount",
      "extract_version"            => "extractVersion",
      "extract_sequence"           => "extractSequence",
      "extract_nsequence"          => "extractNSequence",
      "extract_hash_prevouts"      => "extractHashPrevouts",
      "extract_hash_sequence"      => "extractHashSequence",
      "extract_outpoint"           => "extractOutpoint",
      "extract_script_code"        => "extractScriptCode",
      "extract_input_index"        => "extractInputIndex",
      "extract_sig_hash_type"      => "extractSigHashType",
      "extract_outputs"            => "extractOutputs",
      "mul_div"                    => "mulDiv",
      "percent_of"                 => "percentOf",
      "reverse_bytes"              => "reverseBytes",
      "safe_div"                   => "safediv",
      "safe_mod"                   => "safemod",
      "div_mod"                    => "divmod",
      # SHA-256 partial verification
      "sha256_compress"            => "sha256Compress",
      "sha256_finalize"            => "sha256Finalize",
      "sha256"                     => "sha256",
      "ripemd160"                  => "ripemd160",
      "hash160"                    => "hash160",
      "hash256"                    => "hash256",
      "num2bin"                    => "num2bin",
      "bin2num"                    => "bin2num",
      "log2"                       => "log2",
      # EC constants -- pass through unchanged
      "EC_P"                       => "EC_P",
      "EC_N"                       => "EC_N",
      "EC_G"                       => "EC_G",
    }.freeze

    # Names that pass through unchanged (no snake_case conversion)
    PASSTHROUGH_NAMES = Set.new(%w[
      bool abs min max len pow cat within
      safediv safemod clamp sign sqrt gcd divmod
      log2 substr
    ]).freeze

    # -----------------------------------------------------------------------
    # snake_case -> camelCase conversion
    # -----------------------------------------------------------------------

    # Convert a snake_case identifier to camelCase.
    #
    # Only capitalizes lowercase letters and digits after underscores, matching
    # the TS reference: +name.replace(/_([a-z0-9])/g, ...)+. This means
    # +EC_P+ passes through unchanged (uppercase P is not matched).
    #
    # Leading underscores are stripped so that +_require_owner+ becomes
    # +requireOwner+ (not +RequireOwner+).
    def self.snake_to_camel(name)
      leading = name.length - name.sub(/\A_+/, "").length
      stripped = leading > 0 ? name[leading..] : name
      stripped.gsub(/_([a-z0-9])/) { ::Regexp.last_match(1).upcase }
    end

    # Map a Ruby snake_case name to its Runar AST callee name.
    def self.map_builtin_name(name)
      return SPECIAL_NAMES[name] if SPECIAL_NAMES.key?(name)
      return name if PASSTHROUGH_NAMES.include?(name)

      snake_to_camel(name)
    end

    # -----------------------------------------------------------------------
    # Type mapping
    # -----------------------------------------------------------------------

    RB_TYPE_MAP = {
      "Bigint"          => "bigint",
      "Integer"         => "bigint",
      "Int"             => "bigint",
      "Boolean"         => "boolean",
      "ByteString"      => "ByteString",
      "PubKey"          => "PubKey",
      "Sig"             => "Sig",
      "Addr"            => "Addr",
      "Sha256"          => "Sha256",
      "Ripemd160"       => "Ripemd160",
      "SigHashPreimage" => "SigHashPreimage",
      "RabinSig"        => "RabinSig",
      "RabinPubKey"     => "RabinPubKey",
      "Point"           => "Point",
    }.freeze

    # Map a Ruby type name to a Runar TypeNode.
    def self.map_rb_type(name)
      mapped = RB_TYPE_MAP.fetch(name, name)
      if primitive_type?(mapped)
        PrimitiveType.new(name: mapped)
      else
        CustomType.new(name: mapped)
      end
    end

    # -----------------------------------------------------------------------
    # Single-character token map, helpers, and tokenizer (namespaced)
    # -----------------------------------------------------------------------

    module RubyTokens
      SINGLE_CHAR_TOKENS = {
        "," => TOK_COMMA,
        "." => TOK_DOT,
        ":" => TOK_COLON,
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
        "<" => TOK_LT,
        ">" => TOK_GT,
        "=" => TOK_ASSIGN,
      }.freeze

      # Compound assignment operators -> binary op string
      COMPOUND_OPS = {
        TOK_PLUSEQ    => "+",
        TOK_MINUSEQ   => "-",
        TOK_STAREQ    => "*",
        TOK_SLASHEQ   => "/",
        TOK_PERCENTEQ => "%",
      }.freeze

      def self.ident_start?(ch)
        ch.match?(/[A-Za-z_]/)
      end

      def self.ident_part?(ch)
        ch.match?(/[A-Za-z0-9_]/)
      end

      # Tokenize a Ruby Runar source file line by line.
      #
      # The tokenizer processes one line at a time, tracking parenthesis depth
      # to suppress NEWLINE tokens inside multi-line expressions. This matches
      # the behavior of the TypeScript reference implementation.
      def self.tokenize(source)
      tokens = []
      lines = source.split("\n", -1)
      paren_depth = 0

      lines.each_with_index do |raw_line, line_idx|
        line_num = line_idx + 1

        # Strip trailing carriage return
        line = raw_line.chomp("\r")

        # Skip blank lines and comment-only lines
        stripped = line.lstrip
        next if stripped.empty? || stripped.start_with?("#")

        # Tokenize the content of this line
        pos = line.length - stripped.length # starting position (after indent)

        while pos < line.length
          ch = line[pos]
          col = pos + 1 # 1-based column

          # Whitespace within a line
          if ch == " " || ch == "\t"
            pos += 1
            next
          end

          # Comment -- rest of line is ignored
          break if ch == "#"

          # Instance variable: @name -> single ivar token
          if ch == "@"
            pos += 1
            name_start = pos
            while pos < line.length && ident_part?(line[pos])
              pos += 1
            end
            name = line[name_start...pos]
            tokens << Token.new(kind: TOK_IVAR, value: name, line: line_num, col: col) if name && !name.empty?
            next
          end

          # Three-dot range operator (must be tried before two-dot)
          if ch == "." && pos + 2 < line.length && line[pos + 1] == "." && line[pos + 2] == "."
            tokens << Token.new(kind: TOK_DOTDOTDOT, value: "...", line: line_num, col: col)
            pos += 3
            next
          end

          # Two-dot range operator
          if ch == "." && pos + 1 < line.length && line[pos + 1] == "."
            tokens << Token.new(kind: TOK_DOTDOT, value: "..", line: line_num, col: col)
            pos += 2
            next
          end

          # Two-character operators (longest match first)
          if pos + 1 < line.length
            two = line[pos, 2]
            case two
            when "**"
              tokens << Token.new(kind: TOK_STARSTAR, value: "**", line: line_num, col: col)
              pos += 2
              next
            when "::"
              tokens << Token.new(kind: TOK_COLONCOLON, value: "::", line: line_num, col: col)
              pos += 2
              next
            when "=="
              tokens << Token.new(kind: TOK_EQEQ, value: "==", line: line_num, col: col)
              pos += 2
              next
            when "!="
              tokens << Token.new(kind: TOK_NOTEQ, value: "!=", line: line_num, col: col)
              pos += 2
              next
            when "<="
              tokens << Token.new(kind: TOK_LTEQ, value: "<=", line: line_num, col: col)
              pos += 2
              next
            when ">="
              tokens << Token.new(kind: TOK_GTEQ, value: ">=", line: line_num, col: col)
              pos += 2
              next
            when "<<"
              tokens << Token.new(kind: TOK_LSHIFT, value: "<<", line: line_num, col: col)
              pos += 2
              next
            when ">>"
              tokens << Token.new(kind: TOK_RSHIFT, value: ">>", line: line_num, col: col)
              pos += 2
              next
            when "&&"
              tokens << Token.new(kind: TOK_AMPAMP, value: "&&", line: line_num, col: col)
              pos += 2
              next
            when "||"
              tokens << Token.new(kind: TOK_PIPEPIPE, value: "||", line: line_num, col: col)
              pos += 2
              next
            when "+="
              tokens << Token.new(kind: TOK_PLUSEQ, value: "+=", line: line_num, col: col)
              pos += 2
              next
            when "-="
              tokens << Token.new(kind: TOK_MINUSEQ, value: "-=", line: line_num, col: col)
              pos += 2
              next
            when "*="
              tokens << Token.new(kind: TOK_STAREQ, value: "*=", line: line_num, col: col)
              pos += 2
              next
            when "/="
              tokens << Token.new(kind: TOK_SLASHEQ, value: "/=", line: line_num, col: col)
              pos += 2
              next
            when "%="
              tokens << Token.new(kind: TOK_PERCENTEQ, value: "%=", line: line_num, col: col)
              pos += 2
              next
            end
          end

          # Parentheses (track depth for multi-line suppression)
          if ch == "("
            paren_depth += 1
            tokens << Token.new(kind: TOK_LPAREN, value: "(", line: line_num, col: col)
            pos += 1
            next
          end
          if ch == ")"
            paren_depth = [0, paren_depth - 1].max
            tokens << Token.new(kind: TOK_RPAREN, value: ")", line: line_num, col: col)
            pos += 1
            next
          end
          if ch == "["
            paren_depth += 1
            tokens << Token.new(kind: TOK_LBRACKET, value: "[", line: line_num, col: col)
            pos += 1
            next
          end
          if ch == "]"
            paren_depth = [0, paren_depth - 1].max
            tokens << Token.new(kind: TOK_RBRACKET, value: "]", line: line_num, col: col)
            pos += 1
            next
          end

          # Symbol: :name (but not :: which was handled above)
          if ch == ":" && pos + 1 < line.length && ident_start?(line[pos + 1])
            pos += 1 # skip ':'
            name_start = pos
            while pos < line.length && ident_part?(line[pos])
              pos += 1
            end
            symbol_name = line[name_start...pos]
            tokens << Token.new(kind: TOK_SYMBOL, value: symbol_name, line: line_num, col: col)
            next
          end

          # Single-character operators and delimiters
          if SINGLE_CHAR_TOKENS.key?(ch)
            tokens << Token.new(kind: SINGLE_CHAR_TOKENS[ch], value: ch, line: line_num, col: col)
            pos += 1
            next
          end

          # Single-quoted string literal -> hex ByteString
          if ch == "'"
            pos += 1 # skip opening quote
            val_chars = +""
            while pos < line.length && line[pos] != "'"
              if line[pos] == "\\" && pos + 1 < line.length
                pos += 1 # skip backslash
                val_chars << line[pos]
                pos += 1
              else
                val_chars << line[pos]
                pos += 1
              end
            end
            pos += 1 if pos < line.length # skip closing quote
            tokens << Token.new(kind: TOK_HEXSTRING, value: val_chars, line: line_num, col: col)
            next
          end

          # Double-quoted string literal
          if ch == '"'
            pos += 1 # skip opening quote
            val_chars = +""
            while pos < line.length && line[pos] != '"'
              if line[pos] == "\\" && pos + 1 < line.length
                pos += 1 # skip backslash
                val_chars << line[pos]
                pos += 1
              else
                val_chars << line[pos]
                pos += 1
              end
            end
            pos += 1 if pos < line.length # skip closing quote
            tokens << Token.new(kind: TOK_STRING, value: val_chars, line: line_num, col: col)
            next
          end

          # Numbers (decimal and hex)
          if ch.match?(/[0-9]/)
            num_chars = +""
            if ch == "0" && pos + 1 < line.length && (line[pos + 1] == "x" || line[pos + 1] == "X")
              num_chars << "0x"
              pos += 2
              while pos < line.length && line[pos].match?(/[0-9a-fA-F_]/)
                num_chars << line[pos] unless line[pos] == "_"
                pos += 1
              end
            else
              while pos < line.length && (line[pos].match?(/[0-9]/) || line[pos] == "_")
                num_chars << line[pos] unless line[pos] == "_"
                pos += 1
              end
            end
            tokens << Token.new(kind: TOK_NUMBER, value: num_chars, line: line_num, col: col)
            next
          end

          # Identifiers and keywords
          if ident_start?(ch)
            name_start = pos
            while pos < line.length && ident_part?(line[pos])
              pos += 1
            end
            # Ruby trailing ? or ! (e.g. empty?, include!)
            if pos < line.length && (line[pos] == "?" || line[pos] == "!")
              pos += 1
            end
            word = line[name_start...pos]
            kw = KEYWORDS[word]
            if kw
              tokens << Token.new(kind: kw, value: word, line: line_num, col: col)
            else
              tokens << Token.new(kind: TOK_IDENT, value: word, line: line_num, col: col)
            end
            next
          end

          # Skip unrecognized characters
          pos += 1
        end

        # Emit NEWLINE at end of significant line (only if not inside parens)
        if paren_depth == 0
          tokens << Token.new(kind: TOK_NEWLINE, value: "", line: line_num, col: line.length + 1)
        end
      end

      tokens << Token.new(kind: TOK_EOF, value: "", line: lines.length + 1, col: 1)
      tokens
    end
    end # module RubyTokens (token maps, helpers, tokenizer)

    # -----------------------------------------------------------------------
    # Bare method call rewriting
    # -----------------------------------------------------------------------

    # Rewrite bare function calls to declared contract methods as this.method().
    #
    # In Ruby, +compute_threshold(a, b)+ inside a contract method is equivalent
    # to +self.compute_threshold(a, b)+, which should produce the same AST node
    # as +this.computeThreshold(a, b)+ in TypeScript.
    def self.rewrite_bare_method_calls(stmts, method_names)
      rewrite_expr = nil # forward declaration for closures

      rewrite_expr = lambda do |expr|
        case expr
        when CallExpr
          expr.args = expr.args.map { |a| rewrite_expr.call(a) }
          if expr.callee.is_a?(Identifier) && method_names.include?(expr.callee.name)
            expr.callee = PropertyAccessExpr.new(property: expr.callee.name)
          else
            expr.callee = rewrite_expr.call(expr.callee)
          end
          expr
        when BinaryExpr
          expr.left = rewrite_expr.call(expr.left)
          expr.right = rewrite_expr.call(expr.right)
          expr
        when UnaryExpr
          expr.operand = rewrite_expr.call(expr.operand)
          expr
        when TernaryExpr
          expr.condition = rewrite_expr.call(expr.condition)
          expr.consequent = rewrite_expr.call(expr.consequent)
          expr.alternate = rewrite_expr.call(expr.alternate)
          expr
        else
          expr
        end
      end

      rewrite_stmt = lambda do |stmt|
        case stmt
        when ExpressionStmt
          stmt.expr = rewrite_expr.call(stmt.expr)
        when VariableDeclStmt
          stmt.init = rewrite_expr.call(stmt.init)
        when AssignmentStmt
          stmt.value = rewrite_expr.call(stmt.value)
        when ReturnStmt
          stmt.value = rewrite_expr.call(stmt.value) if stmt.value
        when IfStmt
          stmt.condition = rewrite_expr.call(stmt.condition)
          rewrite_bare_method_calls(stmt.then, method_names)
          rewrite_bare_method_calls(stmt.else_, method_names) if stmt.else_ && !stmt.else_.empty?
        when ForStmt
          rewrite_bare_method_calls(stmt.body, method_names)
        end
      end

      stmts.each { |stmt| rewrite_stmt.call(stmt) }
    end

    # -----------------------------------------------------------------------
    # Parser
    # -----------------------------------------------------------------------

    # Recursive descent parser for Ruby-format Runar contracts.
    class RbParser
      include RubyTokens

      def initialize(tokens, file_name)
        @tokens = tokens
        @pos = 0
        @file = file_name
        @errors = []
        # Track locally declared variables per method scope
        @declared_locals = Set.new
      end

      # -------------------------------------------------------------------
      # Token navigation
      # -------------------------------------------------------------------

      def current
        @pos < @tokens.length ? @tokens[@pos] : @tokens[-1] # EOF
      end

      def advance
        tok = current
        @pos += 1 if @pos < @tokens.length - 1
        tok
      end

      def peek
        current
      end

      def peek_ahead(offset = 1)
        idx = @pos + offset
        idx < @tokens.length ? @tokens[idx] : @tokens[-1]
      end

      def match_tok(kind)
        if current.kind == kind
          advance
          true
        else
          false
        end
      end

      def expect(kind, label = "")
        tok = current
        if tok.kind != kind
          desc = label.empty? ? kind.to_s : label
          @errors << "#{@file}:#{tok.line}:#{tok.col}: expected '#{desc}', got '#{tok.value.empty? ? tok.kind : tok.value}'"
        end
        advance
      end

      def check_ident(name)
        tok = current
        tok.kind == TOK_IDENT && tok.value == name
      end

      def loc
        tok = current
        SourceLocation.new(file: @file, line: tok.line, column: tok.col)
      end

      def skip_newlines
        advance while current.kind == TOK_NEWLINE
      end

      # -------------------------------------------------------------------
      # Top-level parsing
      # -------------------------------------------------------------------

      def parse
        skip_newlines

        # Consume +require 'runar'+ lines
        while peek.kind == TOK_REQUIRE
          parse_require_line
          skip_newlines
        end

        contract = parse_class
        diagnostics = @errors.map { |e| Diagnostic.new(message: e, severity: Severity::ERROR) }
        if contract.nil?
          return ParseResult.new(errors: diagnostics)
        end

        ParseResult.new(contract: contract, errors: diagnostics)
      end

      private

      def parse_require_line
        advance # 'require'
        while peek.kind != TOK_NEWLINE && peek.kind != TOK_EOF
          advance
        end
        skip_newlines
      end

      def parse_class
        skip_newlines

        if peek.kind != TOK_CLASS
          @errors << "#{@file}:#{peek.line}: expected class declaration"
          return nil
        end
        advance # 'class'

        name_tok = expect(TOK_IDENT, "class name")
        contract_name = name_tok.value

        # Expect +< Runar::SmartContract+ or +< Runar::StatefulSmartContract+
        expect(TOK_LT, "<")

        first_part = advance # 'Runar' or the class name directly
        if peek.kind == TOK_COLONCOLON
          advance # '::'
          class_part = advance
          parent_class = class_part.value
        else
          parent_class = first_part.value
        end

        skip_newlines

        unless %w[SmartContract StatefulSmartContract].include?(parent_class)
          @errors << "#{@file}:#{first_part.line}: unknown parent class: #{parent_class}"
          return nil
        end

        # Parse class body until +end+
        properties = []
        methods = []
        constructor = nil

        # Pending visibility/param types for the next method
        pending_visibility = nil
        pending_param_types = nil

        while peek.kind != TOK_END && peek.kind != TOK_EOF
          skip_newlines
          break if peek.kind == TOK_END || peek.kind == TOK_EOF

          # +prop :name, Type [, readonly: true]+
          if check_ident("prop")
            prop = parse_prop(parent_class)
            properties << prop unless prop.nil?
            skip_newlines
            next
          end

          # +runar_public [key: Type, ...]+
          if check_ident("runar_public")
            advance # 'runar_public'
            pending_visibility = "public"
            pending_param_types = parse_optional_param_types
            skip_newlines
            next
          end

          # +params key: Type, ...+
          if check_ident("params")
            advance # 'params'
            pending_param_types = parse_optional_param_types
            skip_newlines
            next
          end

          # Method definition
          if peek.kind == TOK_DEF
            method = parse_method(pending_visibility, pending_param_types)
            if method.name == "constructor"
              constructor = method
            else
              methods << method
            end
            pending_visibility = nil
            pending_param_types = nil
            skip_newlines
            next
          end

          # Skip unknown tokens
          advance
        end

        match_tok(TOK_END) # end of class

        # Auto-generate constructor if not provided
        constructor = auto_generate_constructor(properties) if constructor.nil?

        # Back-fill constructor param types from prop declarations.
        # Ruby +def initialize(pub_key_hash)+ has no type annotations --
        # we infer them from the matching +prop :pub_key_hash, Addr+.
        prop_type_map = {}
        properties.each { |p| prop_type_map[p.name] = p.type }
        constructor.params.each do |param|
          if param.type.is_a?(CustomType) && param.type.name == "unknown"
            prop_type = prop_type_map[param.name]
            param.type = prop_type unless prop_type.nil?
          end
        end

        # Rewrite bare calls to declared methods and intrinsics as this.method().
        # In Ruby, bare calls like +add_output(...)+ are equivalent to
        # +self.add_output(...)+ / +this.addOutput(...)+.
        intrinsic_methods = Set.new(%w[addOutput addRawOutput getStateScript])
        method_names = methods.map(&:name).to_set | intrinsic_methods
        methods.each do |m|
          Frontend.rewrite_bare_method_calls(m.body, method_names)
        end

        # Implicit return conversion for private methods.
        #
        # Ruby methods implicitly return the value of their last expression.
        # Private helper methods that return computed values (e.g. a fee
        # calculation) rely on this -- without conversion, the calling method
        # would receive no return value and the type checker would reject
        # the call. We detect ExpressionStmt as the final statement and
        # promote it to a ReturnStmt so the AST has an explicit return node
        # for ANF lowering and type checking to consume.
        methods.each do |m|
          if m.visibility == "private" && !m.body.empty?
            last = m.body[-1]
            if last.is_a?(ExpressionStmt)
              m.body[-1] = ReturnStmt.new(
                value: last.expr,
                source_location: last.source_location
              )
            end
          end
        end

        ContractNode.new(
          name: contract_name,
          parent_class: parent_class,
          properties: properties,
          constructor: constructor,
          methods: methods,
          source_file: @file
        )
      end

      def parse_optional_param_types
        # Parse optional +key: Type+ pairs after +runar_public+ or +params+.
        # Returns nil if there are no pairs on this line.
        if peek.kind == TOK_NEWLINE || peek.kind == TOK_EOF || peek.kind == TOK_DEF
          return nil
        end

        param_types = {}

        while peek.kind != TOK_NEWLINE && peek.kind != TOK_EOF
          name_tok = advance
          raw_name = name_tok.value

          expect(TOK_COLON, ":")
          type_node = parse_type
          param_types[raw_name] = type_node

          break unless match_tok(TOK_COMMA)
        end

        param_types.empty? ? nil : param_types
      end

      def parse_prop(parent_class)
        # Parse a +prop :name, Type [, readonly: true|false]+ declaration.
        current_loc = loc
        advance # 'prop'

        if peek.kind != TOK_SYMBOL
          @errors << "#{@file}:#{peek.line}: expected symbol after 'prop', got '#{peek.value}'"
          advance while peek.kind != TOK_NEWLINE && peek.kind != TOK_EOF
          return nil
        end

        raw_name = advance.value # symbol value (without colon)
        expect(TOK_COMMA, ",")

        type_node = parse_type

        is_readonly = false
        initializer = nil

        # Check for optional trailing +readonly: true+ or +default: value+
        while peek.kind == TOK_COMMA
          advance # ','

          if check_ident("readonly")
            advance # 'readonly'
            expect(TOK_COLON, ":")
            if peek.kind == TOK_TRUE
              advance
              is_readonly = true
            elsif peek.kind == TOK_FALSE
              advance
              is_readonly = false
            end
          elsif check_ident("default")
            advance # 'default'
            expect(TOK_COLON, ":")
            initializer = parse_primary
          end
        end

        # In stateless contracts, all properties are always readonly
        is_readonly = true if parent_class == "SmartContract"

        # Skip rest of line
        advance while peek.kind != TOK_NEWLINE && peek.kind != TOK_EOF

        PropertyNode.new(
          name: Frontend.snake_to_camel(raw_name),
          type: type_node,
          readonly: is_readonly,
          initializer: initializer,
          source_location: current_loc
        )
      end

      def parse_type
        # Parse a Ruby type name, including +FixedArray[T, N]+.
        tok = advance
        raw_name = tok.value

        # FixedArray[T, N] style generic
        if raw_name == "FixedArray" && peek.kind == TOK_LBRACKET
          advance # '['
          elem_type = parse_type
          expect(TOK_COMMA, ",")
          size_tok = expect(TOK_NUMBER, "number")
          size = size_tok.value.to_i
          expect(TOK_RBRACKET, "]")
          return FixedArrayType.new(element: elem_type, length: size)
        end

        Frontend.map_rb_type(raw_name)
      end

      def parse_method(pending_visibility, pending_param_types)
        # Parse a +def name(params...) ... end+ method definition.
        current_loc = loc
        expect(TOK_DEF, "def")

        name_tok = advance
        raw_name = name_tok.value

        # Reset local variable tracking for this method scope
        @declared_locals = Set.new

        # Parse parameters (parentheses optional for no-arg methods)
        if peek.kind == TOK_LPAREN
          expect(TOK_LPAREN, "(")
          params = parse_params(pending_param_types)
          expect(TOK_RPAREN, ")")
        else
          params = []
        end

        skip_newlines

        body = parse_statements
        expect(TOK_END, "end")

        # +initialize+ maps to +constructor+
        if raw_name == "initialize"
          return MethodNode.new(
            name: "constructor",
            params: params,
            body: body,
            visibility: "public",
            source_location: current_loc
          )
        end

        is_public = pending_visibility == "public"
        method_name = Frontend.snake_to_camel(raw_name)

        MethodNode.new(
          name: method_name,
          params: params,
          body: body,
          visibility: is_public ? "public" : "private",
          source_location: current_loc
        )
      end

      def parse_params(param_types)
        # Parse a comma-separated parameter list (names only in Ruby).
        params = []

        while peek.kind != TOK_RPAREN && peek.kind != TOK_EOF
          name_tok = advance
          raw_name = name_tok.value
          camel_name = Frontend.snake_to_camel(raw_name)

          type_node = nil
          type_node = param_types[raw_name] if param_types

          params << ParamNode.new(
            name: camel_name,
            type: type_node || CustomType.new(name: "unknown")
          )

          break unless match_tok(TOK_COMMA)
        end

        params
      end

      def auto_generate_constructor(properties)
        # Generate a default constructor from property declarations.
        #
        # Produces:
        #   super(prop1, prop2, ...)
        #   @prop1 = prop1
        #   @prop2 = prop2
        #   ...

        # Exclude properties that have initializers (they don't need constructor params)
        required_props = properties.select { |p| p.initializer.nil? }

        params = required_props.map do |p|
          ParamNode.new(name: p.name, type: p.type)
        end

        super_args = required_props.map do |p|
          Identifier.new(name: p.name)
        end

        default_loc = SourceLocation.new(file: @file, line: 1, column: 0)

        super_call = ExpressionStmt.new(
          expr: CallExpr.new(
            callee: Identifier.new(name: "super"),
            args: super_args
          ),
          source_location: default_loc
        )

        assignments = required_props.map do |p|
          AssignmentStmt.new(
            target: PropertyAccessExpr.new(property: p.name),
            value: Identifier.new(name: p.name),
            source_location: default_loc
          )
        end

        MethodNode.new(
          name: "constructor",
          params: params,
          body: [super_call, *assignments],
          visibility: "public",
          source_location: default_loc
        )
      end

      # -------------------------------------------------------------------
      # Statements
      # -------------------------------------------------------------------

      def parse_statements
        # Parse statements until +end+, +elsif+, +else+, or EOF.
        stmts = []

        while peek.kind != TOK_END && peek.kind != TOK_ELSIF &&
              peek.kind != TOK_ELSE && peek.kind != TOK_EOF
          skip_newlines
          break if peek.kind == TOK_END || peek.kind == TOK_ELSIF ||
                   peek.kind == TOK_ELSE || peek.kind == TOK_EOF

          stmt = parse_statement
          stmts << stmt unless stmt.nil?
          skip_newlines
        end

        stmts
      end

      def parse_statement
        current_loc = loc
        kind = peek.kind

        return parse_assert_statement(current_loc) if kind == TOK_ASSERT
        return parse_if_statement(current_loc)     if kind == TOK_IF
        return parse_unless_statement(current_loc)  if kind == TOK_UNLESS
        return parse_for_statement(current_loc)     if kind == TOK_FOR
        return parse_return_statement(current_loc)  if kind == TOK_RETURN
        return parse_super_call(current_loc)        if kind == TOK_SUPER
        return parse_ivar_statement(current_loc)    if kind == TOK_IVAR
        return parse_ident_statement(current_loc)   if kind == TOK_IDENT

        # Skip unrecognized token
        advance
        nil
      end

      def parse_assert_statement(current_loc)
        advance # 'assert'
        expr = parse_expression
        ExpressionStmt.new(
          expr: CallExpr.new(
            callee: Identifier.new(name: "assert"),
            args: [expr]
          ),
          source_location: current_loc
        )
      end

      def parse_if_statement(current_loc)
        advance # 'if'
        condition = parse_expression
        skip_newlines

        then_stmts = parse_statements

        else_stmts = nil

        if peek.kind == TOK_ELSIF
          elif_loc = loc
          else_stmts = [parse_elsif_statement(elif_loc)]
        elsif peek.kind == TOK_ELSE
          advance # 'else'
          skip_newlines
          else_stmts = parse_statements
        end

        expect(TOK_END, "end")

        IfStmt.new(
          condition: condition,
          then: then_stmts,
          else_: else_stmts || [],
          source_location: current_loc
        )
      end

      def parse_elsif_statement(current_loc)
        advance # 'elsif'
        condition = parse_expression
        skip_newlines

        then_stmts = parse_statements

        else_stmts = nil

        if peek.kind == TOK_ELSIF
          elif_loc = loc
          else_stmts = [parse_elsif_statement(elif_loc)]
        elsif peek.kind == TOK_ELSE
          advance # 'else'
          skip_newlines
          else_stmts = parse_statements
        end

        # Note: the outer +end+ is consumed by the parent +parse_if_statement+.
        # +elsif+ branches do not consume their own +end+.

        IfStmt.new(
          condition: condition,
          then: then_stmts,
          else_: else_stmts || [],
          source_location: current_loc
        )
      end

      def parse_unless_statement(current_loc)
        advance # 'unless'
        raw_condition = parse_expression
        skip_newlines

        body = parse_statements
        expect(TOK_END, "end")

        # +unless cond+ maps to +if !cond+
        condition = UnaryExpr.new(op: "!", operand: raw_condition)

        IfStmt.new(
          condition: condition,
          then: body,
          else_: [],
          source_location: current_loc
        )
      end

      def parse_for_statement(current_loc)
        advance # 'for'

        iter_tok = advance # loop variable name
        var_name = Frontend.snake_to_camel(iter_tok.value)

        expect(TOK_IN, "in")

        start_expr = parse_expression

        # Expect range operator +..+ (inclusive) or +...+ (exclusive)
        is_exclusive = false
        if peek.kind == TOK_DOTDOTDOT
          is_exclusive = true
          advance
        elsif peek.kind == TOK_DOTDOT
          is_exclusive = false
          advance
        else
          @errors << "#{@file}:#{peek.line}: expected range operator '..' or '...' in for loop"
        end

        end_expr = parse_expression

        # Optional +do+ keyword
        match_tok(TOK_DO)
        skip_newlines

        body = parse_statements
        expect(TOK_END, "end")

        # Construct a C-style for loop AST node (same as TS reference)
        loop_var_loc = SourceLocation.new(file: @file, line: iter_tok.line, column: iter_tok.col)
        init = VariableDeclStmt.new(
          name: var_name,
          type: PrimitiveType.new(name: "bigint"),
          mutable: true,
          init: start_expr,
          source_location: loop_var_loc
        )

        condition = BinaryExpr.new(
          op: is_exclusive ? "<" : "<=",
          left: Identifier.new(name: var_name),
          right: end_expr
        )

        update = ExpressionStmt.new(
          expr: IncrementExpr.new(
            operand: Identifier.new(name: var_name),
            prefix: false
          ),
          source_location: current_loc
        )

        ForStmt.new(
          init: init,
          condition: condition,
          update: update,
          body: body,
          source_location: current_loc
        )
      end

      def parse_return_statement(current_loc)
        advance # 'return'
        value = nil
        if peek.kind != TOK_NEWLINE && peek.kind != TOK_END && peek.kind != TOK_EOF
          value = parse_expression
        end
        ReturnStmt.new(value: value, source_location: current_loc)
      end

      def parse_super_call(current_loc)
        # Parse +super(args...)+ in a constructor.
        advance # 'super'
        expect(TOK_LPAREN, "(")
        args = []
        while peek.kind != TOK_RPAREN && peek.kind != TOK_EOF
          args << parse_expression
          break unless match_tok(TOK_COMMA)
        end
        expect(TOK_RPAREN, ")")
        ExpressionStmt.new(
          expr: CallExpr.new(
            callee: Identifier.new(name: "super"),
            args: args
          ),
          source_location: current_loc
        )
      end

      def parse_ivar_statement(current_loc)
        # Parse +@var = expr+, +@var[i] = expr+, +@var += expr+, or
        # +@var+ as expression.
        ivar_tok = advance # ivar token
        raw_name = ivar_tok.value
        prop_name = Frontend.snake_to_camel(raw_name)
        target = PropertyAccessExpr.new(property: prop_name)

        # Consume +[index]+ postfixes so that +@var[i] = expr+ is
        # recognised as an assignment statement rather than being
        # split into an orphan read and a rogue rhs.
        while peek.kind == TOK_LBRACKET
          advance # '['
          index = parse_expression
          unless match_tok(TOK_RBRACKET)
            # Recover gracefully; parser will emit a diagnostic.
            break
          end
          target = IndexAccessExpr.new(object: target, index: index)
        end

        # Simple assignment: @var = expr | @var[i] = expr
        if match_tok(TOK_ASSIGN)
          value = parse_expression
          return AssignmentStmt.new(target: target, value: value, source_location: current_loc)
        end

        # Compound assignment: @var += expr, @var -= expr, etc.
        op_kind = peek.kind
        if COMPOUND_OPS.key?(op_kind)
          advance
          right = parse_expression
          value = BinaryExpr.new(op: COMPOUND_OPS[op_kind], left: target, right: right)
          return AssignmentStmt.new(target: target, value: value, source_location: current_loc)
        end

        # Expression statement: bare +@var+ (e.g. followed by +.method(...)+)
        expr = parse_postfix_from(target)
        ExpressionStmt.new(expr: expr, source_location: current_loc)
      end

      def parse_ident_statement(current_loc)
        # Parse a statement starting with an identifier.
        name_tok = peek
        raw_name = name_tok.value

        # Simple +name = expr+ (variable declaration or reassignment)
        if peek_ahead(1).kind == TOK_ASSIGN
          advance # consume ident
          advance # consume '='
          value = parse_expression
          camel_name = Frontend.snake_to_camel(raw_name)

          if @declared_locals.include?(camel_name)
            return AssignmentStmt.new(
              target: Identifier.new(name: camel_name),
              value: value,
              source_location: current_loc
            )
          end
          @declared_locals << camel_name
          return VariableDeclStmt.new(
            name: camel_name,
            mutable: true,
            init: value,
            source_location: current_loc
          )
        end

        # Parse as expression
        expr = parse_expression

        # Simple assignment (e.g. +a.b = expr+)
        if match_tok(TOK_ASSIGN)
          value = parse_expression
          return AssignmentStmt.new(target: expr, value: value, source_location: current_loc)
        end

        # Compound assignment
        op_kind = peek.kind
        if COMPOUND_OPS.key?(op_kind)
          advance
          right = parse_expression
          value = BinaryExpr.new(op: COMPOUND_OPS[op_kind], left: expr, right: right)
          return AssignmentStmt.new(target: expr, value: value, source_location: current_loc)
        end

        ExpressionStmt.new(expr: expr, source_location: current_loc)
      end

      # -------------------------------------------------------------------
      # Expressions (precedence climbing)
      # -------------------------------------------------------------------

      def parse_expression
        parse_ternary
      end

      def parse_ternary
        expr = parse_or
        if peek.kind == TOK_QUESTION
          advance # '?'
          consequent = parse_expression
          expect(TOK_COLON, ":")
          alternate = parse_expression
          return TernaryExpr.new(condition: expr, consequent: consequent, alternate: alternate)
        end
        expr
      end

      def parse_or
        left = parse_and
        while peek.kind == TOK_OR || peek.kind == TOK_PIPEPIPE
          advance
          right = parse_and
          left = BinaryExpr.new(op: "||", left: left, right: right)
        end
        left
      end

      def parse_and
        left = parse_not
        while peek.kind == TOK_AND || peek.kind == TOK_AMPAMP
          advance
          right = parse_not
          left = BinaryExpr.new(op: "&&", left: left, right: right)
        end
        left
      end

      def parse_not
        if peek.kind == TOK_NOT || peek.kind == TOK_BANG
          advance
          operand = parse_not
          return UnaryExpr.new(op: "!", operand: operand)
        end
        parse_bitwise_or
      end

      def parse_bitwise_or
        left = parse_bitwise_xor
        while peek.kind == TOK_PIPE
          advance
          right = parse_bitwise_xor
          left = BinaryExpr.new(op: "|", left: left, right: right)
        end
        left
      end

      def parse_bitwise_xor
        left = parse_bitwise_and
        while peek.kind == TOK_CARET
          advance
          right = parse_bitwise_and
          left = BinaryExpr.new(op: "^", left: left, right: right)
        end
        left
      end

      def parse_bitwise_and
        left = parse_equality
        while peek.kind == TOK_AMP
          advance
          right = parse_equality
          left = BinaryExpr.new(op: "&", left: left, right: right)
        end
        left
      end

      def parse_equality
        left = parse_comparison
        loop do
          kind = peek.kind
          if kind == TOK_EQEQ
            advance
            right = parse_comparison
            left = BinaryExpr.new(op: "===", left: left, right: right)
          elsif kind == TOK_NOTEQ
            advance
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
          kind = peek.kind
          if kind == TOK_LT
            advance
            right = parse_shift
            left = BinaryExpr.new(op: "<", left: left, right: right)
          elsif kind == TOK_LTEQ
            advance
            right = parse_shift
            left = BinaryExpr.new(op: "<=", left: left, right: right)
          elsif kind == TOK_GT
            advance
            right = parse_shift
            left = BinaryExpr.new(op: ">", left: left, right: right)
          elsif kind == TOK_GTEQ
            advance
            right = parse_shift
            left = BinaryExpr.new(op: ">=", left: left, right: right)
          else
            break
          end
        end
        left
      end

      def parse_shift
        left = parse_add_sub
        loop do
          kind = peek.kind
          if kind == TOK_LSHIFT
            advance
            right = parse_add_sub
            left = BinaryExpr.new(op: "<<", left: left, right: right)
          elsif kind == TOK_RSHIFT
            advance
            right = parse_add_sub
            left = BinaryExpr.new(op: ">>", left: left, right: right)
          else
            break
          end
        end
        left
      end

      def parse_add_sub
        left = parse_mul_div
        loop do
          kind = peek.kind
          if kind == TOK_PLUS
            advance
            right = parse_mul_div
            left = BinaryExpr.new(op: "+", left: left, right: right)
          elsif kind == TOK_MINUS
            advance
            right = parse_mul_div
            left = BinaryExpr.new(op: "-", left: left, right: right)
          else
            break
          end
        end
        left
      end

      def parse_mul_div
        left = parse_unary
        loop do
          kind = peek.kind
          if kind == TOK_STAR
            advance
            right = parse_unary
            left = BinaryExpr.new(op: "*", left: left, right: right)
          elsif kind == TOK_SLASH
            advance
            right = parse_unary
            left = BinaryExpr.new(op: "/", left: left, right: right)
          elsif kind == TOK_PERCENT
            advance
            right = parse_unary
            left = BinaryExpr.new(op: "%", left: left, right: right)
          else
            break
          end
        end
        left
      end

      def parse_unary
        kind = peek.kind
        if kind == TOK_MINUS
          advance
          return UnaryExpr.new(op: "-", operand: parse_unary)
        end
        if kind == TOK_TILDE
          advance
          return UnaryExpr.new(op: "~", operand: parse_unary)
        end
        if kind == TOK_BANG
          advance
          return UnaryExpr.new(op: "!", operand: parse_unary)
        end
        parse_power
      end

      def parse_power
        base = parse_postfix
        # +**+ is right-associative and maps to +pow(base, exp)+
        if peek.kind == TOK_STARSTAR
          advance
          exp = parse_power # right-recursive for right-associativity
          return CallExpr.new(
            callee: Identifier.new(name: "pow"),
            args: [base, exp]
          )
        end
        base
      end

      def parse_postfix
        expr = parse_primary
        parse_postfix_from(expr)
      end

      def parse_postfix_from(expr)
        # Parse postfix operations (method calls, property access, indexing).
        loop do
          kind = peek.kind

          # Method call or property access: +expr.name+ or +expr.name(...)+
          if kind == TOK_DOT
            advance # '.'
            prop_tok = advance
            prop_name = Frontend.map_builtin_name(prop_tok.value)

            if peek.kind == TOK_LPAREN
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
            next
          end

          # Function call: +expr(args...)+
          if kind == TOK_LPAREN
            args = parse_call_args
            expr = CallExpr.new(callee: expr, args: args)
            next
          end

          # Index access: +expr[index]+
          if kind == TOK_LBRACKET
            advance # '['
            index = parse_expression
            expect(TOK_RBRACKET, "]")
            expr = IndexAccessExpr.new(object: expr, index: index)
            next
          end

          break
        end

        expr
      end

      def parse_primary
        tok = peek
        kind = tok.kind

        # Number literal
        if kind == TOK_NUMBER
          advance
          return BigIntLiteral.new(value: Integer(tok.value, 0))
        end

        # Boolean literals
        if kind == TOK_TRUE
          advance
          return BoolLiteral.new(value: true)
        end
        if kind == TOK_FALSE
          advance
          return BoolLiteral.new(value: false)
        end

        # Hex string literal (single-quoted)
        if kind == TOK_HEXSTRING
          advance
          return ByteStringLiteral.new(value: tok.value)
        end

        # Double-quoted string literal
        if kind == TOK_STRING
          advance
          return ByteStringLiteral.new(value: tok.value)
        end

        # +nil+ -> 0
        if kind == TOK_NIL
          advance
          return BigIntLiteral.new(value: 0)
        end

        # Instance variable: +@var+ -> property access
        if kind == TOK_IVAR
          advance
          prop_name = Frontend.snake_to_camel(tok.value)
          return PropertyAccessExpr.new(property: prop_name)
        end

        # Parenthesized expression
        if kind == TOK_LPAREN
          advance
          expr = parse_expression
          expect(TOK_RPAREN, ")")
          return expr
        end

        # Array literal: +[elem, ...]+
        if kind == TOK_LBRACKET
          advance
          elements = []
          while peek.kind != TOK_RBRACKET && peek.kind != TOK_EOF
            elements << parse_expression
            break unless match_tok(TOK_COMMA)
          end
          expect(TOK_RBRACKET, "]")
          return ArrayLiteralExpr.new(elements: elements)
        end

        # Identifier or function call (including +assert+ as identifier)
        if kind == TOK_IDENT || kind == TOK_ASSERT
          advance
          raw_name = tok.value
          name = Frontend.map_builtin_name(raw_name)
          return Identifier.new(name: name)
        end

        # +super+ as expression
        if kind == TOK_SUPER
          advance
          return Identifier.new(name: "super")
        end

        @errors << "#{@file}:#{tok.line}:#{tok.col}: unexpected token in expression: '#{tok.value.empty? ? tok.kind : tok.value}'"
        advance
        BigIntLiteral.new(value: 0)
      end

      def parse_call_args
        # Parse +(arg, arg, ...)+.
        expect(TOK_LPAREN, "(")
        args = []
        while peek.kind != TOK_RPAREN && peek.kind != TOK_EOF
          args << parse_expression
          break unless match_tok(TOK_COMMA)
        end
        expect(TOK_RPAREN, ")")
        args
      end
    end

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    # Parse a Ruby-format Runar contract (.runar.rb) and return a ParseResult.
    #
    # @param source [String] the Ruby source code
    # @param file_name [String] the source file name
    # @return [ParseResult]
    def self.parse_ruby(source, file_name = "contract.runar.rb")
      tokens = RubyTokens.tokenize(source)
      parser = RbParser.new(tokens, file_name)
      parser.parse
    end
  end
end
