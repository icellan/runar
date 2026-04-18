# frozen_string_literal: true

# Rust DSL format parser (.runar.rs) for the Runar compiler.
#
# Ported from compilers/python/runar_compiler/frontend/parser_rust.py
# and packages/runar-compiler/src/passes/01-parse-rust.ts.
# Hand-written tokenizer + recursive descent parser.
#
# Rust syntax conventions used in Runar contracts:
#   - `#[runar::contract]` or `#[runar::stateful_contract]` attribute
#   - `struct Name { field: Type, ... }` for properties
#   - `#[runar::methods(Name)]` + `impl Name { ... }` for methods
#   - `#[public]` attribute before `fn` for public methods
#   - `#[readonly]` attribute for readonly struct fields
#   - `fn method_name(&self, param: Type) -> ReturnType { ... }`
#   - `fn init(...) -> Self { Self { field: value } }` for property initializers
#   - Type mapping: i64/i128 -> bigint, bool -> boolean, Vec<u8>/runar::ByteString -> ByteString
#   - `runar::assert(...)` -> assert(...)
#   - `self.property` -> PropertyAccessExpr
#   - snake_case -> camelCase conversion
#   - `for i in 0..n { }` range loops

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"

module RunarCompiler
  module Frontend
    # -----------------------------------------------------------------------
    # Namespaced token constants for the Rust parser
    # -----------------------------------------------------------------------

    module RustTokens
      TOK_EOF         = 0
      TOK_IDENT       = 1
      TOK_NUMBER      = 2
      TOK_HEXSTRING   = 3
      TOK_STRING      = 4
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
      TOK_COLONCOLON  = 15  # ::
      TOK_ARROW       = 16  # ->
      TOK_HASH        = 17  # #
      TOK_PLUS        = 18  # +
      TOK_MINUS       = 19  # -
      TOK_STAR        = 20  # *
      TOK_SLASH       = 21  # /
      TOK_PERCENT     = 22  # %
      TOK_EQEQ        = 23  # ==
      TOK_BANGEQ       = 24  # !=
      TOK_LT          = 25  # <
      TOK_LTEQ        = 26  # <=
      TOK_GT          = 27  # >
      TOK_GTEQ        = 28  # >=
      TOK_AMPAMP      = 29  # &&
      TOK_PIPEPIPE    = 30  # ||
      TOK_AMP         = 31  # &
      TOK_PIPE        = 32  # |
      TOK_CARET       = 33  # ^
      TOK_TILDE       = 34  # ~
      TOK_BANG        = 35  # !
      TOK_EQ          = 36  # =
      TOK_PLUSEQ      = 37  # +=
      TOK_MINUSEQ     = 38  # -=
      TOK_STAREQ      = 39  # *=
      TOK_SLASHEQ     = 40  # /=
      TOK_PERCENTEQ   = 41  # %=
      TOK_PLUSPLUS     = 42  # ++
      TOK_MINUSMINUS  = 43  # --
      TOK_LSHIFT      = 44  # <<
      TOK_RSHIFT      = 45  # >>
      TOK_DOTDOT      = 46  # ..
      TOK_ASSERT_MACRO = 47 # assert!
      # Keywords
      TOK_USE         = 50
      TOK_STRUCT      = 51
      TOK_IMPL        = 52
      TOK_FN          = 53
      TOK_PUB         = 54
      TOK_LET         = 55
      TOK_MUT         = 56
      TOK_IF          = 57
      TOK_ELSE        = 58
      TOK_FOR         = 59
      TOK_RETURN      = 60
      TOK_IN          = 61
      TOK_TRUE        = 62
      TOK_FALSE       = 63
      TOK_SELF        = 64
    end

    # A single token produced by the Rust tokenizer.
    RustToken = Struct.new(:kind, :value, :line, :col, keyword_init: true)

    # -----------------------------------------------------------------------
    # Name conversion: Rust snake_case -> camelCase
    # -----------------------------------------------------------------------

    RUST_SPECIAL_BUILTINS = {
      "bool_cast"                   => "bool",
      "verify_wots"                 => "verifyWOTS",
      "verify_slh_dsa_sha2_128s"   => "verifySLHDSA_SHA2_128s",
      "verify_slh_dsa_sha2_128f"   => "verifySLHDSA_SHA2_128f",
      "verify_slh_dsa_sha2_192s"   => "verifySLHDSA_SHA2_192s",
      "verify_slh_dsa_sha2_192f"   => "verifySLHDSA_SHA2_192f",
      "verify_slh_dsa_sha2_256s"   => "verifySLHDSA_SHA2_256s",
      "verify_slh_dsa_sha2_256f"   => "verifySLHDSA_SHA2_256f",
      "bin_2_num"                   => "bin2num",
      "int_2_str"                   => "int2str",
      "to_byte_string"              => "toByteString",
    }.freeze

    RUST_BUILTIN_MAP = {
      # Hashing
      "hash160" => "hash160", "hash256" => "hash256",
      "sha256" => "sha256", "ripemd160" => "ripemd160",
      # Signature verification
      "checkSig" => "checkSig", "checkMultiSig" => "checkMultiSig",
      "checkPreimage" => "checkPreimage", "verifyRabinSig" => "verifyRabinSig",
      # Post-quantum
      "verifyWOTS" => "verifyWOTS", "verifyWots" => "verifyWOTS",
      "verifySlhDsaSha2128s" => "verifySLHDSA_SHA2_128s",
      "verifySlhdsaSha2128s" => "verifySLHDSA_SHA2_128s",
      "verifySlhDsaSha2128f" => "verifySLHDSA_SHA2_128f",
      "verifySlhdsaSha2128f" => "verifySLHDSA_SHA2_128f",
      "verifySlhDsaSha2192s" => "verifySLHDSA_SHA2_192s",
      "verifySlhdsaSha2192s" => "verifySLHDSA_SHA2_192s",
      "verifySlhDsaSha2192f" => "verifySLHDSA_SHA2_192f",
      "verifySlhdsaSha2192f" => "verifySLHDSA_SHA2_192f",
      "verifySlhDsaSha2256s" => "verifySLHDSA_SHA2_256s",
      "verifySlhdsaSha2256s" => "verifySLHDSA_SHA2_256s",
      "verifySlhDsaSha2256f" => "verifySLHDSA_SHA2_256f",
      "verifySlhdsaSha2256f" => "verifySLHDSA_SHA2_256f",
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
      "addDataOutput" => "addDataOutput",
      "getStateScript" => "getStateScript",
      # Math builtins
      "abs" => "abs", "min" => "min", "max" => "max", "within" => "within",
      "safediv" => "safediv", "safemod" => "safemod", "clamp" => "clamp",
      "sign" => "sign", "pow" => "pow", "mulDiv" => "mulDiv",
      "percentOf" => "percentOf", "sqrt" => "sqrt",
      "gcd" => "gcd", "divmod" => "divmod", "log2" => "log2",
      # EC builtins
      "ecAdd" => "ecAdd", "ecMul" => "ecMul", "ecMulGen" => "ecMulGen",
      "ecNegate" => "ecNegate", "ecOnCurve" => "ecOnCurve",
      "ecModReduce" => "ecModReduce",
      "ecEncodeCompressed" => "ecEncodeCompressed",
      "ecMakePoint" => "ecMakePoint",
      "ecPointX" => "ecPointX", "ecPointY" => "ecPointY",
      # SHA-256 partial
      "sha256Compress" => "sha256Compress", "sha256Finalize" => "sha256Finalize",
      # BLAKE3
      "blake3Compress" => "blake3Compress", "blake3Hash" => "blake3Hash",
    }.freeze

    RUST_TYPE_MAP = {
      "Bigint" => "bigint", "Int" => "bigint",
      "i64" => "bigint", "u64" => "bigint",
      "i128" => "bigint", "u128" => "bigint",
      "i256" => "bigint", "u256" => "bigint",
      "bigint" => "bigint",
      "Bool" => "boolean", "bool" => "boolean", "boolean" => "boolean",
      "ByteString" => "ByteString",
      "PubKey" => "PubKey", "Sig" => "Sig", "Sha256" => "Sha256", "Sha256Digest" => "Sha256",
      "Ripemd160" => "Ripemd160", "Addr" => "Addr",
      "SigHashPreimage" => "SigHashPreimage",
      "RabinSig" => "RabinSig", "RabinPubKey" => "RabinPubKey",
      "Point" => "Point",
    }.freeze

    def self.rust_snake_to_camel(name)
      parts = name.split("_")
      return name if parts.length <= 1

      result = parts[0]
      parts[1..].each do |part|
        next if part.empty?

        result += part[0].upcase + part[1..]
      end
      result
    end

    def self.map_rust_builtin(name)
      return RUST_SPECIAL_BUILTINS[name] if RUST_SPECIAL_BUILTINS.key?(name)

      camel = rust_snake_to_camel(name)
      return RUST_BUILTIN_MAP[camel] if RUST_BUILTIN_MAP.key?(camel)

      camel
    end

    def self.map_rust_type(name)
      return RUST_TYPE_MAP[name] if RUST_TYPE_MAP.key?(name)

      name
    end

    def self.rust_parse_type_name(name)
      mapped = map_rust_type(name)
      if primitive_type?(mapped)
        return PrimitiveType.new(name: mapped)
      end

      CustomType.new(name: mapped)
    end

    # -----------------------------------------------------------------------
    # Tokenizer
    # -----------------------------------------------------------------------

    RUST_KEYWORDS = {
      "use"    => RustTokens::TOK_USE,
      "struct" => RustTokens::TOK_STRUCT,
      "impl"   => RustTokens::TOK_IMPL,
      "fn"     => RustTokens::TOK_FN,
      "pub"    => RustTokens::TOK_PUB,
      "let"    => RustTokens::TOK_LET,
      "mut"    => RustTokens::TOK_MUT,
      "if"     => RustTokens::TOK_IF,
      "else"   => RustTokens::TOK_ELSE,
      "for"    => RustTokens::TOK_FOR,
      "return" => RustTokens::TOK_RETURN,
      "in"     => RustTokens::TOK_IN,
      "true"   => RustTokens::TOK_TRUE,
      "false"  => RustTokens::TOK_FALSE,
      "self"   => RustTokens::TOK_SELF,
    }.freeze

    HEX_DIGITS_SET = "0123456789abcdefABCDEF"

    def self.tokenize_rust(source)
      tokens = []
      n = source.length
      pos = 0
      line = 1
      col = 1

      while pos < n
        ch = source[pos]

        # Whitespace
        if ch == " " || ch == "\t" || ch == "\r" || ch == "\n"
          if ch == "\n"
            line += 1
            col = 1
          else
            col += 1
          end
          pos += 1
          next
        end

        # Line comments (including ///)
        if ch == "/" && pos + 1 < n && source[pos + 1] == "/"
          while pos < n && source[pos] != "\n"
            pos += 1
          end
          next
        end

        # Block comments /* ... */
        if ch == "/" && pos + 1 < n && source[pos + 1] == "*"
          pos += 2
          col += 2
          while pos + 1 < n
            if source[pos] == "\n"
              line += 1
              col = 1
            end
            if source[pos] == "*" && source[pos + 1] == "/"
              pos += 2
              col += 2
              break
            end
            pos += 1
            col += 1
          end
          next
        end

        l = line
        c = col

        # Two-character operators (check longer first)
        if pos + 1 < n
          two = source[pos, 2]
          two_kind = case two
                     when "::" then RustTokens::TOK_COLONCOLON
                     when "->" then RustTokens::TOK_ARROW
                     when "==" then RustTokens::TOK_EQEQ
                     when "!=" then RustTokens::TOK_BANGEQ
                     when "<=" then RustTokens::TOK_LTEQ
                     when ">=" then RustTokens::TOK_GTEQ
                     when "&&" then RustTokens::TOK_AMPAMP
                     when "||" then RustTokens::TOK_PIPEPIPE
                     when "+=" then RustTokens::TOK_PLUSEQ
                     when "-=" then RustTokens::TOK_MINUSEQ
                     when "*=" then RustTokens::TOK_STAREQ
                     when "/=" then RustTokens::TOK_SLASHEQ
                     when "%=" then RustTokens::TOK_PERCENTEQ
                     when "++" then RustTokens::TOK_PLUSPLUS
                     when "--" then RustTokens::TOK_MINUSMINUS
                     when "<<" then RustTokens::TOK_LSHIFT
                     when ">>" then RustTokens::TOK_RSHIFT
                     when ".." then RustTokens::TOK_DOTDOT
                     end

          if two_kind
            tokens << RustToken.new(kind: two_kind, value: two, line: l, col: c)
            pos += 2
            col += 2
            next
          end
        end

        # Single-character tokens
        single_kind = case ch
                      when "(" then RustTokens::TOK_LPAREN
                      when ")" then RustTokens::TOK_RPAREN
                      when "{" then RustTokens::TOK_LBRACE
                      when "}" then RustTokens::TOK_RBRACE
                      when "[" then RustTokens::TOK_LBRACKET
                      when "]" then RustTokens::TOK_RBRACKET
                      when ";" then RustTokens::TOK_SEMI
                      when "," then RustTokens::TOK_COMMA
                      when "." then RustTokens::TOK_DOT
                      when ":" then RustTokens::TOK_COLON
                      when "+" then RustTokens::TOK_PLUS
                      when "-" then RustTokens::TOK_MINUS
                      when "*" then RustTokens::TOK_STAR
                      when "/" then RustTokens::TOK_SLASH
                      when "%" then RustTokens::TOK_PERCENT
                      when "<" then RustTokens::TOK_LT
                      when ">" then RustTokens::TOK_GT
                      when "&" then RustTokens::TOK_AMP
                      when "|" then RustTokens::TOK_PIPE
                      when "^" then RustTokens::TOK_CARET
                      when "~" then RustTokens::TOK_TILDE
                      when "!" then RustTokens::TOK_BANG
                      when "=" then RustTokens::TOK_EQ
                      when "#" then RustTokens::TOK_HASH
                      end

        if single_kind
          tokens << RustToken.new(kind: single_kind, value: ch, line: l, col: c)
          pos += 1
          col += 1
          next
        end

        # String literal
        if ch == '"'
          pos += 1
          col += 1
          val = +""
          while pos < n && source[pos] != '"'
            if source[pos] == "\\"
              pos += 1
              col += 1
              val << source[pos] if pos < n
            else
              val << source[pos]
            end
            pos += 1
            col += 1
          end
          pos += 1 if pos < n # closing quote
          col += 1
          tokens << RustToken.new(kind: RustTokens::TOK_STRING, value: val, line: l, col: c)
          next
        end

        # Hex literal: 0x...
        if ch == "0" && pos + 1 < n && (source[pos + 1] == "x" || source[pos + 1] == "X")
          pos += 2
          col += 2
          start = pos
          while pos < n && HEX_DIGITS_SET.include?(source[pos])
            pos += 1
            col += 1
          end
          val = source[start...pos]
          tokens << RustToken.new(kind: RustTokens::TOK_HEXSTRING, value: val, line: l, col: c)
          next
        end

        # Number
        if ch >= "0" && ch <= "9"
          start = pos
          while pos < n && ((source[pos] >= "0" && source[pos] <= "9") || source[pos] == "_")
            pos += 1
            col += 1
          end
          val = source[start...pos].delete("_")
          tokens << RustToken.new(kind: RustTokens::TOK_NUMBER, value: val, line: l, col: c)
          next
        end

        # Identifier / keyword
        if (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch == "_"
          start = pos
          while pos < n && ((source[pos] >= "a" && source[pos] <= "z") ||
                            (source[pos] >= "A" && source[pos] <= "Z") ||
                            (source[pos] >= "0" && source[pos] <= "9") ||
                            source[pos] == "_")
            pos += 1
            col += 1
          end
          word = source[start...pos]

          # Check for assert!/assert_eq! macros
          if (word == "assert" || word == "assert_eq") && pos < n && source[pos] == "!"
            pos += 1
            col += 1
            tokens << RustToken.new(kind: RustTokens::TOK_ASSERT_MACRO, value: "#{word}!", line: l, col: c)
            next
          end

          kw_kind = RUST_KEYWORDS[word]
          if kw_kind
            tokens << RustToken.new(kind: kw_kind, value: word, line: l, col: c)
          else
            tokens << RustToken.new(kind: RustTokens::TOK_IDENT, value: word, line: l, col: c)
          end
          next
        end

        # Skip unknown
        pos += 1
        col += 1
      end

      tokens << RustToken.new(kind: RustTokens::TOK_EOF, value: "", line: line, col: col)
      tokens
    end

    # -----------------------------------------------------------------------
    # Parser
    # -----------------------------------------------------------------------

    class RustParser
      include RustTokens

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

      # -- Error helpers ----------------------------------------------------

      def add_error(msg)
        @errors << Diagnostic.new(message: msg, severity: Severity::ERROR)
      end

      # -- Token helpers ----------------------------------------------------

      def peek
        return @tokens[@pos] if @pos < @tokens.length

        RustToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
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

      def peek_next
        return @tokens[@pos + 1] if @pos + 1 < @tokens.length

        RustToken.new(kind: TOK_EOF, value: "", line: 0, col: 0)
      end

      # -- Top-level parsing ------------------------------------------------

      def parse_contract
        # Skip use declarations
        skip_use_decls

        parent_class = "SmartContract"
        properties = []
        methods = []

        until check(TOK_EOF)
          # Attributes at top level
          if check(TOK_HASH)
            attr = parse_attribute
            if attr == "runar::contract" || attr == "runar::stateful_contract"
              # Optional pub before struct
              advance if check(TOK_PUB)
              if check(TOK_STRUCT)
                result = parse_struct_decl
                if result
                  @contract_name = result[:name]
                  parent_class = result[:parent_class]
                  properties = result[:properties]
                end
              end
              next
            end
            if attr.start_with?("runar::methods")
              if check(TOK_IMPL)
                impl_methods = parse_impl_block
                methods.concat(impl_methods)
              end
              next
            end
            # Other attributes -- skip
            next
          end

          if check(TOK_PUB) || check(TOK_STRUCT)
            advance if check(TOK_PUB)
            if check(TOK_STRUCT)
              result = parse_struct_decl
              if result
                @contract_name = result[:name]
                parent_class = result[:parent_class]
                properties = result[:properties]
              end
              next
            end
          end

          if check(TOK_IMPL)
            impl_methods = parse_impl_block
            methods.concat(impl_methods)
            next
          end

          # Skip unknown top-level tokens
          advance
        end

        # Process init() method: extract property initializers
        final_methods = []
        methods.each do |m|
          if m.name == "init" && m.params.empty?
            m.body.each do |stmt|
              if stmt.is_a?(AssignmentStmt) && stmt.target.is_a?(PropertyAccessExpr)
                prop_name = stmt.target.property
                properties.each_with_index do |p, i|
                  if p.name == prop_name
                    properties[i] = PropertyNode.new(
                      name: p.name, type: p.type, readonly: p.readonly,
                      initializer: stmt.value, source_location: p.source_location
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
        default_loc = SourceLocation.new(file: @file_name, line: 1, column: 1)
        uninit_props = properties.reject { |p| p.initializer }

        ctor_params = uninit_props.map { |p| ParamNode.new(name: p.name, type: p.type) }

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
          params: ctor_params,
          body: [super_call] + assignments,
          visibility: "public",
          source_location: default_loc
        )

        ContractNode.new(
          name: @contract_name.empty? ? "UnnamedContract" : @contract_name,
          parent_class: parent_class,
          properties: properties,
          constructor: constructor,
          methods: final_methods,
          source_file: @file_name
        )
      end

      # -- Use declaration skipping ------------------------------------------

      def skip_use_decls
        while check(TOK_USE)
          until check(TOK_SEMI) || check(TOK_EOF)
            advance
          end
          advance if check(TOK_SEMI)
        end
      end

      # -- Attribute parsing: #[...] -> string content -----------------------

      def parse_attribute
        expect(TOK_HASH)
        expect(TOK_LBRACKET)
        content = +""
        depth = 1
        while depth > 0 && !check(TOK_EOF)
          if check(TOK_LBRACKET)
            depth += 1
          end
          if check(TOK_RBRACKET)
            depth -= 1
            break if depth == 0
          end
          content << peek.value
          advance
        end
        expect(TOK_RBRACKET)
        content
      end

      # -- Struct declaration ------------------------------------------------

      def parse_struct_decl
        expect(TOK_STRUCT)
        name_tok = expect(TOK_IDENT)
        name = name_tok.value
        expect(TOK_LBRACE)

        properties = []
        has_mutable_field = false

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          prop_loc = loc
          is_readonly = false

          # Check for #[readonly]
          if check(TOK_HASH)
            attr = parse_attribute
            is_readonly = true if attr == "readonly"
          end

          # Skip optional pub
          advance if check(TOK_PUB)

          # Field name
          field_name_raw = expect(TOK_IDENT).value
          field_name = Frontend.rust_snake_to_camel(field_name_raw)

          # Colon + type
          expect(TOK_COLON)
          prop_type = parse_rust_type

          has_mutable_field = true unless is_readonly

          # Skip txPreimage (implicit in stateful contracts)
          if field_name == "txPreimage"
            match_tok(TOK_COMMA)
            next
          end

          properties << PropertyNode.new(
            name: field_name,
            type: prop_type,
            readonly: is_readonly,
            source_location: prop_loc
          )

          match_tok(TOK_COMMA)
        end
        expect(TOK_RBRACE)

        parent_class = has_mutable_field ? "StatefulSmartContract" : "SmartContract"

        { name: name, parent_class: parent_class, properties: properties }
      end

      # -- Type parsing ------------------------------------------------------

      def parse_rust_type
        # Handle reference types: &Type, &mut Type
        if check(TOK_AMP)
          advance
          advance if check(TOK_MUT)
          return parse_rust_type
        end

        # Handle array types: [Type; N]
        if check(TOK_LBRACKET)
          advance
          element = parse_rust_type
          expect(TOK_SEMI)
          length_tok = expect(TOK_NUMBER)
          length = begin
            Integer(length_tok.value, 10)
          rescue ArgumentError
            0
          end
          expect(TOK_RBRACKET)
          return FixedArrayType.new(element: element, length: length)
        end

        if check(TOK_IDENT) || check(TOK_SELF)
          type_name = advance.value
          mapped = Frontend.map_rust_type(type_name)
          return Frontend.rust_parse_type_name(mapped)
        end

        # bool keyword mapped to token
        if check(TOK_TRUE) || check(TOK_FALSE)
          advance
          return PrimitiveType.new(name: "boolean")
        end

        # Fallback
        advance
        CustomType.new(name: "unknown")
      end

      # -- Impl block -------------------------------------------------------

      def parse_impl_block
        expect(TOK_IMPL)
        # Skip struct name
        advance if check(TOK_IDENT)
        expect(TOK_LBRACE)

        methods = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          is_public = false
          while check(TOK_HASH)
            attr = parse_attribute
            is_public = true if attr == "public"
          end

          # Skip optional pub
          advance if check(TOK_PUB)

          if check(TOK_FN)
            method = parse_fn_decl(is_public)
            methods << method if method
          else
            advance
          end
        end
        expect(TOK_RBRACE)

        methods
      end

      # -- Function/method declaration ---------------------------------------

      def parse_fn_decl(is_public)
        location = loc
        expect(TOK_FN)

        raw_name = expect(TOK_IDENT).value
        name = Frontend.rust_snake_to_camel(raw_name)

        expect(TOK_LPAREN)
        params = []

        while !check(TOK_RPAREN) && !check(TOK_EOF)
          # Handle &self, &mut self, self
          if check(TOK_AMP)
            advance
            advance if check(TOK_MUT)
            if check(TOK_SELF)
              advance
              match_tok(TOK_COMMA)
              next
            end
          end
          if check(TOK_SELF)
            advance
            match_tok(TOK_COMMA)
            next
          end
          if check(TOK_MUT) && peek_next.kind == TOK_SELF
            advance # mut
            advance # self
            match_tok(TOK_COMMA)
            next
          end

          # Normal parameter: name: Type
          param_name_raw = expect(TOK_IDENT).value
          expect(TOK_COLON)
          param_type = parse_rust_type

          params << ParamNode.new(
            name: Frontend.rust_snake_to_camel(param_name_raw),
            type: param_type
          )

          match_tok(TOK_COMMA)
        end
        expect(TOK_RPAREN)

        # Optional return type: -> Type
        has_return_type = false
        if check(TOK_ARROW)
          advance
          parse_rust_type # consume but don't store
          has_return_type = true
        end

        # Body
        expect(TOK_LBRACE)
        body = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          stmt = parse_statement
          body << stmt if stmt
        end
        expect(TOK_RBRACE)

        # Rust implicit returns: convert last expression_statement to return
        if has_return_type && !body.empty?
          last = body.last
          if last.is_a?(ExpressionStmt)
            body[-1] = ReturnStmt.new(value: last.expr, source_location: last.source_location)
          end
        end

        visibility = is_public ? "public" : "private"

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

        # return [expr];
        if check(TOK_RETURN)
          advance
          value = nil
          if !check(TOK_SEMI) && !check(TOK_RBRACE)
            value = parse_expression
          end
          match_tok(TOK_SEMI)
          return ReturnStmt.new(value: value, source_location: location)
        end

        # if statement
        if check(TOK_IF)
          return parse_if_statement(location)
        end

        # for statement
        if check(TOK_FOR)
          return parse_for_statement(location)
        end

        # let [mut] name [: type] = expr;
        if check(TOK_LET)
          advance
          is_mutable = false
          if check(TOK_MUT)
            advance
            is_mutable = true
          end
          var_name = Frontend.rust_snake_to_camel(expect(TOK_IDENT).value)
          var_type = nil
          if check(TOK_COLON)
            advance
            var_type = parse_rust_type
          end
          expect(TOK_EQ)
          init = parse_expression
          match_tok(TOK_SEMI)
          return VariableDeclStmt.new(
            name: var_name, type: var_type, mutable: is_mutable,
            init: init, source_location: location
          )
        end

        # assert!(expr)
        if check(TOK_ASSERT_MACRO)
          tok = advance
          expect(TOK_LPAREN)
          if tok.value == "assert_eq!"
            left = parse_expression
            expect(TOK_COMMA)
            right = parse_expression
            expect(TOK_RPAREN)
            match_tok(TOK_SEMI)
            cond = BinaryExpr.new(op: "===", left: left, right: right)
            return ExpressionStmt.new(
              expr: CallExpr.new(callee: Identifier.new(name: "assert"), args: [cond]),
              source_location: location
            )
          else
            expr = parse_expression
            expect(TOK_RPAREN)
            match_tok(TOK_SEMI)
            return ExpressionStmt.new(
              expr: CallExpr.new(callee: Identifier.new(name: "assert"), args: [expr]),
              source_location: location
            )
          end
        end

        # runar::assert(expr) — identifier that starts with runar prefix
        if check(TOK_IDENT) && peek.value == "runar" && peek_next.kind == TOK_COLONCOLON
          advance # runar
          advance # ::
          fn_name = advance.value # assert or other
          if fn_name == "assert" && check(TOK_LPAREN)
            expect(TOK_LPAREN)
            expr = parse_expression
            expect(TOK_RPAREN)
            match_tok(TOK_SEMI)
            return ExpressionStmt.new(
              expr: CallExpr.new(callee: Identifier.new(name: "assert"), args: [expr]),
              source_location: location
            )
          end
          # Other runar:: function — treat as expression
          @pos -= 1 # back up to handle in expression parsing
        end

        # Expression statement
        expr = parse_expression

        # Assignment: expr = expr
        if check(TOK_EQ)
          advance
          value = parse_expression
          match_tok(TOK_SEMI)
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
          if match_tok(kind)
            right = parse_expression
            match_tok(TOK_SEMI)
            value = BinaryExpr.new(op: bin_op, left: expr, right: right)
            return AssignmentStmt.new(target: expr, value: value, source_location: location)
          end
        end

        # Postfix ++/--
        if match_tok(TOK_PLUSPLUS)
          match_tok(TOK_SEMI)
          return ExpressionStmt.new(
            expr: IncrementExpr.new(operand: expr, prefix: false),
            source_location: location
          )
        end
        if match_tok(TOK_MINUSMINUS)
          match_tok(TOK_SEMI)
          return ExpressionStmt.new(
            expr: DecrementExpr.new(operand: expr, prefix: false),
            source_location: location
          )
        end

        match_tok(TOK_SEMI)
        ExpressionStmt.new(expr: expr, source_location: location)
      end

      def parse_if_statement(location)
        expect(TOK_IF)
        condition = parse_expression
        expect(TOK_LBRACE)
        then_block = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          stmt = parse_statement
          then_block << stmt if stmt
        end
        expect(TOK_RBRACE)

        else_block = nil
        if check(TOK_ELSE)
          advance
          if check(TOK_IF)
            else_block = [parse_if_statement(loc)]
          else
            expect(TOK_LBRACE)
            else_block = []
            while !check(TOK_RBRACE) && !check(TOK_EOF)
              stmt = parse_statement
              else_block << stmt if stmt
            end
            expect(TOK_RBRACE)
          end
        end

        IfStmt.new(
          condition: condition,
          then: then_block,
          else_: else_block || [],
          source_location: location
        )
      end

      def parse_for_statement(location)
        expect(TOK_FOR)

        loop_var_raw = expect(TOK_IDENT).value
        loop_var = Frontend.rust_snake_to_camel(loop_var_raw)

        expect(TOK_IN)

        start_expr = parse_expression
        expect(TOK_DOTDOT)
        end_expr = parse_expression

        expect(TOK_LBRACE)
        body = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          stmt = parse_statement
          body << stmt if stmt
        end
        expect(TOK_RBRACE)

        init = VariableDeclStmt.new(
          name: loop_var, mutable: true, init: start_expr, source_location: location
        )
        condition = BinaryExpr.new(
          op: "<",
          left: Identifier.new(name: loop_var),
          right: end_expr
        )
        update = ExpressionStmt.new(
          expr: IncrementExpr.new(
            operand: Identifier.new(name: loop_var),
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

      # -- Expression parsing ------------------------------------------------
      # Operator precedence (lowest to highest):
      #   ternary (condition ? a : b)  — not in Rust, but handle for completeness
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
      #   unary (! - ~ &)
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
        # Skip reference operator & in expression context
        if check(TOK_AMP) && (peek_next.kind == TOK_MUT || peek_next.kind == TOK_IDENT ||
                               peek_next.kind == TOK_SELF || peek_next.kind == TOK_LPAREN)
          # Check if this is & reference (not && which is already handled)
          advance
          advance if check(TOK_MUT)
          return parse_unary
        end
        # Prefix ++/--
        if match_tok(TOK_PLUSPLUS)
          operand = parse_unary
          return IncrementExpr.new(operand: operand, prefix: true)
        end
        if match_tok(TOK_MINUSMINUS)
          operand = parse_unary
          return DecrementExpr.new(operand: operand, prefix: true)
        end
        parse_postfix
      end

      def parse_postfix
        expr = parse_primary
        loop do
          # Member access: expr.name or expr.name(...)
          if match_tok(TOK_DOT)
            raw_prop = peek.value
            advance
            prop = Frontend.rust_snake_to_camel(raw_prop)

            # Strip .clone()
            if prop == "clone" && check(TOK_LPAREN)
              advance # (
              expect(TOK_RPAREN)
              next
            end

            # Check for method call
            if check(TOK_LPAREN)
              args = parse_call_args
              if expr.is_a?(Identifier) && expr.name == "self"
                # self.method(...) -> this.method(...)
                expr = CallExpr.new(
                  callee: MemberExpr.new(
                    object: Identifier.new(name: "this"),
                    property: prop
                  ),
                  args: args
                )
              else
                expr = CallExpr.new(
                  callee: MemberExpr.new(object: expr, property: prop),
                  args: args
                )
              end
            else
              # Property access
              if expr.is_a?(Identifier) && expr.name == "self"
                expr = PropertyAccessExpr.new(property: prop)
              else
                expr = MemberExpr.new(object: expr, property: prop)
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

          # Postfix ++/--
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

      def callable?(expr)
        expr.is_a?(Identifier) || expr.is_a?(MemberExpr)
      end

      def parse_call_args
        expect(TOK_LPAREN)
        args = []
        while !check(TOK_RPAREN) && !check(TOK_EOF)
          # Strip leading & in arguments
          if check(TOK_AMP)
            advance
            advance if check(TOK_MUT)
          end
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

        # Array literal: [expr, expr, ...]
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

        # self keyword
        if tok.kind == TOK_SELF
          advance
          return Identifier.new(name: "self")
        end

        # Identifier (possibly with runar:: prefix)
        if tok.kind == TOK_IDENT
          advance
          raw_name = tok.value

          # Handle runar:: prefix (e.g. runar::assert, runar::hash160)
          if raw_name == "runar" && check(TOK_COLONCOLON)
            advance # ::
            raw_name = advance.value
          end

          # Handle StructName { field: value, ... } — Self/struct literal in init
          if raw_name == "Self" || raw_name == @contract_name
            if check(TOK_LBRACE)
              # This is a struct literal used in init() — skip it, parse fields as dummy
              advance # {
              while !check(TOK_RBRACE) && !check(TOK_EOF)
                advance # field name or value
              end
              match_tok(TOK_RBRACE)
              return Identifier.new(name: raw_name)
            end
          end

          camel_name = Frontend.rust_snake_to_camel(raw_name)
          name = Frontend.map_rust_builtin(raw_name)
          # If the special builtin map didn't match, use the camel version
          name = RUST_BUILTIN_MAP[camel_name] || camel_name if name == camel_name && name != raw_name

          return Identifier.new(name: name)
        end

        # Fallback
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

    # Parse a Rust-syntax Runar contract (.runar.rs).
    #
    # @param source [String] the source code
    # @param file_name [String] the file name (used in diagnostics)
    # @return [ParseResult]
    def self.parse_rust(source, file_name)
      p = RustParser.new(file_name)
      p.tokens = tokenize_rust(source)
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
