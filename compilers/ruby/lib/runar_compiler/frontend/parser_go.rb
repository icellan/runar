# frozen_string_literal: true

# Go contract format parser (.runar.go) for the Runar compiler.
#
# Ported from packages/runar-compiler/src/passes/01-parse-go.ts.
# Hand-written tokenizer + recursive descent parser for Go contract syntax.

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "parse_result"
require_relative "identifier_collision"
require_relative "input_limits"
require_relative "sighash_directive"

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
      "Ripemd160Hash"   => "Ripemd160",
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
      # the *Big peers of num2bin / bin2num. They lower to the SAME builtins as Num2Bin / Bin2Num, exactly as compilers/go has always done: the suffix names a different Go RUNTIME type (*big.Int, so the Go-side mock does not truncate), not a different Script operation. Six tiers fell through to the default rule and produced `num2BinBig` / `bin2NumBig`, names no builtin registry has (R-Bigint)
      "Num2BinBig" => "num2bin",
      "Bin2NumBig" => "bin2num",

      # the *Big peers of abs / gcd. Same rule as Num2BinBig / Bin2NumBig above: the
      # suffix names a different Go RUNTIME type (*big.Int, so the Go-side mock does
      # not narrow at MinInt64), not a different Script operation -- OP_ABS and the gcd
      # builtin are arbitrary-width after Genesis. These were mapped in ZERO tiers
      # while `Abs(math.MinInt64)` and `Gcd(math.MinInt64, 0)` in packages/runar-go
      # panic telling the author to use them, naming the .runar.go parser as the thing
      # that lowers them.
      "AbsBig" => "abs",
      "GcdBig" => "gcd",
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
      # NIST EC curves
      "VerifyECDSAP256" => "verifyECDSA_P256",
      "VerifyECDSAP384" => "verifyECDSA_P384",
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
      # Intent sub-covenant intrinsics (BSVM Phase 13)
      "ExtractPrevOutputScript" => "extractPrevOutputScript",
      "RequireOutputP2PKH" => "requireOutputP2PKH",
      "CurrentBlockHeight" => "currentBlockHeight",
      "ContinuationAmount" => "continuationAmount",
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
    #
    # MUST stay disjoint from GO_BUILTIN_MAP. `Sha256` and `Ripemd160` are both
    # Rúnar type names and Rúnar builtin names, and the Go surface spells a cast
    # and a call identically -- `runar.Sha256(x)`. While both names sat here the
    # cast branch ran first and `runar.Sha256(preimage)` unwrapped to its own
    # argument: `assert(sha256(x) == digest)` compiled to `assert(x == digest)`,
    # with the digest in the locking script for anyone to read and push back.
    #
    # In call position the FUNCTION wins. docs/formats/go.md has documented
    # `runar.Sha256(data)` -> `sha256(data)` since the surface shipped, five of
    # the seven tiers already implemented it, and the cast reading loses nothing:
    # both names are ByteString subtypes, so the conversion was an identity on
    # the value and a no-op on the bytes. They still resolve as TYPES -- that is
    # GO_TYPE_MAP, consulted from type position only.
    #
    # test/test_parser_go.rb asserts the disjointness; adding a name to both
    # tables is what reintroduces the bug.
    GO_CAST_TYPES = %w[
      Int Bigint BigintBig Bool ByteString PubKey Sig
      Addr SigHashPreimage RabinSig RabinPubKey Point
    ].to_set.freeze

    # The Rúnar binary operator each `BigintBig` helper stands for.
    #
    # runar.BigintBig is *big.Int in packages/runar-go and Go has no operator
    # overloading, so a .runar.go contract carrying arbitrary-precision values
    # spells `a === b` as `runar.BigintBigEqual(a, b)` -- and it has to emit the
    # script the operator emits. Mirrors bigintBigOpFor in
    # compilers/go/frontend/parser_gocontract.go and its peers in the TS, Rust,
    # Python, Zig and Java tiers, plus the eleven helpers in
    # packages/runar-go/runar.go. The rewrite lived only in compilers/go until
    # R-Bigint, although all seven tiers parse .runar.go -- a frontend-parity
    # break no fixture exercised.
    GO_BIGINTBIG_OPS = {
      "BigintBigLess"       => "<",
      "BigintBigLessEq"     => "<=",
      "BigintBigGreater"    => ">",
      "BigintBigGreaterEq"  => ">=",
      "BigintBigEqual"      => "===",
      "BigintBigNotEqual"   => "!==",
      "BigintBigAdd"        => "+",
      "BigintBigSub"        => "-",
      "BigintBigMul"        => "*",
      "BigintBigMod"        => "%",
      "BigintBigDiv"        => "/"
    }.freeze

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

    # +directives+ (N-093) collects every Go DSL directive comment
    # `//runar:<name> <args>` (Go's own `//go:` convention: no space after
    # `//`) as {name:, args:, token_index:, line:, column:}. +token_index+ is
    # the index of the first token after the comment, so a directive attaches
    # to the declaration that follows it, with only comments and blank lines
    # in between.
    def self.tokenize_go(source, lex = [], file_name = "", directives = [])
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
          comment_start = i
          while i < n && source[i] != "\n" && source[i] != "\r"
            i += 1
          end
          # N-093: `//runar:<name> <args>` is a directive, not prose.
          text = source[comment_start...i]
          if text.start_with?("//runar:")
            body = text["//runar:".length..]
            dname = body[/\A[^ \t]*/]
            directives << { name: dname, args: body[dname.length..], token_index: tokens.length,
                             line: line, column: col }
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
          tag_line = line
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
          # F-011: a raw string may span lines, so only end of file leaves it
          # unterminated.
          if i < n
            i += 1
            col += 1
          else
            lex << Frontend.lex_error(UNTERMINATED_STRING_LITERAL, file_name, tag_line, start_col)
          end
          tokens << GoToken.new(kind: GoTokens::TOK_BACKTICK, value: val, line: line, col: start_col)
          next
        end

        # String literal
        if ch == '"'
          i += 1
          col += 1
          str_start = i
          # F-011: a literal that reaches a line break (escaped or not) or end
          # of file is unterminated; it must never run on into the next lines.
          while i < n && source[i] != '"' && source[i] != "\n" && source[i] != "\r"
            if source[i] == "\\"
              break if i + 1 >= n || source[i + 1] == "\n" || source[i + 1] == "\r"

              i += 1
              col += 1
            end
            if i < n
              i += 1
              col += 1
            end
          end
          val = source[str_start...i]
          if i < n && source[i] == '"'
            i += 1
            col += 1
          else
            lex << Frontend.lex_error(UNTERMINATED_STRING_LITERAL, file_name, line, start_col)
          end
          tokens << GoToken.new(kind: GoTokens::TOK_STRING, value: val, line: line, col: start_col)
          next
        end

        # Number (F-026): the whole glued [0-9A-Za-z_] run is one literal.
        if ch >= "0" && ch <= "9"
          stop, value, = IntLiteral.lex_number("go", source, i, lex, file_name, line, start_col)
          col += stop - i
          i = stop
          tokens << GoToken.new(kind: GoTokens::TOK_NUMBER, value: value, line: line, col: start_col)
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

    # F-010 diagnostics -- emitted verbatim by every tier's .runar.go parser
    # (TS reference: goNoContractMessage / goMultipleContractsMessage /
    # goForeignReceiverMessage in packages/runar-compiler/src/passes/01-parse-go.ts).
    GO_NO_CONTRACT_MESSAGE = "no Rúnar contract struct found in Go source"

    def self.go_multiple_contracts_message(first, second)
      "multiple Rúnar contract structs found in Go source: '#{first}' and '#{second}'; " \
        "exactly one struct may embed runar.SmartContract, runar.StatefulSmartContract or runar.UnsafeSmartContract"
    end

    def self.go_foreign_receiver_message(method, receiver_type, contract)
      "method '#{method}' has receiver type '#{receiver_type}', not the contract type '#{contract}'; " \
        "methods on other types are not allowed"
    end

    # -------------------------------------------------------------------------
    # N-056 -- ambiguous operator precedence (mirrors 01-parse-go.ts)
    # -------------------------------------------------------------------------
    #
    # Go: `* / % << >> & &^` > `+ - | ^` > comparisons > `&&` > `||`. C ladder
    # (this parser): MulDiv > AddSub > Shift > Comparison > Equality > BitAnd >
    # BitXor > BitOr > And > Or. For `x OP1 y OP2 z` a scheme groups left iff
    # prec(OP1) >= prec(OP2). The ordered (OP1 class, OP2 class) pairs on which
    # the schemes disagree: 23 class pairs, 72 operator pairs. `&^` lexes as
    # `&` over a prefix `^`, i.e. `&`.

    GO_PRECEDENCE_CLASS = {
      "*" => "mul", "/" => "mul", "%" => "mul",
      "<<" => "shift", ">>" => "shift",
      "&" => "and",
      "+" => "add", "-" => "add",
      "|" => "or", "^" => "xor",
      "<" => "rel", "<=" => "rel", ">" => "rel", ">=" => "rel",
      "===" => "eq", "!==" => "eq",
      "&&" => "land", "||" => "lor"
    }.freeze

    GO_AMBIGUOUS_PRECEDENCE_PAIRS = Set[
      %w[shift mul], %w[shift add],
      %w[and mul], %w[and shift], %w[and add], %w[and rel], %w[and eq],
      %w[add shift], %w[add and],
      %w[or add], %w[or xor], %w[or rel], %w[or eq],
      %w[xor add], %w[xor rel], %w[xor eq],
      %w[rel and], %w[rel or], %w[rel xor],
      %w[eq and], %w[eq or], %w[eq xor], %w[eq rel]
    ].freeze

    def self.go_ambiguous_precedence?(first, second)
      GO_AMBIGUOUS_PRECEDENCE_PAIRS.include?([GO_PRECEDENCE_CLASS[first], GO_PRECEDENCE_CLASS[second]])
    end

    def self.go_ambiguous_precedence_message(first, second)
      go = { "===" => "==", "!==" => "!=" }
      "ambiguous operator precedence in .runar.go: `a #{go.fetch(first, first)} b " \
        "#{go.fetch(second, second)} c` groups differently under Go precedence than in " \
        "Rúnar's other surfaces; add parentheses"
    end

    class GoParser
      include InputLimits::NestingCounter

      include GoTokens

      def initialize(file_name)
        @file_name = file_name
        @tokens = []
        @pos = 0
        @errors = []
        @self_names = Set.new
        @contract_name = ""
        @go_atoms = {}.compare_by_identity # N-056: expression operands
      end

      attr_accessor :tokens, :pos, :errors

      # N-093: every `//runar:` directive in the file, in source order.
      attr_writer :directives

      # F-017: (source spelling, Rúnar name) of every declared identifier.
      attr_reader :declared

      # Convert a DECLARED identifier and record it for the F-017 collision
      # rule (see identifier_collision.rb).
      def declare(raw)
        name = Frontend.go_to_camel(raw)
        (@declared ||= []) << [raw, name]
        name
      end

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

        structs = []
        funcs = []

        # Parse top-level declarations
        while !check(TOK_EOF)
          if check_ident("type")
            structs << parse_struct_decl
          elsif check_ident("func")
            funcs << parse_func_decl
          else
            advance # skip unknown top-level tokens
          end
        end
        report_stray_directives

        # F-010: the contract is THE struct embedding a Rúnar base class --
        # never "the last struct in the file". Any other struct is ignored,
        # and a method whose receiver is not the contract type is refused:
        # before this rule an exported method on a helper type became a
        # public entry point.
        contracts = structs.select { |st| st[:embeds_base] }
        if contracts.empty?
          add_error(Frontend::GO_NO_CONTRACT_MESSAGE)
          return nil
        end
        contract_struct = contracts.first
        contracts.drop(1).each do |extra|
          add_error(Frontend.go_multiple_contracts_message(contract_struct[:name], extra[:name]))
        end
        @contract_name = contract_struct[:name]
        parent_class = contract_struct[:parent_class]
        properties = contract_struct[:properties].dup
        methods = []
        funcs.each do |f|
          if !f[:receiver_type].nil? && f[:receiver_type] != @contract_name
            add_error(Frontend.go_foreign_receiver_message(f[:go_name], f[:receiver_type], @contract_name))
            next
          end
          # N-018: a free `init`/`main` is not an ordinary private helper.
          # Real Go reserves both names for the package initializer / entry
          # point, which can never be called as a function.
          next if f[:receiver_type].nil? && %w[init main].include?(f[:go_name])

          methods << f[:method]
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
                      source_location: prop.source_location,
                      synthetic_array_chain: prop.synthetic_array_chain,
                      embed_always: prop.embed_always
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
        embeds_base = false
        properties = []

        while !check(TOK_RBRACE) && !check(TOK_EOF)
          prop_loc = loc

          # Check for embedded type:
          # runar.SmartContract / runar.StatefulSmartContract / runar.UnsafeSmartContract
          if check_ident("runar") && peek_next.kind == TOK_DOT
            advance # skip 'runar'
            advance # skip '.'
            embed_name = expect(TOK_IDENT).value
            parent_class = "StatefulSmartContract" if embed_name == "StatefulSmartContract"
            parent_class = "UnsafeSmartContract" if embed_name == "UnsafeSmartContract"
            embeds_base = true if %w[SmartContract StatefulSmartContract UnsafeSmartContract].include?(embed_name)
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

          # Check for struct tag. The `runar` key holds comma-separated
          # options (N-093): `readonly`, and `embedAlways` -- the native
          # spelling of the `@embedAlways` directive -- in any order.
          readonly = false
          embed_always = false
          if check(TOK_BACKTICK)
            tag_value = peek.value
            runar_tag = tag_value.match(/(?:\A|\s)runar:"([^"]*)"/)
            options = runar_tag ? runar_tag[1].split(",", -1).map(&:strip) : []
            readonly = true if options.include?("readonly")
            embed_always = true if options.include?("embedAlways")
            advance
          end

          field_names.each do |field_name|
            properties << PropertyNode.new(
              name: declare(field_name),
              type: prop_type,
              readonly: readonly,
              embed_always: embed_always,
              source_location: prop_loc
            )
          end
        end
        expect(TOK_RBRACE)

        { name: name, parent_class: parent_class, properties: properties, embeds_base: embeds_base }
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
          element = nested { parse_go_type }
          return FixedArrayType.new(element: element, length: length)
        end

        # Fallback
        advance
        CustomType.new(name: "unknown")
      end

      # -- Function/method declaration --------------------------------------

      # N-093: the flag specs of the `//runar:sighash` directives attached to
      # the declaration starting at token +token_index+ (nil for a malformed
      # one).
      def take_sighash_directives(token_index)
        specs = []
        (@directives || []).each do |d|
          next if d[:token_index] != token_index || d[:name] != "sighash"

          (@consumed_directives ||= Set.new.compare_by_identity) << d
          specs << (d[:args].empty? || d[:args].match?(/\A[ \t][A-Za-z0-9_| \t]*\z/) ? d[:args] : nil)
        end
        specs
      end

      # N-093: refuse every directive that is unknown or attached to no func.
      def report_stray_directives
        consumed = @consumed_directives || Set.new.compare_by_identity
        (@directives || []).each do |d|
          next if consumed.include?(d)

          msg = if d[:name] == "sighash"
                  SighashDirective.lost_directive_message("@sighash")
                else
                  SighashDirective.unknown_go_directive_message(d[:name] + d[:args])
                end
          @errors << Diagnostic.new(
            message: msg, severity: Severity::ERROR,
            loc: SourceLocation.new(file: @file_name, line: d[:line], column: d[:column])
          )
        end
      end

      def parse_func_decl
        location = loc
        # N-093: the `//runar:sighash` directives directly above this func.
        func_token_index = @pos
        expect_ident("func")

        # Check for receiver: (c *Type)
        has_receiver = false
        recv_name = ""
        receiver_type = nil

        if check(TOK_LPAREN)
          advance # '('
          recv_name = expect(TOK_IDENT).value
          # Skip '*'
          if check(TOK_STAR)
            advance
          end
          # Type name. An unnamed receiver `(Type)` has only the type.
          receiver_type = ""
          if check(TOK_IDENT)
            receiver_type = advance.value
          elsif check(TOK_RPAREN)
            receiver_type = recv_name
            recv_name = ""
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
            params << ParamNode.new(name: declare(p_name), type: p_type)
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
          skip_statement_separators
          break if check(TOK_RBRACE) || check(TOK_EOF)

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
        name = declare(func_name)

        sighash = SighashDirective.resolve_native_sighash(
          name, visibility == "public", take_sighash_directives(func_token_index)
        )
        if sighash && sighash[:error]
          @errors << Diagnostic.new(message: sighash[:error], severity: Severity::ERROR, loc: location)
        end

        method = MethodNode.new(
          name: name,
          params: params,
          body: body,
          visibility: visibility,
          source_location: location,
          sighash_type: sighash && sighash[:value]
        )
        # F-010: parse_contract checks receiver_type against the contract.
        { method: method, go_name: func_name, receiver_type: receiver_type }
      end

      # -- Statement parsing -------------------------------------------------

      def parse_statement
        nested { parse_statement_inner }
      end

      # N-154: a `;` that ends a statement on the same line separates it from
      # the next one (`a := 1; b := 2`, `runar.Assert(x);`), as go/parser
      # accepts. Any other `;` -- after another `;`, or on a later line than
      # the statement it would end (where Go has already inserted one) -- is
      # an EMPTY statement, which stays refused (N-153) with the TS
      # reference's diagnostic. Called before every statement of a block
      # (so a `;` right after `{` is refused too), never in a `for` header.
      def skip_statement_separators
        while check(TOK_SEMICOLON)
          prev = @pos.positive? ? @tokens[@pos - 1] : nil
          separates = !prev.nil? &&
                      prev.kind != TOK_LBRACE && prev.kind != TOK_SEMICOLON &&
                      prev.line == peek.line
          add_error("Unexpected token in expression: ';'") unless separates
          advance
        end
      end

      def parse_statement_inner
        location = loc

        # N-153: a `{` cannot start a statement (no block statement, and not a
        # brace composite literal). Refuse it, as the TS reference does, and
        # skip the balanced braces.
        if check(TOK_LBRACE)
          add_error("Unexpected token in expression: '{'")
          depth = 0
          loop do
            kind = advance.kind
            depth += 1 if kind == TOK_LBRACE
            depth -= 1 if kind == TOK_RBRACE
            break if depth <= 0 || check(TOK_EOF)
          end
          return ExpressionStmt.new(expr: BigIntLiteral.new(value: 0), source_location: location)
        end

        # return
        if check_ident("return")
          advance
          value = nil
          # N-154: a `;` separator also ends a bare return.
          if !check(TOK_RBRACE) && !check(TOK_EOF) && !check(TOK_SEMICOLON)
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
          var_name = declare(expect(TOK_IDENT).value)
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
          var_name = declare(advance.value)
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
          skip_statement_separators
          break if check(TOK_RBRACE) || check(TOK_EOF)

          then_block << parse_statement
        end
        expect(TOK_RBRACE)

        else_block = []
        if check_ident("else")
          advance
          if check_ident("if")
            # else if -- parse as nested if_statement in the else branch
            else_block = [nested { parse_if_statement }]
          else
            expect(TOK_LBRACE)
            while !check(TOK_RBRACE) && !check(TOK_EOF)
              skip_statement_separators
              break if check(TOK_RBRACE) || check(TOK_EOF)

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
          init_name = declare(expect(TOK_IDENT).value)
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
          skip_statement_separators
          break if check(TOK_RBRACE) || check(TOK_EOF)

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
        nested { parse_expression_inner }
      end

      def parse_expression_inner
        expr = parse_or
        # N-056: refuse an unparenthesised operand edge that groups differently
        # under Go precedence; nested ( ... ) groups were checked by their own
        # parse_expression call and are atoms here.
        atoms = @go_atoms
        work = [expr]
        until work.empty?
          e = work.pop
          next if !e.is_a?(BinaryExpr) || atoms.key?(e)

          edges = []
          edges << [e.left, e.left.op, e.op] if e.left.is_a?(BinaryExpr) && !atoms.key?(e.left)
          edges << [e.right, e.op, e.right.op] if e.right.is_a?(BinaryExpr) && !atoms.key?(e.right)
          edges.each do |child, first, second|
            if Frontend.go_ambiguous_precedence?(first, second)
              add_error(Frontend.go_ambiguous_precedence_message(first, second))
              return expr
            end
            work << child
          end
        end
        expr
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
          return UnaryExpr.new(op: "!", operand: nested { parse_unary })
        end
        if match_tok(TOK_MINUS)
          return UnaryExpr.new(op: "-", operand: nested { parse_unary })
        end
        if match_tok(TOK_TILDE)
          return UnaryExpr.new(op: "~", operand: nested { parse_unary })
        end
        # Go uses ^ as bitwise NOT (complement) when used as unary prefix
        if match_tok(TOK_CARET)
          return UnaryExpr.new(op: "~", operand: nested { parse_unary })
        end

        expr = parse_postfix_chain(parse_primary)
        @go_atoms[expr] = true # N-056: an operand is an atom
        expr
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

      # Nested composite literal body: `{elem, elem, ...}` or `{ {..}, {..} }`.
      def parse_go_brace_literal
        expect(TOK_LBRACE)
        elements = []
        while !check(TOK_RBRACE) && !check(TOK_EOF)
          elements << if check(TOK_LBRACE)
            nested { parse_go_brace_literal }
          else
            parse_expression
          end
          match_tok(TOK_COMMA)
        end
        expect(TOK_RBRACE)
        ArrayLiteralExpr.new(elements: elements)
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

        # Go composite literal for arrays: [N]Type{elements} or
        # [N][M]Type{{...},{...}}. Also accept the plain bracket-list form
        # `[a, b, c]` for compatibility. Both lower to an ArrayLiteralExpr so
        # downstream passes (typecheck, ANF-lowering for +checkMultiSig+) see
        # the same array_literal node shape used by every other format parser.
        if tok.kind == TOK_LBRACKET
          saved = @pos
          advance # skip '['
          # Look ahead to decide between Go composite literal (`[N]...{...}`)
          # and the legacy bracket-list form (`[a, b, c]`).
          if check(TOK_NUMBER) && peek_next.kind == TOK_RBRACKET
            advance # number
            advance # ']'
            # Consume any additional leading `[M]` dimensions.
            while check(TOK_LBRACKET) && peek_next.kind == TOK_NUMBER &&
                  @pos + 2 < @tokens.length && @tokens[@pos + 2].kind == TOK_RBRACKET
              advance # '['
              advance # number
              advance # ']'
            end
            # Consume the element type: `runar.Sig`, `bool`, etc.
            if check_ident("runar") && peek_next.kind == TOK_DOT
              advance # runar
              advance # .
              advance if check(TOK_IDENT) # type name
            elsif check(TOK_IDENT)
              advance # type name
            end
            # Now expect `{` -- composite literal body.
            if check(TOK_LBRACE)
              return parse_go_brace_literal
            end
            # Not a composite literal after all -- roll back.
            @pos = saved
            advance # re-skip '['
          end
          elements = []
          while !check(TOK_RBRACKET) && !check(TOK_EOF)
            elements << parse_expression
            match_tok(TOK_COMMA)
          end
          expect(TOK_RBRACKET)
          return ArrayLiteralExpr.new(elements: elements)
        end

        # Nested composite literal body: `{elem, elem, ...}`.
        if tok.kind == TOK_LBRACE
          return parse_go_brace_literal
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

            # BigintBig operator helper: runar.BigintBigEqual(a, b) is `a === b`.
            big_op = GO_BIGINTBIG_OPS[member_name]
            if big_op && check(TOK_LPAREN)
              advance # '('
              left = parse_expression
              expect(TOK_COMMA)
              right = parse_expression
              expect(TOK_RPAREN)
              return BinaryExpr.new(op: big_op, left: left, right: right)
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
      # F-011: run the parser below and keep its tokenizer's diagnostics.
      # DoS-bound size guard, enforced at every exported parser entry, not
      # just _parse_source. N-136.
      RunarCompiler::Frontend::InputLimits.assert_source_bytes_under_limit(source)
      lex = []
      Frontend.with_lex_errors(
        InputLimits.with_nesting_limit(file_name) { _parse_go_tokens(source, file_name, lex) }, lex
      )
    end

    def self._parse_go_tokens(source, file_name, lex)
      p = GoParser.new(file_name)
      directives = []
      p.tokens = tokenize_go(source, lex, file_name, directives)
      p.directives = directives
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

      p.errors.concat(IdentifierCollision.diagnostics(p.declared || []))
      if p.errors.any?
        return ParseResult.new(contract: contract, errors: p.errors)
      end

      ParseResult.new(contract: contract)
    end
  end
end
