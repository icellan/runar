package runar.compiler.frontend;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.BoolLiteral;
import runar.compiler.ir.ast.ByteStringLiteral;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.CustomType;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.FixedArrayType;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.DecrementExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParamNode;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.SourceLocation;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;
import runar.compiler.passes.SighashDirective;

/**
 * Parses {@code .runar.rb} (Ruby) source into a Rúnar {@link ContractNode}.
 *
 * <p>Ported from {@code compilers/python/runar_compiler/frontend/parser_ruby.py}.
 * Hand-rolled tokenizer + recursive-descent parser. Produces the same AST
 * shape as the TypeScript / Python / Go / Rust / Zig / Ruby Ruby parsers.
 *
 * <p>Ruby surface accepted by Rúnar:
 * <ul>
 *   <li>{@code require 'runar'}</li>
 *   <li>{@code class Foo < Runar::SmartContract} /
 *       {@code class Foo < Runar::StatefulSmartContract} (also
 *       {@code class Foo < SmartContract})</li>
 *   <li>{@code prop :name, Type [, readonly: true|false] [, default: value]}</li>
 *   <li>{@code runar_public [name: Type, ...]} marker for public methods</li>
 *   <li>{@code params name: Type, ...} optional separate parameter type DSL</li>
 *   <li>{@code def initialize(...)} → constructor; {@code def foo(...)} → method</li>
 *   <li>{@code @ivar} → property access; snake_case → camelCase on idents</li>
 *   <li>{@code assert expr} as a statement keyword (no parentheses)</li>
 *   <li>{@code if/elsif/else/end}, {@code unless}, {@code for x in 0...n do/end}</li>
 *   <li>{@code and}/{@code or}/{@code not} alongside {@code &&}/{@code ||}/{@code !}</li>
 * </ul>
 */
public final class RbParser {

    private RbParser() {}

    // ---------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------

    /** Parse Ruby source into a Rúnar contract AST. */
    public static ContractNode parse(String source, String filename) throws ParseException {
        // DoS-bound size guard, enforced at every exported parser entry, not
        // just ParserDispatch.parse. N-136.
        try {
            InputLimits.assertSourceBytesUnderLimit(source);
        } catch (ParserDispatch.ParseException e) {
            throw new ParseException(e.getMessage());
        }
        List<String> lex = new ArrayList<>();
        List<Token> tokens = tokenize(source, filename, lex);
        // F-011: refuse an unterminated literal before parsing what follows it.
        if (!lex.isEmpty()) throw new ParseException(String.join("; ", lex));
        Parser parser = new Parser(tokens, filename);
        // F-213: measures (A) and (B). parseClass's recursive bare-call
        // rewrite runs inside this guard, so the StackOverflowError backstop
        // covers it on a loop-built tree too deep for it.
        ContractNode contract = SourceNesting.guard(parser::parseTop, ParseException::new);
        String collision = parser.idents.message();
        if (contract != null && collision != null) parser.errors.add(collision);
        if (!parser.errors.isEmpty()) {
            throw new ParseException(String.join("\n", parser.errors));
        }
        return contract;
    }

    /** Checked exception for parse-time problems. */
    public static class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
    }

    // ---------------------------------------------------------------
    // Token kinds
    // ---------------------------------------------------------------

    private enum TK {
        EOF,
        IDENT,
        NUMBER,
        HEXSTRING,    // single-quoted string → hex ByteString
        STRING,       // double-quoted string
        SYMBOL,       // :name
        IVAR,         // @name
        LPAREN, RPAREN,
        LBRACKET, RBRACKET,
        COMMA, DOT, COLON, COLONCOLON,
        ASSIGN, EQEQ, NOTEQ,
        LT, LTEQ, GT, GTEQ,
        PLUS, MINUS, STAR, SLASH, PERCENT, STARSTAR,
        BANG, TILDE, AMP, PIPE, CARET,
        AMPAMP, PIPEPIPE,
        LSHIFT, RSHIFT,
        PLUSEQ, MINUSEQ, STAREQ, SLASHEQ, PERCENTEQ,
        DOTDOT, DOTDOTDOT,
        QUESTION,
        NEWLINE,
        // keywords
        CLASS, DEF, IF, ELSIF, ELSE, UNLESS, FOR, IN, END, RETURN,
        TRUE, FALSE, NIL, AND, OR, NOT, SUPER, REQUIRE, ASSERT, DO,
    }

    private static final Map<String, TK> KEYWORDS = Map.ofEntries(
        Map.entry("class", TK.CLASS),
        Map.entry("def", TK.DEF),
        Map.entry("if", TK.IF),
        Map.entry("elsif", TK.ELSIF),
        Map.entry("else", TK.ELSE),
        Map.entry("unless", TK.UNLESS),
        Map.entry("for", TK.FOR),
        Map.entry("in", TK.IN),
        Map.entry("end", TK.END),
        Map.entry("return", TK.RETURN),
        Map.entry("true", TK.TRUE),
        Map.entry("false", TK.FALSE),
        Map.entry("nil", TK.NIL),
        Map.entry("and", TK.AND),
        Map.entry("or", TK.OR),
        Map.entry("not", TK.NOT),
        Map.entry("super", TK.SUPER),
        Map.entry("require", TK.REQUIRE),
        Map.entry("assert", TK.ASSERT),
        Map.entry("do", TK.DO)
    );

    private static final class Token {
        final TK kind;
        final String value;
        final int line;
        final int col;

        Token(TK kind, String value, int line, int col) {
            this.kind = kind;
            this.value = value;
            this.line = line;
            this.col = col;
        }
    }

    // ---------------------------------------------------------------
    // Snake-case → camelCase + builtin name mapping
    // ---------------------------------------------------------------

    private static final Map<String, String> SPECIAL_NAMES;
    static {
        Map<String, String> m = new HashMap<>();
        m.put("initialize", "constructor");
        m.put("check_sig", "checkSig");
        m.put("check_multi_sig", "checkMultiSig");
        m.put("check_preimage", "checkPreimage");
        m.put("verify_wots", "verifyWOTS");
        m.put("verify_slh_dsa_sha2_128s", "verifySLHDSA_SHA2_128s");
        m.put("verify_slh_dsa_sha2_128f", "verifySLHDSA_SHA2_128f");
        m.put("verify_slh_dsa_sha2_192s", "verifySLHDSA_SHA2_192s");
        m.put("verify_slh_dsa_sha2_192f", "verifySLHDSA_SHA2_192f");
        m.put("verify_slh_dsa_sha2_256s", "verifySLHDSA_SHA2_256s");
        m.put("verify_slh_dsa_sha2_256f", "verifySLHDSA_SHA2_256f");
        m.put("verify_rabin_sig", "verifyRabinSig");
        m.put("ec_add", "ecAdd");
        m.put("ec_mul", "ecMul");
        m.put("ec_mul_gen", "ecMulGen");
        m.put("ec_negate", "ecNegate");
        m.put("ec_on_curve", "ecOnCurve");
        m.put("ec_mod_reduce", "ecModReduce");
        m.put("ec_encode_compressed", "ecEncodeCompressed");
        m.put("ec_make_point", "ecMakePoint");
        m.put("ec_point_x", "ecPointX");
        m.put("ec_point_y", "ecPointY");
        m.put("p256_add", "p256Add");
        m.put("p256_mul", "p256Mul");
        m.put("p256_mul_gen", "p256MulGen");
        m.put("p256_negate", "p256Negate");
        m.put("p256_on_curve", "p256OnCurve");
        m.put("p256_encode_compressed", "p256EncodeCompressed");
        m.put("verify_ecdsa_p256", "verifyECDSA_P256");
        m.put("p384_add", "p384Add");
        m.put("p384_mul", "p384Mul");
        m.put("p384_mul_gen", "p384MulGen");
        m.put("p384_negate", "p384Negate");
        m.put("p384_on_curve", "p384OnCurve");
        m.put("p384_encode_compressed", "p384EncodeCompressed");
        m.put("verify_ecdsa_p384", "verifyECDSA_P384");
        m.put("add_output", "addOutput");
        m.put("add_raw_output", "addRawOutput");
        m.put("add_data_output", "addDataOutput");
        m.put("get_state_script", "getStateScript");
        m.put("extract_locktime", "extractLocktime");
        m.put("extract_output_hash", "extractOutputHash");
        m.put("extract_amount", "extractAmount");
        m.put("extract_version", "extractVersion");
        m.put("extract_sequence", "extractSequence");
        m.put("extract_nsequence", "extractNSequence");
        m.put("extract_hash_prevouts", "extractHashPrevouts");
        m.put("extract_hash_sequence", "extractHashSequence");
        m.put("extract_outpoint", "extractOutpoint");
        m.put("extract_script_code", "extractScriptCode");
        m.put("extract_input_index", "extractInputIndex");
        m.put("extract_sig_hash_type", "extractSigHashType");
        m.put("extract_outputs", "extractOutputs");
        m.put("mul_div", "mulDiv");
        m.put("percent_of", "percentOf");
        m.put("reverse_bytes", "reverseBytes");
        m.put("safe_div", "safediv");
        m.put("safe_mod", "safemod");
        m.put("div_mod", "divmod");
        m.put("sha256_compress", "sha256Compress");
        m.put("sha256_finalize", "sha256Finalize");
        m.put("sha256", "sha256");
        m.put("ripemd160", "ripemd160");
        m.put("hash160", "hash160");
        m.put("hash256", "hash256");
        m.put("num2bin", "num2bin");
        m.put("bin2num", "bin2num");
        m.put("log2", "log2");
        m.put("EC_P", "EC_P");
        m.put("EC_N", "EC_N");
        m.put("EC_G", "EC_G");
        SPECIAL_NAMES = Collections.unmodifiableMap(m);
    }

    private static final Set<String> PASSTHROUGH_NAMES = Set.of(
        "bool", "abs", "min", "max", "len", "pow", "cat", "within",
        "safediv", "safemod", "clamp", "sign", "sqrt", "gcd", "divmod",
        "log2", "substr"
    );

    private static final Set<String> INTRINSIC_METHODS = Set.of(
        "addOutput", "addRawOutput", "addDataOutput", "getStateScript"
    );

    /**
     * Convert a snake_case identifier to camelCase: split on {@code _} and
     * capitalise the first character of every following part, skipping empty
     * parts. This is the shared R-113 rule — the same algorithm as
     * {@code snakeToCamelCore} (TS), {@code rbConvertName} (Go),
     * {@code snake_to_camel} (Rust) and {@code snakeToCamel} (Zig), and the
     * one {@link MoveParser} and {@link RustParser} already used here.
     *
     * <p>This method used to walk the characters and uppercase only a
     * lower-case letter or digit following the underscore, leaving {@code _}
     * before a CAPITAL in place — the {@code /_([a-z0-9])/} rule spelled out
     * by hand, which is why grepping for that pattern did not find it. A
     * property {@code total_A} reached the artifact as {@code total_A} here
     * and as {@code totalA} in ts/go/rust/zig. The script hex is identical
     * either way, so hex parity never saw it — but {@code serializeState}
     * looks state up by {@code field.name}, so the two spellings do not
     * interoperate.
     *
     * <p>Strips leading underscores so {@code _foo_bar} becomes
     * {@code fooBar}. An all-underscore name has nothing left to convert and
     * is returned unchanged, as in the Go tier.
     */
    static String snakeToCamel(String name) {
        int leading = 0;
        while (leading < name.length() && name.charAt(leading) == '_') {
            leading++;
        }
        String stripped = name.substring(leading);
        if (stripped.isEmpty()) return name;
        String[] parts = stripped.split("_", -1);
        if (parts.length <= 1) return stripped;
        StringBuilder sb = new StringBuilder(stripped.length());
        sb.append(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            if (part.isEmpty()) continue;
            sb.append(Character.toUpperCase(part.charAt(0))).append(part.substring(1));
        }
        return sb.toString();
    }

    private static String mapBuiltinName(String name) {
        String special = SPECIAL_NAMES.get(name);
        if (special != null) return special;
        if (PASSTHROUGH_NAMES.contains(name)) return name;
        return snakeToCamel(name);
    }

    private static final Map<String, String> TYPE_MAP;
    static {
        Map<String, String> m = new HashMap<>();
        m.put("Bigint", "bigint");
        m.put("Integer", "bigint");
        m.put("Int", "bigint");
        m.put("Boolean", "boolean");
        m.put("Bool", "boolean");
        m.put("ByteString", "ByteString");
        m.put("PubKey", "PubKey");
        m.put("Sig", "Sig");
        m.put("Addr", "Addr");
        m.put("Sha256", "Sha256");
        m.put("Sha256Digest", "Sha256");
        m.put("Ripemd160", "Ripemd160");
        m.put("SigHashPreimage", "SigHashPreimage");
        m.put("RabinSig", "RabinSig");
        m.put("RabinPubKey", "RabinPubKey");
        m.put("Point", "Point");
        m.put("P256Point", "P256Point");
        m.put("P384Point", "P384Point");
        TYPE_MAP = Collections.unmodifiableMap(m);
    }

    private static TypeNode mapRbType(String name) {
        String mapped = TYPE_MAP.getOrDefault(name, name);
        try {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(mapped));
        } catch (IllegalArgumentException unknown) {
            return new CustomType(mapped);
        }
    }

    // ---------------------------------------------------------------
    // Tokenizer
    // ---------------------------------------------------------------

    private static boolean isIdentStart(char c) {
        return Character.isLetter(c) || c == '_';
    }

    private static boolean isIdentPart(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }

    /**
     * Whether {@code line} starts at column 0 with {@code marker}
     * ({@code =begin} or {@code =end}) as a whole word: followed by ASCII
     * whitespace (Ruby's {@code \s}) or end of line.
     */
    private static boolean isEmbeddedDocMarker(String line, String marker) {
        if (!line.startsWith(marker)) return false;
        if (line.length() == marker.length()) return true;
        return " \t\n\u000b\f\r".indexOf(line.charAt(marker.length())) >= 0;
    }

    private static List<Token> tokenize(String source, String filename, List<String> lex) throws ParseException {
        List<Token> tokens = new ArrayList<>();
        String[] lines = source.split("\n", -1);
        int parenDepth = 0;
        // Line number of an open `=begin` embedded document, or 0.
        int blockCommentStart = 0;

        for (int lineIdx = 0; lineIdx < lines.length; lineIdx++) {
            int lineNum = lineIdx + 1;
            String raw = lines[lineIdx];
            // strip trailing carriage return
            if (raw.endsWith("\r")) {
                raw = raw.substring(0, raw.length() - 1);
            }
            String line = raw;

            // N-021: Ruby embedded documents, the Ruby tier's F-018 rule
            // (Ruby's own). `=begin` / `=end` open and close a block comment
            // only at column 0 and only as a whole word (followed by
            // whitespace or end of line). Every line from `=begin` through
            // `=end` is a comment. Before this, a method "commented out" this
            // way compiled as a live spend path and the `end` of `=end`
            // closed the class early.
            if (blockCommentStart != 0) {
                if (isEmbeddedDocMarker(line, "=end")) blockCommentStart = 0;
                continue;
            }
            if (isEmbeddedDocMarker(line, "=begin")) {
                blockCommentStart = lineNum;
                continue;
            }

            // Detect blank or comment-only lines
            int firstNonSpace = 0;
            while (firstNonSpace < line.length()
                && (line.charAt(firstNonSpace) == ' ' || line.charAt(firstNonSpace) == '\t')) {
                firstNonSpace++;
            }
            if (firstNonSpace == line.length() || line.charAt(firstNonSpace) == '#') {
                continue;
            }

            int pos = firstNonSpace;
            while (pos < line.length()) {
                char ch = line.charAt(pos);
                int col = pos;

                if (ch == ' ' || ch == '\t') {
                    pos++;
                    continue;
                }
                if (ch == '#') {
                    break;
                }

                // @name → IVAR
                if (ch == '@') {
                    pos++;
                    int nameStart = pos;
                    while (pos < line.length() && isIdentPart(line.charAt(pos))) {
                        pos++;
                    }
                    String name = line.substring(nameStart, pos);
                    if (!name.isEmpty()) {
                        tokens.add(new Token(TK.IVAR, name, lineNum, col));
                    } else {
                        // N-214: a bare `@` was dropped, so `a + @ b` compiled
                        // as `a + b`. The TS reference lexes it as its own token
                        // and refuses it in the expression; refuse it with TS's
                        // diagnostic.
                        lex.add(LexDiag.at(filename, lineNum, col, "Unexpected token in expression: '@'"));
                    }
                    continue;
                }

                // ... and ..
                if (ch == '.' && pos + 2 < line.length()
                    && line.charAt(pos + 1) == '.' && line.charAt(pos + 2) == '.') {
                    tokens.add(new Token(TK.DOTDOTDOT, "...", lineNum, col));
                    pos += 3;
                    continue;
                }
                if (ch == '.' && pos + 1 < line.length() && line.charAt(pos + 1) == '.') {
                    tokens.add(new Token(TK.DOTDOT, "..", lineNum, col));
                    pos += 2;
                    continue;
                }

                // Two-character operators
                if (pos + 1 < line.length()) {
                    String two = line.substring(pos, pos + 2);
                    TK twoTok = switch (two) {
                        case "**" -> TK.STARSTAR;
                        case "::" -> TK.COLONCOLON;
                        case "==" -> TK.EQEQ;
                        case "!=" -> TK.NOTEQ;
                        case "<=" -> TK.LTEQ;
                        case ">=" -> TK.GTEQ;
                        case "<<" -> TK.LSHIFT;
                        case ">>" -> TK.RSHIFT;
                        case "&&" -> TK.AMPAMP;
                        case "||" -> TK.PIPEPIPE;
                        case "+=" -> TK.PLUSEQ;
                        case "-=" -> TK.MINUSEQ;
                        case "*=" -> TK.STAREQ;
                        case "/=" -> TK.SLASHEQ;
                        case "%=" -> TK.PERCENTEQ;
                        default -> null;
                    };
                    if (twoTok != null) {
                        tokens.add(new Token(twoTok, two, lineNum, col));
                        pos += 2;
                        continue;
                    }
                }

                // Parens / brackets — track depth for newline suppression
                if (ch == '(') {
                    parenDepth++;
                    tokens.add(new Token(TK.LPAREN, "(", lineNum, col));
                    pos++;
                    continue;
                }
                if (ch == ')') {
                    parenDepth = Math.max(0, parenDepth - 1);
                    tokens.add(new Token(TK.RPAREN, ")", lineNum, col));
                    pos++;
                    continue;
                }
                if (ch == '[') {
                    parenDepth++;
                    tokens.add(new Token(TK.LBRACKET, "[", lineNum, col));
                    pos++;
                    continue;
                }
                if (ch == ']') {
                    parenDepth = Math.max(0, parenDepth - 1);
                    tokens.add(new Token(TK.RBRACKET, "]", lineNum, col));
                    pos++;
                    continue;
                }

                // Symbol :name (must follow an alpha or underscore)
                if (ch == ':' && pos + 1 < line.length() && isIdentStart(line.charAt(pos + 1))) {
                    pos++; // consume ':'
                    int nameStart = pos;
                    while (pos < line.length() && isIdentPart(line.charAt(pos))) {
                        pos++;
                    }
                    String sym = line.substring(nameStart, pos);
                    tokens.add(new Token(TK.SYMBOL, sym, lineNum, col));
                    continue;
                }

                // Single-character punctuation
                TK single = switch (ch) {
                    case ',' -> TK.COMMA;
                    case '.' -> TK.DOT;
                    case ':' -> TK.COLON;
                    case '+' -> TK.PLUS;
                    case '-' -> TK.MINUS;
                    case '*' -> TK.STAR;
                    case '/' -> TK.SLASH;
                    case '%' -> TK.PERCENT;
                    case '!' -> TK.BANG;
                    case '~' -> TK.TILDE;
                    case '&' -> TK.AMP;
                    case '|' -> TK.PIPE;
                    case '^' -> TK.CARET;
                    case '?' -> TK.QUESTION;
                    case '<' -> TK.LT;
                    case '>' -> TK.GT;
                    case '=' -> TK.ASSIGN;
                    default -> null;
                };
                if (single != null) {
                    tokens.add(new Token(single, String.valueOf(ch), lineNum, col));
                    pos++;
                    continue;
                }

                // Single-quoted string → hex ByteString literal
                if (ch == '\'') {
                    pos++;
                    StringBuilder val = new StringBuilder();
                    while (pos < line.length() && line.charAt(pos) != '\'') {
                        if (line.charAt(pos) == '\\' && pos + 1 < line.length()) {
                            pos++;
                            val.append(line.charAt(pos));
                            pos++;
                        } else {
                            val.append(line.charAt(pos));
                            pos++;
                        }
                    }
                    if (pos < line.length()) pos++; // closing quote
                    // F-011: line-based, so reaching the line break means the
                    // literal is unterminated; refuse it, never end it silently.
                    else lex.add(LexDiag.at(filename, lineNum, col, LexDiag.UNTERMINATED_STRING_LITERAL));
                    tokens.add(new Token(TK.HEXSTRING, val.toString(), lineNum, col));
                    continue;
                }

                // Double-quoted string
                if (ch == '"') {
                    pos++;
                    StringBuilder val = new StringBuilder();
                    while (pos < line.length() && line.charAt(pos) != '"') {
                        if (line.charAt(pos) == '\\' && pos + 1 < line.length()) {
                            pos++;
                            val.append(line.charAt(pos));
                            pos++;
                        } else {
                            val.append(line.charAt(pos));
                            pos++;
                        }
                    }
                    if (pos < line.length()) pos++;
                    else lex.add(LexDiag.at(filename, lineNum, col, LexDiag.UNTERMINATED_STRING_LITERAL));
                    tokens.add(new Token(TK.STRING, val.toString(), lineNum, col));
                    continue;
                }

                // Number (F-026): the whole glued [0-9A-Za-z_] run is one literal.
                if (ch >= '0' && ch <= '9') {
                    IntLiteral.Scan sc = IntLiteral.lex("rb", line, pos, lex, filename, lineNum, col);
                    pos = sc.end();
                    tokens.add(new Token(TK.NUMBER, sc.value(), lineNum, col));
                    continue;
                }

                // Identifier / keyword
                if (isIdentStart(ch)) {
                    int nameStart = pos;
                    while (pos < line.length() && isIdentPart(line.charAt(pos))) {
                        pos++;
                    }
                    // Trailing ? or ! makes it a Ruby method ident (e.g. empty?)
                    if (pos < line.length()
                        && (line.charAt(pos) == '?' || line.charAt(pos) == '!')) {
                        pos++;
                    }
                    String word = line.substring(nameStart, pos);
                    TK kw = KEYWORDS.get(word);
                    if (kw != null) {
                        tokens.add(new Token(kw, word, lineNum, col));
                    } else {
                        tokens.add(new Token(TK.IDENT, word, lineNum, col));
                    }
                    continue;
                }

                // N-214: an unrecognised character is refused, as the TS reference
                // does, rather than skipped: skipping compiled `a + § b` as `a + b`.
                lex.add(LexDiag.at(filename, lineNum, col, "Unexpected character '" + ch + "'"));
                pos++;
            }

            if (parenDepth == 0) {
                tokens.add(new Token(TK.NEWLINE, "", lineNum, line.length()));
            }
        }

        if (blockCommentStart != 0) {
            // `file:N:` with no column is how the Go tier prints this
            // diagnostic's column-0 location.
            lex.add(filename + ":" + blockCommentStart + ": unterminated '=begin' block comment starting at line "
                + blockCommentStart + ": missing '=end'");
        }
        tokens.add(new Token(TK.EOF, "", lines.length + 1, 0));
        return tokens;
    }

    // ---------------------------------------------------------------
    // Compound-assignment table
    // ---------------------------------------------------------------

    private static final Map<TK, Expression.BinaryOp> COMPOUND_OPS = Map.of(
        TK.PLUSEQ, Expression.BinaryOp.ADD,
        TK.MINUSEQ, Expression.BinaryOp.SUB,
        TK.STAREQ, Expression.BinaryOp.MUL,
        TK.SLASHEQ, Expression.BinaryOp.DIV,
        TK.PERCENTEQ, Expression.BinaryOp.MOD
    );

    // ---------------------------------------------------------------
    // Recursive-descent parser
    // ---------------------------------------------------------------

    private static final class Parser {
        final List<Token> tokens;
        final String file;
        int pos;
        final List<String> errors = new ArrayList<>();
        /** F-213 measure (A): parse nesting. */
        final SourceNesting.Counter nest = new SourceNesting.Counter();
        Set<String> declaredLocals = new HashSet<>();
        /** F-017: declared (spelling, Rúnar name) pairs. */
        final IdentifierCollision.Declared idents = new IdentifierCollision.Declared();

        Parser(List<Token> tokens, String file) {
            this.tokens = tokens;
            this.file = file;
            this.pos = 0;
        }

        Token peek() {
            return pos < tokens.size() ? tokens.get(pos) : tokens.get(tokens.size() - 1);
        }

        Token peekAhead(int offset) {
            int idx = pos + offset;
            if (idx < tokens.size()) return tokens.get(idx);
            return tokens.get(tokens.size() - 1);
        }

        Token advance() {
            Token t = peek();
            if (pos < tokens.size() - 1) pos++;
            return t;
        }

        boolean match(TK kind) {
            if (peek().kind == kind) {
                advance();
                return true;
            }
            return false;
        }

        Token expect(TK kind, String label) {
            Token t = peek();
            if (t.kind != kind) {
                errors.add(file + ":" + t.line + ":" + t.col + ": expected '"
                    + label + "', got '" + (t.value.isEmpty() ? t.kind.name() : t.value) + "'");
            }
            return advance();
        }

        boolean checkIdent(String name) {
            Token t = peek();
            return t.kind == TK.IDENT && t.value.equals(name);
        }

        SourceLocation loc() {
            Token t = peek();
            return new SourceLocation(file, t.line, t.col);
        }

        void skipNewlines() {
            while (peek().kind == TK.NEWLINE) advance();
        }

        // ----------------------------------------------------------
        // Top-level
        // ----------------------------------------------------------

        ContractNode parseTop() {
            skipNewlines();
            while (peek().kind == TK.REQUIRE) {
                parseRequireLine();
                skipNewlines();
            }
            ContractNode contract = parseClass();
            if (contract != null) {
                // N-004: nothing may follow the class's `end`.
                skipNewlines();
                Token trailing = peek();
                if (trailing.kind != TK.EOF) {
                    errors.add(file + ":" + trailing.line + ":" + trailing.col + ": "
                        + LexDiag.unexpectedTokenAfterClass(trailing.value));
                }
            }
            return contract;
        }

        void parseRequireLine() {
            advance(); // 'require'
            while (peek().kind != TK.NEWLINE && peek().kind != TK.EOF) advance();
            skipNewlines();
        }

        ContractNode parseClass() {
            skipNewlines();
            if (peek().kind != TK.CLASS) {
                errors.add(file + ":" + peek().line + ": expected class declaration");
                return null;
            }
            advance(); // 'class'

            Token nameTok = expect(TK.IDENT, "class name");
            String contractName = nameTok.value;

            expect(TK.LT, "<");

            // Could be `Runar::SmartContract`, `Runar::StatefulSmartContract`,
            // or just `SmartContract` / `StatefulSmartContract`.
            Token firstPart = advance();
            String parentClassName;
            if (peek().kind == TK.COLONCOLON) {
                advance(); // '::'
                Token classPart = advance();
                parentClassName = classPart.value;
            } else {
                parentClassName = firstPart.value;
            }

            skipNewlines();

            ParentClass parentClass;
            switch (parentClassName) {
                case "SmartContract" -> parentClass = ParentClass.SMART_CONTRACT;
                case "StatefulSmartContract" -> parentClass = ParentClass.STATEFUL_SMART_CONTRACT;
                case "UnsafeSmartContract" -> parentClass = ParentClass.UNSAFE_SMART_CONTRACT;
                default -> {
                    errors.add(file + ":" + firstPart.line + ": unknown parent class: '" + parentClassName
                        + "', expected SmartContract, StatefulSmartContract, or UnsafeSmartContract");
                    return null;
                }
            }

            List<PropertyNode> properties = new ArrayList<>();
            List<MethodNode> methods = new ArrayList<>();
            MethodNode constructor = null;

            String pendingVisibility = null;
            Map<String, TypeNode> pendingParamTypes = null;
            // N-093: pending `runar_sighash` specs (null = malformed) for the
            // next def, each with the location of its macro.
            List<String> pendingSighash = new ArrayList<>();
            List<SourceLocation> pendingSighashLocs = new ArrayList<>();

            while (peek().kind != TK.END && peek().kind != TK.EOF) {
                skipNewlines();
                if (peek().kind == TK.END || peek().kind == TK.EOF) break;

                if (checkIdent("prop")) {
                    PropertyNode p = parseProp(parentClass);
                    if (p != null) properties.add(p);
                    skipNewlines();
                    continue;
                }
                // N-093: `runar_sighash 'FLAGS'` is the native spelling of the
                // `@sighash` directive; it applies to the next `def`.
                if (checkIdent("runar_sighash")) {
                    pendingSighashLocs.add(loc());
                    advance(); // 'runar_sighash'
                    Token arg = peek();
                    int count = 0;
                    while (peek().kind != TK.NEWLINE && peek().kind != TK.EOF) {
                        advance();
                        count++;
                    }
                    boolean isStr = arg.kind == TK.STRING || arg.kind == TK.HEXSTRING;
                    pendingSighash.add(count == 1 && isStr ? arg.value : null);
                    skipNewlines();
                    continue;
                }
                if (checkIdent("runar_public")) {
                    advance();
                    pendingVisibility = "public";
                    pendingParamTypes = parseOptionalParamTypes();
                    skipNewlines();
                    continue;
                }
                if (checkIdent("params")) {
                    advance();
                    pendingParamTypes = parseOptionalParamTypes();
                    skipNewlines();
                    continue;
                }
                if (peek().kind == TK.DEF) {
                    MethodNode m = parseMethod(pendingVisibility, pendingParamTypes);
                    if ("constructor".equals(m.name())) {
                        // N-093: the constructor is not a spending entry point.
                        for (SourceLocation sl : pendingSighashLocs) {
                            errors.add(file + ":" + sl.line() + ":" + sl.column() + ": "
                                + SighashDirective.lostDirectiveMessage("@sighash"));
                        }
                        constructor = m;
                    } else {
                        SighashDirective.Result sighash = SighashDirective.resolveNativeSighash(
                            m.name(), m.visibility() == Visibility.PUBLIC, pendingSighash);
                        if (sighash != null && sighash.isError()) {
                            SourceLocation ml = m.sourceLocation();
                            errors.add(file + ":" + ml.line() + ":" + ml.column() + ": " + sighash.error());
                        } else if (sighash != null) {
                            m = new MethodNode(m.name(), m.params(), m.body(), m.visibility(),
                                m.sourceLocation(), sighash.value());
                        }
                        methods.add(m);
                    }
                    pendingVisibility = null;
                    pendingParamTypes = null;
                    pendingSighash = new ArrayList<>();
                    pendingSighashLocs = new ArrayList<>();
                    skipNewlines();
                    continue;
                }
                // Ruby's bare visibility markers are no-ops here (visibility
                // comes from `runar_public`); examples/ruby uses them.
                if (checkIdent("private") || checkIdent("public")) {
                    advance();
                    continue;
                }
                // N-004: refuse anything else (an indented `=begin` lexes as `=`).
                Token stray = advance();
                errors.add(file + ":" + stray.line + ":" + stray.col + ": "
                    + LexDiag.unexpectedClassBodyToken(stray.value));
            }
            // N-093: a `runar_sighash` with no `def` after it annotates nothing.
            for (SourceLocation sl : pendingSighashLocs) {
                errors.add(file + ":" + sl.line() + ":" + sl.column() + ": "
                    + SighashDirective.lostDirectiveMessage("@sighash"));
            }
            // N-319: the class `end` is required; EOF here means it is missing.
            if (!match(TK.END)) {
                Token eofTok = peek();
                errors.add(file + ":" + eofTok.line + ":" + eofTok.col
                    + ": unterminated class: missing closing 'end'");
            }

            if (constructor == null) {
                constructor = autoGenerateConstructor(properties);
            }

            // Back-fill constructor param types from prop declarations.
            Map<String, TypeNode> propTypes = new HashMap<>();
            for (PropertyNode p : properties) propTypes.put(p.name(), p.type());
            List<ParamNode> ctorParams = new ArrayList<>(constructor.params().size());
            boolean rebuildCtor = false;
            for (ParamNode pn : constructor.params()) {
                TypeNode t = pn.type();
                if (t instanceof CustomType ct && "unknown".equals(ct.name())) {
                    TypeNode propType = propTypes.get(pn.name());
                    if (propType != null) {
                        ctorParams.add(new ParamNode(pn.name(), propType));
                        rebuildCtor = true;
                        continue;
                    }
                }
                ctorParams.add(pn);
            }
            if (rebuildCtor) {
                constructor = new MethodNode(
                    constructor.name(),
                    ctorParams,
                    constructor.body(),
                    constructor.visibility(),
                    constructor.sourceLocation()
                );
            }

            // Rewrite bare calls to declared methods/intrinsics as this.method(...)
            Set<String> methodNames = new HashSet<>();
            for (MethodNode m : methods) methodNames.add(m.name());
            methodNames.addAll(INTRINSIC_METHODS);
            List<MethodNode> rewritten = new ArrayList<>(methods.size());
            for (MethodNode m : methods) {
                List<Statement> body = rewriteBareCalls(m.body(), methodNames);
                // Implicit return for private methods: promote the trailing
                // ExpressionStatement to a ReturnStatement so callers receive
                // a value.
                if (m.visibility() == Visibility.PRIVATE && !body.isEmpty()) {
                    int last = body.size() - 1;
                    Statement lastStmt = body.get(last);
                    if (lastStmt instanceof ExpressionStatement es) {
                        body = new ArrayList<>(body);
                        body.set(last, new ReturnStatement(es.expression(), es.sourceLocation()));
                    }
                }
                rewritten.add(new MethodNode(
                    m.name(), m.params(), body, m.visibility(), m.sourceLocation(), m.sighashType()
                ));
            }

            return new ContractNode(
                contractName,
                parentClass,
                properties,
                constructor,
                rewritten,
                file
            );
        }

        Map<String, TypeNode> parseOptionalParamTypes() {
            if (peek().kind == TK.NEWLINE || peek().kind == TK.EOF || peek().kind == TK.DEF) {
                return null;
            }
            // Use LinkedHashMap so insertion order is preserved.
            Map<String, TypeNode> paramTypes = new LinkedHashMap<>();
            while (peek().kind != TK.NEWLINE && peek().kind != TK.EOF) {
                Token nameTok = advance();
                String rawName = nameTok.value;
                expect(TK.COLON, ":");
                TypeNode t = parseType();
                paramTypes.put(rawName, t);
                if (!match(TK.COMMA)) break;
            }
            return paramTypes.isEmpty() ? null : paramTypes;
        }

        PropertyNode parseProp(ParentClass parentClass) {
            SourceLocation propLoc = loc();
            advance(); // 'prop'

            if (peek().kind != TK.SYMBOL) {
                errors.add(file + ":" + peek().line
                    + ": expected symbol after 'prop', got '" + peek().value + "'");
                while (peek().kind != TK.NEWLINE && peek().kind != TK.EOF) advance();
                return null;
            }

            String rawName = advance().value;
            expect(TK.COMMA, ",");
            TypeNode typeNode = parseType();

            boolean isReadonly = false;
            boolean embedAlways = false;
            Expression initializer = null;
            boolean optionError = false;

            while (peek().kind == TK.COMMA) {
                advance();
                if (checkIdent("embed_always")) {
                    // N-093: the native spelling of the `@embedAlways` directive.
                    advance();
                    expect(TK.COLON, ":");
                    if (peek().kind == TK.TRUE) {
                        advance();
                        embedAlways = true;
                    } else if (peek().kind == TK.FALSE) {
                        advance();
                        embedAlways = false;
                    } else {
                        badBooleanPropOption("embed_always");
                        optionError = true;
                        break;
                    }
                } else if (checkIdent("readonly")) {
                    advance();
                    expect(TK.COLON, ":");
                    if (peek().kind == TK.TRUE) {
                        advance();
                        isReadonly = true;
                    } else if (peek().kind == TK.FALSE) {
                        advance();
                        isReadonly = false;
                    } else {
                        badBooleanPropOption("readonly");
                        optionError = true;
                        break;
                    }
                } else if (checkIdent("default")) {
                    advance();
                    expect(TK.COLON, ":");
                    if (peek().kind == TK.NIL) {
                        // N-414: `nil` is not a Rúnar literal; refused, never read as 0.
                        errors.add(file + ":" + peek().line + ":" + peek().col
                            + ": prop default 'nil' is not a literal (expected a number, true, false or a hex string)");
                        advance(); // 'nil'
                    } else {
                        initializer = parseUnary();
                    }
                } else {
                    // N-301: an unknown option (e.g. a typo of `embed_always`) is
                    // refused, never silently dropped. Same text in all seven tiers.
                    errors.add(file + ":" + peek().line + ":" + peek().col
                        + ": unknown prop option '" + peek().value
                        + "' (expected readonly, embed_always or default)");
                    optionError = true;
                    break;
                }
            }

            // N-413: nothing may follow the type or an option value except `,`
            // (the next option) or end of line, so `default: 1 + 2` is refused
            // rather than silently truncated to its first operand. Same text in
            // all seven tiers.
            if (!optionError && peek().kind != TK.NEWLINE && peek().kind != TK.EOF) {
                errors.add(file + ":" + peek().line + ":" + peek().col
                    + ": unexpected '" + peek().value
                    + "' in prop declaration (expected ',' or end of line)");
            }

            // Stateless contracts (SmartContract and UnsafeSmartContract):
            // all properties readonly.
            if (parentClass == ParentClass.SMART_CONTRACT
                || parentClass == ParentClass.UNSAFE_SMART_CONTRACT) {
                isReadonly = true;
            }

            // Skip rest of the line.
            while (peek().kind != TK.NEWLINE && peek().kind != TK.EOF) advance();

            return new PropertyNode(
                idents.declare(rawName, snakeToCamel(rawName)),
                typeNode,
                isReadonly,
                initializer,
                propLoc,
                null,
                embedAlways
            );
        }

        /** N-313: {@code readonly:} / {@code embed_always:} take a literal true or
         *  false. Any other value is refused, never silently dropped. Same text
         *  in all seven tiers. */
        private void badBooleanPropOption(String option) {
            Token t = peek();
            String got = (t.kind == TK.NEWLINE || t.kind == TK.EOF) ? "<end of line>" : t.value;
            errors.add(file + ":" + t.line + ":" + t.col
                + ": invalid value '" + got + "' for prop option '" + option
                + "' (expected true or false)");
        }

        TypeNode parseType() {
            Token t = advance();
            String rawName = t.value;
            if ("FixedArray".equals(rawName) && peek().kind == TK.LBRACKET) {
                advance(); // '['
                TypeNode elem = nest.nested(this::parseType);
                expect(TK.COMMA, ",");
                Token sizeTok = expect(TK.NUMBER, "number");
                int size;
                try {
                    size = parseIntLiteral(sizeTok.value);
                } catch (NumberFormatException ex) {
                    // expect() already logged the token-mismatch diagnostic
                    // above; fall back to 0 instead of letting the raw
                    // exception escape the parser.
                    size = 0;
                }
                expect(TK.RBRACKET, "]");
                return new FixedArrayType(elem, size);
            }
            return mapRbType(rawName);
        }

        MethodNode parseMethod(String pendingVisibility, Map<String, TypeNode> pendingParamTypes) {
            SourceLocation methodLoc = loc();
            expect(TK.DEF, "def");

            Token nameTok = advance();
            // N-050: `def self.m` / `def Vault.m` declares a singleton
            // (class-level) method, not a contract method.
            if (peek().kind == TK.DOT) {
                advance(); // '.'
                nameTok = advance();
                errors.add(file + ":" + nameTok.line + ":" + nameTok.col + ": " + LexDiag.staticMethod(nameTok.value));
            }
            String rawName = nameTok.value;
            declaredLocals = new HashSet<>();

            List<ParamNode> params;
            if (peek().kind == TK.LPAREN) {
                expect(TK.LPAREN, "(");
                params = parseParams(pendingParamTypes);
                expect(TK.RPAREN, ")");
            } else {
                params = new ArrayList<>();
            }
            skipNewlines();

            List<Statement> body = parseStatements();
            expect(TK.END, "end");

            if ("initialize".equals(rawName)) {
                return new MethodNode("constructor", params, body, Visibility.PUBLIC, methodLoc);
            }
            boolean isPublic = "public".equals(pendingVisibility);
            return new MethodNode(
                idents.declare(rawName, snakeToCamel(rawName)),
                params,
                body,
                isPublic ? Visibility.PUBLIC : Visibility.PRIVATE,
                methodLoc
            );
        }

        List<ParamNode> parseParams(Map<String, TypeNode> paramTypes) {
            List<ParamNode> out = new ArrayList<>();
            while (peek().kind != TK.RPAREN && peek().kind != TK.EOF) {
                Token nameTok = advance();
                String rawName = nameTok.value;
                String camelName = idents.declare(rawName, snakeToCamel(rawName));
                TypeNode t = paramTypes != null ? paramTypes.get(rawName) : null;
                out.add(new ParamNode(camelName, t != null ? t : new CustomType("unknown")));
                if (!match(TK.COMMA)) break;
            }
            return out;
        }

        MethodNode autoGenerateConstructor(List<PropertyNode> properties) {
            List<PropertyNode> required = new ArrayList<>();
            for (PropertyNode p : properties) {
                if (p.initializer() == null) required.add(p);
            }

            List<ParamNode> params = new ArrayList<>(required.size());
            List<Expression> superArgs = new ArrayList<>(required.size());
            for (PropertyNode p : required) {
                params.add(new ParamNode(p.name(), p.type()));
                superArgs.add(new Identifier(p.name()));
            }
            SourceLocation l = new SourceLocation(file, 1, 0);

            List<Statement> body = new ArrayList<>();
            body.add(new ExpressionStatement(
                new CallExpr(new Identifier("super"), superArgs),
                l
            ));
            for (PropertyNode p : required) {
                body.add(new AssignmentStatement(
                    new PropertyAccessExpr(p.name()),
                    new Identifier(p.name()),
                    l
                ));
            }

            return new MethodNode("constructor", params, body, Visibility.PUBLIC, l);
        }

        // ----------------------------------------------------------
        // Statements
        // ----------------------------------------------------------

        List<Statement> parseStatements() {
            List<Statement> stmts = new ArrayList<>();
            while (peek().kind != TK.END && peek().kind != TK.ELSIF
                && peek().kind != TK.ELSE && peek().kind != TK.EOF) {
                skipNewlines();
                if (peek().kind == TK.END || peek().kind == TK.ELSIF
                    || peek().kind == TK.ELSE || peek().kind == TK.EOF) break;

                Statement s = parseStatement();
                if (s != null) stmts.add(s);
                skipNewlines();
            }
            return stmts;
        }

        Statement parseStatement() {
            return nest.nested(this::parseStatementInner);
        }

        Statement parseStatementInner() {
            SourceLocation l = loc();
            TK k = peek().kind;
            return switch (k) {
                case ASSERT -> parseAssertStatement(l);
                case IF -> parseIfStatement(l);
                case UNLESS -> parseUnlessStatement(l);
                case FOR -> parseForStatement(l);
                case RETURN -> parseReturnStatement(l);
                case SUPER -> parseSuperCall(l);
                case IVAR -> parseIvarStatement(l);
                case IDENT -> parseIdentStatement(l);
                // N-053: a token that can begin an expression begins an
                // expression statement (a private helper's last one is its
                // implicit return value). Skipping it dropped `!` / `(` /
                // literals.
                case NUMBER, STRING, HEXSTRING, TRUE, FALSE, NIL,
                     LPAREN, LBRACKET, MINUS, TILDE, BANG, NOT ->
                    new ExpressionStatement(parseExpression(), l);
                // N-053: any other token is refused.
                default -> {
                    Token t = advance();
                    errors.add(file + ":" + t.line + ":" + t.col + ": " + LexDiag.unsupportedStatement(t.value));
                    yield null;
                }
            };
        }

        Statement parseAssertStatement(SourceLocation l) {
            advance(); // 'assert'
            Expression e = parseExpression();
            return new ExpressionStatement(
                new CallExpr(new Identifier("assert"), List.of(e)),
                l
            );
        }

        Statement parseIfStatement(SourceLocation l) {
            advance(); // 'if'
            Expression cond = parseExpression();
            skipNewlines();
            // Variables declared inside an if/elsif/else branch are scoped
            // to that branch. Snapshot+restore declaredLocals so a sibling
            // branch (or sibling top-level if-without-else block) can
            // re-declare the same local without it being treated as an
            // assignment to an out-of-scope variable. Mirrors the
            // canonical TS / Python lexical-scope semantics.
            Set<String> localsBeforeThen = new HashSet<>(declaredLocals);
            List<Statement> thenStmts = parseStatements();
            declaredLocals = new HashSet<>(localsBeforeThen);
            List<Statement> elseStmts = null;
            if (peek().kind == TK.ELSIF) {
                SourceLocation elifLoc = loc();
                elseStmts = new ArrayList<>();
                // F-213 A1: an elsif is a statement of the else branch.
                elseStmts.add(nest.nested(() -> parseElsifStatement(elifLoc)));
                declaredLocals = new HashSet<>(localsBeforeThen);
            } else if (peek().kind == TK.ELSE) {
                advance();
                skipNewlines();
                elseStmts = parseStatements();
                declaredLocals = new HashSet<>(localsBeforeThen);
            }
            expect(TK.END, "end");
            return new IfStatement(cond, thenStmts, elseStmts != null ? elseStmts : new ArrayList<>(), l);
        }

        Statement parseElsifStatement(SourceLocation l) {
            advance(); // 'elsif'
            Expression cond = parseExpression();
            skipNewlines();
            // Same scope discipline as parseIfStatement.
            Set<String> localsBeforeThen = new HashSet<>(declaredLocals);
            List<Statement> thenStmts = parseStatements();
            declaredLocals = new HashSet<>(localsBeforeThen);
            List<Statement> elseStmts = null;
            if (peek().kind == TK.ELSIF) {
                SourceLocation elifLoc = loc();
                elseStmts = new ArrayList<>();
                // F-213 A1: an elsif is a statement of the else branch.
                elseStmts.add(nest.nested(() -> parseElsifStatement(elifLoc)));
                declaredLocals = new HashSet<>(localsBeforeThen);
            } else if (peek().kind == TK.ELSE) {
                advance();
                skipNewlines();
                elseStmts = parseStatements();
                declaredLocals = new HashSet<>(localsBeforeThen);
            }
            // outer 'end' is consumed by the parent if-statement
            return new IfStatement(cond, thenStmts, elseStmts != null ? elseStmts : new ArrayList<>(), l);
        }

        Statement parseUnlessStatement(SourceLocation l) {
            advance(); // 'unless'
            Expression rawCond = parseExpression();
            skipNewlines();
            List<Statement> body = parseStatements();
            expect(TK.END, "end");
            Expression cond = new UnaryExpr(Expression.UnaryOp.NOT, rawCond);
            return new IfStatement(cond, body, new ArrayList<>(), l);
        }

        /**
         * Destructure {@code <receiver>.downto(<bound>)} — the Ruby countdown
         * header — into {@code {receiver, bound}}.
         *
         * <p>Returns {@code null} for every other expression, including
         * {@code downto} with the wrong arity, so a malformed header falls
         * through to the range-operator branch and gets that branch's
         * diagnostic rather than silently becoming a loop.
         */
        private static Expression[] matchDowntoCall(Expression expr) {
            if (!(expr instanceof CallExpr call)) return null;
            if (call.args().size() != 1) return null;
            if (!(call.callee() instanceof MemberExpr member)) return null;
            if (!"downto".equals(member.property())) return null;
            return new Expression[] { member.object(), call.args().get(0) };
        }

        Statement parseForStatement(SourceLocation l) {
            advance(); // 'for'
            Token iterTok = advance();
            String varName = idents.declare(iterTok.value, snakeToCamel(iterTok.value));
            expect(TK.IN, "in");
            Expression startExpr = parseExpression();

            // Three loop headers, all of them real Ruby that iterates exactly
            // these values:
            //
            //   for i in 0...n       -> 0, 1, … n-1  (exclusive, ascending)
            //   for i in 0..n        -> 0, 1, … n    (inclusive, ascending)
            //   for i in n.downto(m) -> n, n-1, … m  (inclusive, DESCENDING)
            //
            // `downto` is what lets the Ruby surface spell a countdown.
            // Ruby's range operators only ever ascend — `(5..2)` is empty —
            // so `step = -1` was unreachable from this surface, and no fixture
            // could exercise it across all nine. `Integer#downto` is the
            // language's own countdown verb, it returns an Enumerator, and
            // `for x in enum` is valid Ruby over one.
            //
            // `5.downto(2)` is a postfix method call, so the start-expression
            // parser has already consumed the whole header by the time we get
            // here. Match on the shape it produced rather than on the tokens.
            boolean isExclusive = false;
            boolean descending = false;
            Expression endExpr;
            Expression[] downto = matchDowntoCall(startExpr);
            if (downto != null) {
                startExpr = downto[0];
                endExpr = downto[1];
                descending = true;
                isExclusive = false; // downto's bound is inclusive
            } else {
                if (peek().kind == TK.DOTDOTDOT) {
                    isExclusive = true;
                    advance();
                } else if (peek().kind == TK.DOTDOT) {
                    advance();
                } else {
                    errors.add(file + ":" + peek().line
                        + ": expected range operator '..' or '...', or '.downto(n)', in for loop");
                }
                endExpr = parseExpression();
            }

            match(TK.DO);
            skipNewlines();
            List<Statement> body = parseStatements();
            expect(TK.END, "end");

            SourceLocation varLoc = new SourceLocation(file, iterTok.line, iterTok.col);
            VariableDeclStatement init = new VariableDeclStatement(
                varName,
                new PrimitiveType(PrimitiveTypeName.BIGINT),
                startExpr,
                varLoc
            );
            Expression.BinaryOp cmpOp;
            if (descending) {
                cmpOp = Expression.BinaryOp.GE;
            } else if (isExclusive) {
                cmpOp = Expression.BinaryOp.LT;
            } else {
                cmpOp = Expression.BinaryOp.LE;
            }
            Expression cond = new BinaryExpr(cmpOp, new Identifier(varName), endExpr);
            Statement update = new ExpressionStatement(
                descending
                    ? new DecrementExpr(new Identifier(varName), false)
                    : new IncrementExpr(new Identifier(varName), false),
                l
            );
            return new ForStatement(init, cond, update, body, l);
        }

        Statement parseReturnStatement(SourceLocation l) {
            advance(); // 'return'
            Expression val = null;
            TK k = peek().kind;
            if (k != TK.NEWLINE && k != TK.END && k != TK.EOF) {
                val = parseExpression();
            }
            return new ReturnStatement(val, l);
        }

        Statement parseSuperCall(SourceLocation l) {
            advance(); // 'super'
            expect(TK.LPAREN, "(");
            List<Expression> args = new ArrayList<>();
            while (peek().kind != TK.RPAREN && peek().kind != TK.EOF) {
                args.add(parseExpression());
                if (!match(TK.COMMA)) break;
            }
            expect(TK.RPAREN, ")");
            return new ExpressionStatement(
                new CallExpr(new Identifier("super"), args),
                l
            );
        }

        Statement parseIvarStatement(SourceLocation l) {
            int start = pos;
            Token ivarTok = advance();
            String propName = snakeToCamel(ivarTok.value);
            Expression target = new PropertyAccessExpr(propName);

            // index-access on the LHS: @arr[i] = expr
            while (peek().kind == TK.LBRACKET) {
                advance();
                Expression idx = parseExpression();
                expect(TK.RBRACKET, "]");
                target = new IndexAccessExpr(target, idx);
            }

            if (match(TK.ASSIGN)) {
                Expression value = parseExpression();
                return new AssignmentStatement(target, value, l);
            }

            TK opKind = peek().kind;
            Expression.BinaryOp compoundOp = COMPOUND_OPS.get(opKind);
            if (compoundOp != null) {
                advance();
                Expression right = parseExpression();
                Expression value = new BinaryExpr(compoundOp, target, right);
                return new AssignmentStatement(target, value, l);
            }

            // Bare expression starting with @ivar (@x on its own line,
            // @x.method(...), or a private helper's implicit return such as
            // `@x + 1`). N-053: re-parse from the ivar as a whole expression;
            // continuing only the postfix chain left `+ 1` behind, and the
            // statement dispatcher skipped it.
            pos = start;
            return new ExpressionStatement(parseExpression(), l);
        }

        Statement parseIdentStatement(SourceLocation l) {
            Token nameTok = peek();
            String rawName = nameTok.value;

            if (peekAhead(1).kind == TK.ASSIGN) {
                advance(); // ident
                advance(); // '='
                Expression value = parseExpression();
                String camel = idents.declare(rawName, snakeToCamel(rawName));
                if (declaredLocals.contains(camel)) {
                    return new AssignmentStatement(new Identifier(camel), value, l);
                }
                declaredLocals.add(camel);
                return new VariableDeclStatement(camel, null, value, l);
            }

            Expression expr = parseExpression();
            if (match(TK.ASSIGN)) {
                Expression value = parseExpression();
                return new AssignmentStatement(expr, value, l);
            }
            TK opKind = peek().kind;
            Expression.BinaryOp compoundOp = COMPOUND_OPS.get(opKind);
            if (compoundOp != null) {
                advance();
                Expression right = parseExpression();
                Expression value = new BinaryExpr(compoundOp, expr, right);
                return new AssignmentStatement(expr, value, l);
            }
            return new ExpressionStatement(expr, l);
        }

        // ----------------------------------------------------------
        // Expression precedence climbing
        // ----------------------------------------------------------

        Expression parseExpression() {
            return nest.nested(this::parseTernary);
        }

        Expression parseTernary() {
            Expression e = parseOr();
            if (peek().kind == TK.QUESTION) {
                advance();
                Expression cons = parseExpression();
                expect(TK.COLON, ":");
                Expression alt = parseExpression();
                return new TernaryExpr(e, cons, alt);
            }
            return e;
        }

        Expression parseOr() {
            Expression left = parseAnd();
            while (peek().kind == TK.OR || peek().kind == TK.PIPEPIPE) {
                advance();
                Expression right = parseAnd();
                left = new BinaryExpr(Expression.BinaryOp.OR, left, right);
            }
            return left;
        }

        Expression parseAnd() {
            Expression left = parseNot();
            while (peek().kind == TK.AND || peek().kind == TK.AMPAMP) {
                advance();
                Expression right = parseNot();
                left = new BinaryExpr(Expression.BinaryOp.AND, left, right);
            }
            return left;
        }

        Expression parseNot() {
            if (peek().kind == TK.NOT || peek().kind == TK.BANG) {
                advance();
                Expression operand = nest.nested(this::parseNot);
                return new UnaryExpr(Expression.UnaryOp.NOT, operand);
            }
            return parseBitOr();
        }

        Expression parseBitOr() {
            Expression left = parseBitXor();
            while (peek().kind == TK.PIPE) {
                advance();
                Expression right = parseBitXor();
                left = new BinaryExpr(Expression.BinaryOp.BIT_OR, left, right);
            }
            return left;
        }

        Expression parseBitXor() {
            Expression left = parseBitAnd();
            while (peek().kind == TK.CARET) {
                advance();
                Expression right = parseBitAnd();
                left = new BinaryExpr(Expression.BinaryOp.BIT_XOR, left, right);
            }
            return left;
        }

        Expression parseBitAnd() {
            Expression left = parseEquality();
            while (peek().kind == TK.AMP) {
                advance();
                Expression right = parseEquality();
                left = new BinaryExpr(Expression.BinaryOp.BIT_AND, left, right);
            }
            return left;
        }

        Expression parseEquality() {
            Expression left = parseComparison();
            while (true) {
                TK k = peek().kind;
                if (k == TK.EQEQ) {
                    advance();
                    Expression right = parseComparison();
                    left = new BinaryExpr(Expression.BinaryOp.EQ, left, right);
                } else if (k == TK.NOTEQ) {
                    advance();
                    Expression right = parseComparison();
                    left = new BinaryExpr(Expression.BinaryOp.NEQ, left, right);
                } else break;
            }
            return left;
        }

        Expression parseComparison() {
            Expression left = parseShift();
            while (true) {
                TK k = peek().kind;
                Expression.BinaryOp op = switch (k) {
                    case LT -> Expression.BinaryOp.LT;
                    case LTEQ -> Expression.BinaryOp.LE;
                    case GT -> Expression.BinaryOp.GT;
                    case GTEQ -> Expression.BinaryOp.GE;
                    default -> null;
                };
                if (op == null) break;
                advance();
                Expression right = parseShift();
                left = new BinaryExpr(op, left, right);
            }
            return left;
        }

        Expression parseShift() {
            Expression left = parseAddSub();
            while (true) {
                TK k = peek().kind;
                if (k == TK.LSHIFT) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.SHL, left, parseAddSub());
                } else if (k == TK.RSHIFT) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.SHR, left, parseAddSub());
                } else break;
            }
            return left;
        }

        Expression parseAddSub() {
            Expression left = parseMulDiv();
            while (true) {
                TK k = peek().kind;
                if (k == TK.PLUS) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.ADD, left, parseMulDiv());
                } else if (k == TK.MINUS) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.SUB, left, parseMulDiv());
                } else break;
            }
            return left;
        }

        Expression parseMulDiv() {
            Expression left = parseUnary();
            while (true) {
                TK k = peek().kind;
                if (k == TK.STAR) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.MUL, left, parseUnary());
                } else if (k == TK.SLASH) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.DIV, left, parseUnary());
                } else if (k == TK.PERCENT) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.MOD, left, parseUnary());
                } else break;
            }
            return left;
        }

        Expression parseUnary() {
            TK k = peek().kind;
            if (k == TK.MINUS) {
                advance();
                return new UnaryExpr(Expression.UnaryOp.NEG, nest.nested(this::parseUnary));
            }
            if (k == TK.TILDE) {
                advance();
                return new UnaryExpr(Expression.UnaryOp.BIT_NOT, nest.nested(this::parseUnary));
            }
            if (k == TK.BANG) {
                advance();
                return new UnaryExpr(Expression.UnaryOp.NOT, nest.nested(this::parseUnary));
            }
            return parsePower();
        }

        Expression parsePower() {
            Expression base = parsePostfix();
            if (peek().kind == TK.STARSTAR) {
                advance();
                Expression exp = nest.nested(this::parsePower); // right-associative
                return new CallExpr(new Identifier("pow"), List.of(base, exp));
            }
            return base;
        }

        Expression parsePostfix() {
            Expression e = parsePrimary();
            return parsePostfixFrom(e);
        }

        Expression parsePostfixFrom(Expression expr) {
            while (true) {
                TK k = peek().kind;
                if (k == TK.DOT) {
                    advance();
                    Token propTok = advance();
                    String propName = mapBuiltinName(propTok.value);
                    if (peek().kind == TK.LPAREN) {
                        List<Expression> args = parseCallArgs();
                        if (expr instanceof Identifier id && "this".equals(id.name())) {
                            expr = new CallExpr(
                                new MemberExpr(new Identifier("this"), propName),
                                args
                            );
                        } else {
                            expr = new CallExpr(new MemberExpr(expr, propName), args);
                        }
                    } else {
                        if (expr instanceof Identifier id && "this".equals(id.name())) {
                            expr = new PropertyAccessExpr(propName);
                        } else {
                            expr = new MemberExpr(expr, propName);
                        }
                    }
                    continue;
                }
                if (k == TK.LPAREN) {
                    List<Expression> args = parseCallArgs();
                    expr = new CallExpr(expr, args);
                    continue;
                }
                if (k == TK.LBRACKET) {
                    advance();
                    Expression idx = parseExpression();
                    expect(TK.RBRACKET, "]");
                    expr = new IndexAccessExpr(expr, idx);
                    continue;
                }
                break;
            }
            return expr;
        }

        Expression parsePrimary() {
            Token t = peek();
            TK k = t.kind;
            switch (k) {
                case NUMBER -> {
                    advance();
                    return new BigIntLiteral(parseBigIntLiteral(t.value));
                }
                case TRUE -> { advance(); return new BoolLiteral(true); }
                case FALSE -> { advance(); return new BoolLiteral(false); }
                case HEXSTRING -> { advance(); return new ByteStringLiteral(t.value); }
                case STRING -> { advance(); return new ByteStringLiteral(t.value); }
                case NIL -> {
                    // N-416: `nil` is not a Rúnar value; refused, never read as 0.
                    errors.add(file + ":" + t.line + ":" + t.col
                        + ": 'nil' is not a Rúnar value (use a number, true, false or a hex string)");
                    advance();
                    return new BigIntLiteral(BigInteger.ZERO);
                }
                case IVAR -> {
                    advance();
                    return new PropertyAccessExpr(snakeToCamel(t.value));
                }
                case LPAREN -> {
                    advance();
                    Expression e = parseExpression();
                    expect(TK.RPAREN, ")");
                    return e;
                }
                case LBRACKET -> {
                    advance();
                    List<Expression> elems = new ArrayList<>();
                    while (peek().kind != TK.RBRACKET && peek().kind != TK.EOF) {
                        elems.add(parseExpression());
                        if (!match(TK.COMMA)) break;
                    }
                    expect(TK.RBRACKET, "]");
                    return new ArrayLiteralExpr(elems);
                }
                case IDENT, ASSERT -> {
                    advance();
                    String raw = t.value;
                    return new Identifier(mapBuiltinName(raw));
                }
                case SUPER -> { advance(); return new Identifier("super"); }
                default -> {
                    errors.add(file + ":" + t.line + ":" + t.col
                        + ": unexpected token in expression: '"
                        + (t.value.isEmpty() ? t.kind.name() : t.value) + "'");
                    advance();
                    return new BigIntLiteral(BigInteger.ZERO);
                }
            }
        }

        List<Expression> parseCallArgs() {
            expect(TK.LPAREN, "(");
            List<Expression> args = new ArrayList<>();
            while (peek().kind != TK.RPAREN && peek().kind != TK.EOF) {
                args.add(parseExpression());
                if (!match(TK.COMMA)) break;
            }
            expect(TK.RPAREN, ")");
            return args;
        }

        // ----------------------------------------------------------
        // Number parsing helpers
        // ----------------------------------------------------------

        long parseLongLiteral(String raw) {
            if (raw.startsWith("0x") || raw.startsWith("0X")) {
                return Long.parseLong(raw.substring(2), 16);
            }
            return Long.parseLong(raw, 10);
        }

        /** Parse a numeric literal as a BigInteger so 256-bit constants (e.g.
         *  the secp256k1 group order) compile cleanly even when they overflow
         *  a Java long. */
        BigInteger parseBigIntLiteral(String raw) {
            if (raw.startsWith("0x") || raw.startsWith("0X")) {
                return new BigInteger(raw.substring(2), 16);
            }
            return new BigInteger(raw, 10);
        }

        int parseIntLiteral(String raw) {
            if (raw.startsWith("0x") || raw.startsWith("0X")) {
                return Integer.parseInt(raw.substring(2), 16);
            }
            return Integer.parseInt(raw, 10);
        }

        // ----------------------------------------------------------
        // Bare-call rewriting (post-parse pass)
        // ----------------------------------------------------------

        List<Statement> rewriteBareCalls(List<Statement> stmts, Set<String> methodNames) {
            List<Statement> out = new ArrayList<>(stmts.size());
            for (Statement s : stmts) {
                out.add(rewriteStmt(s, methodNames));
            }
            return out;
        }

        Statement rewriteStmt(Statement s, Set<String> methodNames) {
            if (s instanceof ExpressionStatement es) {
                return new ExpressionStatement(
                    rewriteExpr(es.expression(), methodNames),
                    es.sourceLocation()
                );
            }
            if (s instanceof VariableDeclStatement vds) {
                return new VariableDeclStatement(
                    vds.name(),
                    vds.type(),
                    rewriteExpr(vds.init(), methodNames),
                    vds.sourceLocation()
                );
            }
            if (s instanceof AssignmentStatement as) {
                return new AssignmentStatement(
                    rewriteExpr(as.target(), methodNames),
                    rewriteExpr(as.value(), methodNames),
                    as.sourceLocation()
                );
            }
            if (s instanceof ReturnStatement rs) {
                Expression v = rs.value() != null ? rewriteExpr(rs.value(), methodNames) : null;
                return new ReturnStatement(v, rs.sourceLocation());
            }
            if (s instanceof IfStatement is) {
                Expression cond = rewriteExpr(is.condition(), methodNames);
                List<Statement> thenBody = rewriteBareCalls(is.thenBody(), methodNames);
                List<Statement> elseBody = is.elseBody() != null
                    ? rewriteBareCalls(is.elseBody(), methodNames)
                    : null;
                return new IfStatement(cond, thenBody, elseBody, is.sourceLocation());
            }
            if (s instanceof ForStatement fs) {
                List<Statement> body = rewriteBareCalls(fs.body(), methodNames);
                return new ForStatement(fs.init(), fs.condition(), fs.update(), body, fs.sourceLocation());
            }
            return s;
        }

        Expression rewriteExpr(Expression e, Set<String> methodNames) {
            if (e instanceof CallExpr ce) {
                List<Expression> newArgs = new ArrayList<>(ce.args().size());
                for (Expression a : ce.args()) newArgs.add(rewriteExpr(a, methodNames));
                Expression callee = ce.callee();
                if (callee instanceof Identifier id && methodNames.contains(id.name())) {
                    return new CallExpr(new PropertyAccessExpr(id.name()), newArgs);
                }
                return new CallExpr(rewriteExpr(callee, methodNames), newArgs);
            }
            if (e instanceof BinaryExpr be) {
                return new BinaryExpr(be.op(),
                    rewriteExpr(be.left(), methodNames),
                    rewriteExpr(be.right(), methodNames));
            }
            if (e instanceof UnaryExpr ue) {
                return new UnaryExpr(ue.op(), rewriteExpr(ue.operand(), methodNames));
            }
            if (e instanceof TernaryExpr te) {
                return new TernaryExpr(
                    rewriteExpr(te.condition(), methodNames),
                    rewriteExpr(te.consequent(), methodNames),
                    rewriteExpr(te.alternate(), methodNames)
                );
            }
            return e;
        }
    }

}
