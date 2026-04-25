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
        List<Token> tokens = tokenize(source);
        Parser parser = new Parser(tokens, filename);
        ContractNode contract = parser.parseTop();
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
     * Convert a snake_case identifier to camelCase. Only capitalises
     * lower-case letters or digits following an underscore (so {@code EC_P}
     * is left untouched). Strips leading underscores so {@code _foo_bar}
     * becomes {@code fooBar}.
     */
    static String snakeToCamel(String name) {
        int leading = 0;
        while (leading < name.length() && name.charAt(leading) == '_') {
            leading++;
        }
        String s = name.substring(leading);
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '_' && i + 1 < s.length()) {
                char next = s.charAt(i + 1);
                if ((next >= 'a' && next <= 'z') || (next >= '0' && next <= '9')) {
                    sb.append(Character.toUpperCase(next));
                    i++;
                    continue;
                }
            }
            sb.append(c);
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

    private static List<Token> tokenize(String source) throws ParseException {
        List<Token> tokens = new ArrayList<>();
        String[] lines = source.split("\n", -1);
        int parenDepth = 0;

        for (int lineIdx = 0; lineIdx < lines.length; lineIdx++) {
            int lineNum = lineIdx + 1;
            String raw = lines[lineIdx];
            // strip trailing carriage return
            if (raw.endsWith("\r")) {
                raw = raw.substring(0, raw.length() - 1);
            }
            String line = raw;

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
                int col = pos + 1;

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
                    tokens.add(new Token(TK.STRING, val.toString(), lineNum, col));
                    continue;
                }

                // Number (decimal or hex)
                if (Character.isDigit(ch)) {
                    StringBuilder buf = new StringBuilder();
                    if (ch == '0' && pos + 1 < line.length()
                        && (line.charAt(pos + 1) == 'x' || line.charAt(pos + 1) == 'X')) {
                        buf.append("0x");
                        pos += 2;
                        while (pos < line.length()) {
                            char c2 = line.charAt(pos);
                            if (c2 == '_') { pos++; continue; }
                            if (Character.isDigit(c2)
                                || (c2 >= 'a' && c2 <= 'f') || (c2 >= 'A' && c2 <= 'F')) {
                                buf.append(c2);
                                pos++;
                            } else {
                                break;
                            }
                        }
                    } else {
                        while (pos < line.length()) {
                            char c2 = line.charAt(pos);
                            if (c2 == '_') { pos++; continue; }
                            if (Character.isDigit(c2)) {
                                buf.append(c2);
                                pos++;
                            } else {
                                break;
                            }
                        }
                    }
                    tokens.add(new Token(TK.NUMBER, buf.toString(), lineNum, col));
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

                // Unknown character — skip rather than crash. Mirrors the
                // Python tokeniser behaviour.
                pos++;
            }

            if (parenDepth == 0) {
                tokens.add(new Token(TK.NEWLINE, "", lineNum, line.length() + 1));
            }
        }

        tokens.add(new Token(TK.EOF, "", lines.length + 1, 1));
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
        Set<String> declaredLocals = new HashSet<>();

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
            return parseClass();
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
                default -> {
                    errors.add(file + ":" + firstPart.line + ": unknown parent class: " + parentClassName);
                    return null;
                }
            }

            List<PropertyNode> properties = new ArrayList<>();
            List<MethodNode> methods = new ArrayList<>();
            MethodNode constructor = null;

            String pendingVisibility = null;
            Map<String, TypeNode> pendingParamTypes = null;

            while (peek().kind != TK.END && peek().kind != TK.EOF) {
                skipNewlines();
                if (peek().kind == TK.END || peek().kind == TK.EOF) break;

                if (checkIdent("prop")) {
                    PropertyNode p = parseProp(parentClass);
                    if (p != null) properties.add(p);
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
                        constructor = m;
                    } else {
                        methods.add(m);
                    }
                    pendingVisibility = null;
                    pendingParamTypes = null;
                    skipNewlines();
                    continue;
                }
                // Skip unknown tokens defensively.
                advance();
            }
            match(TK.END);

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
                    m.name(), m.params(), body, m.visibility(), m.sourceLocation()
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
            Expression initializer = null;

            while (peek().kind == TK.COMMA) {
                advance();
                if (checkIdent("readonly")) {
                    advance();
                    expect(TK.COLON, ":");
                    if (peek().kind == TK.TRUE) {
                        advance();
                        isReadonly = true;
                    } else if (peek().kind == TK.FALSE) {
                        advance();
                        isReadonly = false;
                    }
                } else if (checkIdent("default")) {
                    advance();
                    expect(TK.COLON, ":");
                    initializer = parsePrimary();
                }
            }

            // Stateless contracts: all properties readonly.
            if (parentClass == ParentClass.SMART_CONTRACT) {
                isReadonly = true;
            }

            // Skip rest of the line.
            while (peek().kind != TK.NEWLINE && peek().kind != TK.EOF) advance();

            return new PropertyNode(
                snakeToCamel(rawName),
                typeNode,
                isReadonly,
                initializer,
                propLoc,
                null
            );
        }

        TypeNode parseType() {
            Token t = advance();
            String rawName = t.value;
            if ("FixedArray".equals(rawName) && peek().kind == TK.LBRACKET) {
                advance(); // '['
                TypeNode elem = parseType();
                expect(TK.COMMA, ",");
                Token sizeTok = expect(TK.NUMBER, "number");
                int size = parseIntLiteral(sizeTok.value);
                expect(TK.RBRACKET, "]");
                return new FixedArrayType(elem, size);
            }
            return mapRbType(rawName);
        }

        MethodNode parseMethod(String pendingVisibility, Map<String, TypeNode> pendingParamTypes) {
            SourceLocation methodLoc = loc();
            expect(TK.DEF, "def");

            Token nameTok = advance();
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
                snakeToCamel(rawName),
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
                String camelName = snakeToCamel(rawName);
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
                default -> { advance(); yield null; }
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
            List<Statement> thenStmts = parseStatements();
            List<Statement> elseStmts = null;
            if (peek().kind == TK.ELSIF) {
                SourceLocation elifLoc = loc();
                elseStmts = new ArrayList<>();
                elseStmts.add(parseElsifStatement(elifLoc));
            } else if (peek().kind == TK.ELSE) {
                advance();
                skipNewlines();
                elseStmts = parseStatements();
            }
            expect(TK.END, "end");
            return new IfStatement(cond, thenStmts, elseStmts != null ? elseStmts : new ArrayList<>(), l);
        }

        Statement parseElsifStatement(SourceLocation l) {
            advance(); // 'elsif'
            Expression cond = parseExpression();
            skipNewlines();
            List<Statement> thenStmts = parseStatements();
            List<Statement> elseStmts = null;
            if (peek().kind == TK.ELSIF) {
                SourceLocation elifLoc = loc();
                elseStmts = new ArrayList<>();
                elseStmts.add(parseElsifStatement(elifLoc));
            } else if (peek().kind == TK.ELSE) {
                advance();
                skipNewlines();
                elseStmts = parseStatements();
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

        Statement parseForStatement(SourceLocation l) {
            advance(); // 'for'
            Token iterTok = advance();
            String varName = snakeToCamel(iterTok.value);
            expect(TK.IN, "in");
            Expression startExpr = parseExpression();

            boolean isExclusive = false;
            if (peek().kind == TK.DOTDOTDOT) {
                isExclusive = true;
                advance();
            } else if (peek().kind == TK.DOTDOT) {
                advance();
            } else {
                errors.add(file + ":" + peek().line
                    + ": expected range operator '..' or '...' in for loop");
            }
            Expression endExpr = parseExpression();

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
            Expression cond = new BinaryExpr(
                isExclusive ? Expression.BinaryOp.LT : Expression.BinaryOp.LE,
                new Identifier(varName),
                endExpr
            );
            Statement update = new ExpressionStatement(
                new IncrementExpr(new Identifier(varName), false),
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

            // Bare expression starting with @ivar (e.g. @x.method(...))
            Expression expr = parsePostfixFrom(target);
            return new ExpressionStatement(expr, l);
        }

        Statement parseIdentStatement(SourceLocation l) {
            Token nameTok = peek();
            String rawName = nameTok.value;

            if (peekAhead(1).kind == TK.ASSIGN) {
                advance(); // ident
                advance(); // '='
                Expression value = parseExpression();
                String camel = snakeToCamel(rawName);
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
            return parseTernary();
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
                Expression operand = parseNot();
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
                return new UnaryExpr(Expression.UnaryOp.NEG, parseUnary());
            }
            if (k == TK.TILDE) {
                advance();
                return new UnaryExpr(Expression.UnaryOp.BIT_NOT, parseUnary());
            }
            if (k == TK.BANG) {
                advance();
                return new UnaryExpr(Expression.UnaryOp.NOT, parseUnary());
            }
            return parsePower();
        }

        Expression parsePower() {
            Expression base = parsePostfix();
            if (peek().kind == TK.STARSTAR) {
                advance();
                Expression exp = parsePower(); // right-associative
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
                    return new BigIntLiteral(BigInteger.valueOf(parseLongLiteral(t.value)));
                }
                case TRUE -> { advance(); return new BoolLiteral(true); }
                case FALSE -> { advance(); return new BoolLiteral(false); }
                case HEXSTRING -> { advance(); return new ByteStringLiteral(t.value); }
                case STRING -> { advance(); return new ByteStringLiteral(t.value); }
                case NIL -> { advance(); return new BigIntLiteral(BigInteger.ZERO); }
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
