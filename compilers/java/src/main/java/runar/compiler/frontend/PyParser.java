package runar.compiler.frontend;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
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
 * Parses {@code .runar.py} source into a Rúnar {@link ContractNode}.
 *
 * <p>Hand-written tokenizer with INDENT/DEDENT plus a recursive-descent
 * parser. Mirrors {@code compilers/python/runar_compiler/frontend/parser_python.py}
 * and {@code compilers/go/frontend/parser_python.go} so all six compilers
 * produce byte-identical AST output for the same Python contract source.
 *
 * <p>The Python surface understood here is the Rúnar subset: a single
 * {@code class} extending {@code SmartContract} or {@code StatefulSmartContract},
 * type-annotated fields, an optional {@code __init__}, and methods marked
 * {@code @public}. Snake_case identifiers are converted to camelCase so the
 * downstream IR matches the TypeScript reference.
 */
public final class PyParser {

    private PyParser() {}

    public static ContractNode parse(String source, String filename) throws ParseException {
        PyParserImpl impl = new PyParserImpl(filename);
        List<Token> raw = tokenizeRaw(source);
        impl.tokens = insertIndentation(raw);
        impl.pos = 0;
        ContractNode contract = impl.parseContract();
        if (!impl.errors.isEmpty()) {
            throw new ParseException(String.join("\n", impl.errors));
        }
        return contract;
    }

    // -----------------------------------------------------------------
    // Public exception type
    // -----------------------------------------------------------------

    public static final class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
    }

    // -----------------------------------------------------------------
    // Token kinds
    // -----------------------------------------------------------------

    private enum TokKind {
        EOF,
        IDENT,
        NUMBER,
        STRING,
        LPAREN,
        RPAREN,
        LBRACKET,
        RBRACKET,
        LBRACE,
        RBRACE,
        COMMA,
        DOT,
        COLON,
        SEMICOLON,
        ASSIGN,
        EQEQ,
        NOTEQ,
        LT,
        LTEQ,
        GT,
        GTEQ,
        PLUS,
        MINUS,
        STAR,
        SLASH,
        PERCENT,
        BANG,
        TILDE,
        AMP,
        PIPE,
        CARET,
        AMPAMP,
        PIPEPIPE,
        PLUSEQ,
        MINUSEQ,
        STAREQ,
        SLASHEQ,
        PERCENTEQ,
        AT,
        SLASHSLASH,
        STARSTAR,
        ARROW,
        LSHIFT,
        RSHIFT,
        INDENT,
        DEDENT,
        NEWLINE
    }

    private static final class Token {
        final TokKind kind;
        final String value;
        final int line;
        final int col;

        Token(TokKind kind, String value, int line, int col) {
            this.kind = kind;
            this.value = value;
            this.line = line;
            this.col = col;
        }
    }

    // -----------------------------------------------------------------
    // Special name mappings (snake_case -> camelCase)
    // -----------------------------------------------------------------

    private static final Map<String, String> SPECIAL_NAMES = buildSpecialNames();

    private static Map<String, String> buildSpecialNames() {
        Map<String, String> m = new HashMap<>();
        m.put("assert_", "assert");
        m.put("__init__", "constructor");
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
        m.put("extract_sequence", "extractSequence");
        m.put("extract_version", "extractVersion");
        m.put("extract_amount", "extractAmount");
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
        m.put("sha256", "sha256");
        m.put("ripemd160", "ripemd160");
        m.put("hash160", "hash160");
        m.put("hash256", "hash256");
        m.put("num2bin", "num2bin");
        m.put("bin2num", "bin2num");
        m.put("int_to_str", "int2str");
        m.put("log2", "log2");
        m.put("div_mod", "divmod");
        m.put("EC_P", "EC_P");
        m.put("EC_N", "EC_N");
        m.put("EC_G", "EC_G");
        return m;
    }

    /** Convert a Python snake_case name to Rúnar camelCase. */
    static String pyConvertName(String name) {
        // 1. Special names first.
        String special = SPECIAL_NAMES.get(name);
        if (special != null) {
            return special;
        }
        // 2. No underscores → return as-is.
        if (name.indexOf('_') < 0) {
            return name;
        }
        // 3. Dunder names (e.g. __init__) — preserved untouched after the
        //    SPECIAL_NAMES lookup so future dunders flow through.
        if (name.startsWith("__") && name.endsWith("__")) {
            return name;
        }
        // 4. Names ending with `_` that aren't in SPECIAL_NAMES drop the
        //    trailing underscore unless an explicit alias exists for the
        //    "name_" form. Mirrors the Python parser's two-pass lookup so
        //    `assert_` → `assert` flows through SPECIAL_NAMES while
        //    `something_` falls through to the normal camelCase path on the
        //    cleaned-up form.
        String cleaned = stripTrailingUnderscore(name);
        if (!cleaned.equals(name)) {
            String key = cleaned + "_";
            if (SPECIAL_NAMES.containsKey(key)) {
                return SPECIAL_NAMES.get(key);
            }
        }
        // 5. Strip a single leading underscore on private names.
        String stripped = name;
        if (stripped.startsWith("_") && !stripped.startsWith("__")) {
            stripped = stripped.substring(1);
        }
        // 6. snake_case → camelCase.
        String[] parts = stripped.split("_", -1);
        if (parts.length <= 1) {
            return stripped;
        }
        StringBuilder sb = new StringBuilder(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            String p = parts[i];
            if (!p.isEmpty()) {
                sb.append(Character.toUpperCase(p.charAt(0))).append(p.substring(1));
            }
        }
        return sb.toString();
    }

    private static String stripTrailingUnderscore(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '_') end--;
        return s.substring(0, end);
    }

    // -----------------------------------------------------------------
    // Type parsing helpers
    // -----------------------------------------------------------------

    private static final Map<String, String> TYPE_MAP = buildTypeMap();

    private static Map<String, String> buildTypeMap() {
        Map<String, String> m = new HashMap<>();
        m.put("int", "bigint");
        m.put("Int", "bigint");
        m.put("Bigint", "bigint");
        m.put("bigint", "bigint");
        m.put("bool", "boolean");
        m.put("Bool", "boolean");
        m.put("boolean", "boolean");
        m.put("bytes", "ByteString");
        m.put("ByteString", "ByteString");
        m.put("PubKey", "PubKey");
        m.put("Sig", "Sig");
        m.put("Sha256", "Sha256");
        m.put("Sha256Digest", "Sha256");
        m.put("Ripemd160", "Ripemd160");
        m.put("Addr", "Addr");
        m.put("SigHashPreimage", "SigHashPreimage");
        m.put("RabinSig", "RabinSig");
        m.put("RabinPubKey", "RabinPubKey");
        m.put("Point", "Point");
        m.put("P256Point", "P256Point");
        m.put("P384Point", "P384Point");
        return m;
    }

    private static final Set<String> PRIMITIVE_TYPE_NAMES = new HashSet<>(Arrays.asList(
        "bigint", "boolean", "ByteString", "PubKey", "Sig", "Sha256", "Ripemd160",
        "Addr", "SigHashPreimage", "RabinSig", "RabinPubKey", "Point", "P256Point", "P384Point"
    ));

    private static TypeNode parsePyType(String name) {
        String mapped = TYPE_MAP.get(name);
        if (mapped != null) {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(mapped));
        }
        if (PRIMITIVE_TYPE_NAMES.contains(name)) {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(name));
        }
        return new CustomType(name);
    }

    // -----------------------------------------------------------------
    // Byte-string helpers
    // -----------------------------------------------------------------

    /** Convert a Python byte-string content like {@code \xde\xad} to hex {@code "dead"}. */
    static String pyByteStringToHex(String s) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < n) {
                char nc = s.charAt(i + 1);
                if (nc == 'x' && i + 3 < n) {
                    out.append(s, i + 2, i + 4);
                    i += 4;
                    continue;
                } else if (nc == '0') {
                    out.append("00");
                    i += 2;
                    continue;
                }
            }
            out.append(String.format("%02x", (int) c));
            i++;
        }
        return out.toString();
    }

    // -----------------------------------------------------------------
    // Tokenizer (raw — without INDENT/DEDENT)
    // -----------------------------------------------------------------

    private static boolean isIdentStart(char ch) {
        return Character.isLetter(ch) || ch == '_';
    }

    private static boolean isIdentPart(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '_';
    }

    private static boolean isHexDigit(char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    }

    private static List<Token> tokenizeRaw(String source) {
        List<Token> tokens = new ArrayList<>();
        int line = 1;
        int col = 0;
        int i = 0;
        int parenDepth = 0;
        int n = source.length();

        while (i < n) {
            char ch = source.charAt(i);

            // Newlines (consume \r\n as one).
            if (ch == '\n' || ch == '\r') {
                if (ch == '\r') {
                    i++;
                    if (i < n && source.charAt(i) == '\n') {
                        i++;
                    }
                } else {
                    i++;
                }
                if (parenDepth == 0) {
                    tokens.add(new Token(TokKind.NEWLINE, "\n", line, col));
                }
                line++;
                col = 0;
                continue;
            }

            // Whitespace.
            if (ch == ' ' || ch == '\t') {
                i++;
                col++;
                continue;
            }

            // Comment.
            if (ch == '#') {
                while (i < n && source.charAt(i) != '\n' && source.charAt(i) != '\r') {
                    i++;
                }
                continue;
            }

            int startCol = col;

            // Byte string literals: b'...' / b"..."
            if (ch == 'b' && i + 1 < n && (source.charAt(i + 1) == '\'' || source.charAt(i + 1) == '"')) {
                char quote = source.charAt(i + 1);
                i += 2;
                col += 2;
                int start = i;
                while (i < n && source.charAt(i) != quote) {
                    if (source.charAt(i) == '\\') {
                        i++;
                        col++;
                    }
                    i++;
                    col++;
                }
                String val = source.substring(start, Math.min(i, n));
                if (i < n) {
                    i++;
                    col++;
                }
                tokens.add(new Token(TokKind.STRING, pyByteStringToHex(val), line, startCol));
                continue;
            }

            // String literals: '…' / "…" / triple-quoted docstrings (skipped).
            if (ch == '\'' || ch == '"') {
                char quote = ch;
                if (i + 2 < n && source.charAt(i + 1) == quote && source.charAt(i + 2) == quote) {
                    // Triple-quoted: docstring — consume without emitting a token.
                    i += 3;
                    col += 3;
                    while (i + 2 < n) {
                        if (source.charAt(i) == quote
                            && source.charAt(i + 1) == quote
                            && source.charAt(i + 2) == quote) {
                            break;
                        }
                        if (source.charAt(i) == '\n') {
                            line++;
                            col = 0;
                        } else {
                            col++;
                        }
                        i++;
                    }
                    if (i + 2 < n) {
                        i += 3;
                        col += 3;
                    }
                    continue;
                }
                i++;
                col++;
                int start = i;
                while (i < n && source.charAt(i) != quote) {
                    if (source.charAt(i) == '\\') {
                        i++;
                        col++;
                    }
                    i++;
                    col++;
                }
                String val = source.substring(start, Math.min(i, n));
                if (i < n) {
                    i++;
                    col++;
                }
                tokens.add(new Token(TokKind.STRING, val, line, startCol));
                continue;
            }

            // Numbers.
            if (Character.isDigit(ch)) {
                int start = i;
                if (ch == '0' && i + 1 < n && (source.charAt(i + 1) == 'x' || source.charAt(i + 1) == 'X')) {
                    i += 2;
                    col += 2;
                    while (i < n && isHexDigit(source.charAt(i))) {
                        i++;
                        col++;
                    }
                } else {
                    while (i < n && (Character.isDigit(source.charAt(i)) || source.charAt(i) == '_')) {
                        i++;
                        col++;
                    }
                }
                String numStr = source.substring(start, i).replace("_", "");
                tokens.add(new Token(TokKind.NUMBER, numStr, line, startCol));
                continue;
            }

            // Identifiers & keywords.
            if (isIdentStart(ch)) {
                int start = i;
                while (i < n && isIdentPart(source.charAt(i))) {
                    i++;
                    col++;
                }
                String word = source.substring(start, i);
                switch (word) {
                    case "and" -> tokens.add(new Token(TokKind.AMPAMP, "and", line, startCol));
                    case "or" -> tokens.add(new Token(TokKind.PIPEPIPE, "or", line, startCol));
                    case "not" -> tokens.add(new Token(TokKind.BANG, "not", line, startCol));
                    default -> tokens.add(new Token(TokKind.IDENT, word, line, startCol));
                }
                continue;
            }

            // Three-char operators.
            if (i + 2 < n) {
                String three = source.substring(i, i + 3);
                if ("//=".equals(three)) {
                    tokens.add(new Token(TokKind.SLASHEQ, "//=", line, startCol));
                    i += 3;
                    col += 3;
                    continue;
                }
            }

            // Two-char operators.
            if (i + 1 < n) {
                String two = source.substring(i, i + 2);
                TokKind twoKind = switch (two) {
                    case "==" -> TokKind.EQEQ;
                    case "!=" -> TokKind.NOTEQ;
                    case "<=" -> TokKind.LTEQ;
                    case ">=" -> TokKind.GTEQ;
                    case "+=" -> TokKind.PLUSEQ;
                    case "-=" -> TokKind.MINUSEQ;
                    case "*=" -> TokKind.STAREQ;
                    case "%=" -> TokKind.PERCENTEQ;
                    case "//" -> TokKind.SLASHSLASH;
                    case "**" -> TokKind.STARSTAR;
                    case "->" -> TokKind.ARROW;
                    case "<<" -> TokKind.LSHIFT;
                    case ">>" -> TokKind.RSHIFT;
                    default -> null;
                };
                if (twoKind != null) {
                    tokens.add(new Token(twoKind, two, line, startCol));
                    i += 2;
                    col += 2;
                    continue;
                }
            }

            // Single-char operators.
            TokKind oneKind = switch (ch) {
                case '(' -> TokKind.LPAREN;
                case ')' -> TokKind.RPAREN;
                case '[' -> TokKind.LBRACKET;
                case ']' -> TokKind.RBRACKET;
                case '{' -> TokKind.LBRACE;
                case '}' -> TokKind.RBRACE;
                case ',' -> TokKind.COMMA;
                case '.' -> TokKind.DOT;
                case ':' -> TokKind.COLON;
                case ';' -> TokKind.SEMICOLON;
                case '=' -> TokKind.ASSIGN;
                case '<' -> TokKind.LT;
                case '>' -> TokKind.GT;
                case '+' -> TokKind.PLUS;
                case '-' -> TokKind.MINUS;
                case '*' -> TokKind.STAR;
                case '/' -> TokKind.SLASH;
                case '%' -> TokKind.PERCENT;
                case '!' -> TokKind.BANG;
                case '~' -> TokKind.TILDE;
                case '&' -> TokKind.AMP;
                case '|' -> TokKind.PIPE;
                case '^' -> TokKind.CARET;
                case '@' -> TokKind.AT;
                default -> null;
            };
            if (oneKind != null) {
                if (ch == '(' || ch == '[' || ch == '{') {
                    parenDepth++;
                } else if (ch == ')' || ch == ']' || ch == '}') {
                    if (parenDepth > 0) parenDepth--;
                }
                tokens.add(new Token(oneKind, String.valueOf(ch), line, startCol));
                i++;
                col++;
                continue;
            }

            // Skip unknown characters (mirror Python parser behaviour).
            i++;
            col++;
        }

        // Ensure final NEWLINE before EOF.
        if (tokens.isEmpty() || tokens.get(tokens.size() - 1).kind != TokKind.NEWLINE) {
            tokens.add(new Token(TokKind.NEWLINE, "\n", line, col));
        }
        tokens.add(new Token(TokKind.EOF, "", line, col));
        return tokens;
    }

    // -----------------------------------------------------------------
    // Indentation insertion (NEWLINE → INDENT/DEDENT layout)
    // -----------------------------------------------------------------

    private static List<Token> insertIndentation(List<Token> raw) {
        List<Token> result = new ArrayList<>(raw.size());
        List<Integer> indentStack = new ArrayList<>();
        indentStack.add(0);
        boolean atLineStart = true;
        int i = 0;
        while (i < raw.size()) {
            Token tok = raw.get(i);

            if (tok.kind == TokKind.NEWLINE) {
                result.add(tok);
                atLineStart = true;
                i++;
                continue;
            }

            if (tok.kind == TokKind.EOF) {
                while (indentStack.size() > 1) {
                    result.add(new Token(TokKind.DEDENT, "", tok.line, tok.col));
                    indentStack.remove(indentStack.size() - 1);
                }
                result.add(tok);
                break;
            }

            if (atLineStart) {
                atLineStart = false;
                int indent = tok.col;
                int currentIndent = indentStack.get(indentStack.size() - 1);
                if (indent > currentIndent) {
                    indentStack.add(indent);
                    result.add(new Token(TokKind.INDENT, "", tok.line, tok.col));
                } else if (indent < currentIndent) {
                    while (indentStack.size() > 1 && indentStack.get(indentStack.size() - 1) > indent) {
                        indentStack.remove(indentStack.size() - 1);
                        result.add(new Token(TokKind.DEDENT, "", tok.line, tok.col));
                    }
                }
            }

            result.add(tok);
            i++;
        }
        return result;
    }

    // -----------------------------------------------------------------
    // Recursive-descent parser
    // -----------------------------------------------------------------

    private static final class PyParserImpl {
        final String fileName;
        List<Token> tokens = new ArrayList<>();
        int pos = 0;
        final List<String> errors = new ArrayList<>();

        PyParserImpl(String fileName) {
            this.fileName = fileName;
        }

        // -- Token helpers ----------------------------------------------------

        Token peek() {
            if (pos < tokens.size()) return tokens.get(pos);
            return new Token(TokKind.EOF, "", 0, 0);
        }

        Token advance() {
            Token t = peek();
            if (pos < tokens.size()) pos++;
            return t;
        }

        Token expect(TokKind kind) {
            Token t = advance();
            if (t.kind != kind) {
                addError("line " + t.line + ": expected token kind " + kind
                    + ", got " + t.kind + " (" + repr(t.value) + ")");
            }
            return t;
        }

        Token expectIdent(String value) {
            Token t = advance();
            if (t.kind != TokKind.IDENT || !t.value.equals(value)) {
                addError("line " + t.line + ": expected '" + value + "', got " + repr(t.value));
            }
            return t;
        }

        boolean check(TokKind kind) {
            return peek().kind == kind;
        }

        boolean checkIdent(String value) {
            Token t = peek();
            return t.kind == TokKind.IDENT && t.value.equals(value);
        }

        boolean match(TokKind kind) {
            if (check(kind)) {
                advance();
                return true;
            }
            return false;
        }

        boolean matchIdent(String value) {
            if (checkIdent(value)) {
                advance();
                return true;
            }
            return false;
        }

        SourceLocation loc() {
            Token t = peek();
            return new SourceLocation(fileName, t.line, t.col);
        }

        void skipNewlines() {
            while (check(TokKind.NEWLINE)) advance();
        }

        void addError(String msg) {
            errors.add(msg);
        }

        static String repr(String v) {
            return "'" + v + "'";
        }

        // -- Type parsing -----------------------------------------------------

        TypeNode parseTypeAnnotation() {
            Token tok = peek();
            if (tok.kind != TokKind.IDENT) {
                addError("line " + tok.line + ": expected type name, got " + repr(tok.value));
                advance();
                return new CustomType("unknown");
            }
            String name = tok.value;
            advance();

            if (name.equals("Readonly")) {
                if (match(TokKind.LBRACKET)) {
                    TypeNode inner = parseTypeAnnotation();
                    expect(TokKind.RBRACKET);
                    return inner;
                }
                return new CustomType(name);
            }

            if (name.equals("FixedArray")) {
                if (match(TokKind.LBRACKET)) {
                    TypeNode elem = parseTypeAnnotation();
                    expect(TokKind.COMMA);
                    Token sizeTok = expect(TokKind.NUMBER);
                    int size;
                    try {
                        size = parseIntFlexible(sizeTok.value);
                    } catch (NumberFormatException e) {
                        size = 0;
                        addError("line " + sizeTok.line + ": FixedArray size must be integer");
                    }
                    expect(TokKind.RBRACKET);
                    return new FixedArrayType(elem, size);
                }
                return new CustomType(name);
            }

            // Other generics: skip the bracketed parameter list, return the
            // base type.
            if (check(TokKind.LBRACKET)) {
                advance();
                int depth = 1;
                while (depth > 0 && !check(TokKind.EOF)) {
                    if (check(TokKind.LBRACKET)) depth++;
                    if (check(TokKind.RBRACKET)) {
                        depth--;
                        if (depth == 0) {
                            advance();
                            break;
                        }
                    }
                    advance();
                }
                return parsePyType(name);
            }

            return parsePyType(name);
        }

        // -- Top-level contract parsing --------------------------------------

        ContractNode parseContract() throws ParseException {
            skipNewlines();

            // Skip module-level import / from statements.
            while (checkIdent("from") || checkIdent("import")) {
                while (!check(TokKind.NEWLINE) && !check(TokKind.EOF)) advance();
                skipNewlines();
            }

            if (!matchIdent("class")) {
                throw new ParseException("expected 'class' keyword");
            }

            Token nameTok = expect(TokKind.IDENT);
            String contractName = nameTok.value;

            String parentClassName = "SmartContract";
            if (match(TokKind.LPAREN)) {
                Token parentTok = expect(TokKind.IDENT);
                parentClassName = parentTok.value;
                expect(TokKind.RPAREN);
            }

            ParentClass parentClass;
            switch (parentClassName) {
                case "SmartContract" -> parentClass = ParentClass.SMART_CONTRACT;
                case "StatefulSmartContract" -> parentClass = ParentClass.STATEFUL_SMART_CONTRACT;
                default -> throw new ParseException("unknown parent class: " + parentClassName);
            }

            expect(TokKind.COLON);
            skipNewlines();
            expect(TokKind.INDENT);

            List<PropertyNode> properties = new ArrayList<>();
            MethodNode constructor = null;
            List<MethodNode> methods = new ArrayList<>();

            while (!check(TokKind.DEDENT) && !check(TokKind.EOF)) {
                skipNewlines();
                if (check(TokKind.DEDENT) || check(TokKind.EOF)) break;

                // Decorator: @public def foo(...)
                if (check(TokKind.AT)) {
                    advance();
                    Token decoratorTok = expect(TokKind.IDENT);
                    String decorator = decoratorTok.value;
                    skipNewlines();
                    if (checkIdent("def")) {
                        methods.add(parseMethod(decorator));
                    } else {
                        addError("line " + peek().line + ": expected 'def' after @" + decorator);
                    }
                    continue;
                }

                // def __init__ / def method
                if (checkIdent("def")) {
                    if (pos + 1 < tokens.size() && tokens.get(pos + 1).value.equals("__init__")) {
                        constructor = parseConstructor(properties);
                    } else {
                        methods.add(parseMethod("private"));
                    }
                    continue;
                }

                // pass
                if (matchIdent("pass")) {
                    skipNewlines();
                    continue;
                }

                // Property: name: Type [ = init ]
                if (peek().kind == TokKind.IDENT && isPropertyDecl()) {
                    PropertyNode p = parseProperty(parentClassName);
                    if (p != null) properties.add(p);
                    continue;
                }

                advance();
            }

            match(TokKind.DEDENT);

            if (constructor == null) {
                constructor = new MethodNode(
                    "constructor",
                    new ArrayList<>(),
                    new ArrayList<>(),
                    Visibility.PUBLIC,
                    new SourceLocation(fileName, 1, 0)
                );
            }

            return new ContractNode(contractName, parentClass, properties, constructor, methods, fileName);
        }

        boolean isPropertyDecl() {
            if (pos + 1 >= tokens.size()) return false;
            return tokens.get(pos + 1).kind == TokKind.COLON;
        }

        // -- Property parsing -------------------------------------------------

        PropertyNode parseProperty(String parentClassName) {
            SourceLocation location = loc();
            Token nameTok = expect(TokKind.IDENT);
            String propName = pyConvertName(nameTok.value);
            expect(TokKind.COLON);

            boolean isReadonly = false;
            if (checkIdent("Readonly")) {
                isReadonly = true;
            }
            if (parentClassName.equals("SmartContract")) {
                isReadonly = true;
            }

            TypeNode typeNode = parseTypeAnnotation();

            Expression initializer = null;
            if (match(TokKind.ASSIGN)) {
                initializer = parseExpression();
            }
            skipNewlines();

            return new PropertyNode(propName, typeNode, isReadonly, initializer, location, null);
        }

        // -- Constructor parsing ---------------------------------------------

        MethodNode parseConstructor(List<PropertyNode> properties) {
            SourceLocation location = loc();
            expectIdent("def");
            expectIdent("__init__");

            List<ParamNode> params = parseParams();

            if (match(TokKind.ARROW)) {
                advance(); // skip return type
            }

            expect(TokKind.COLON);
            List<Statement> body = parseBlock();

            // Transform `super().__init__(...)` (or `super().constructor(...)`)
            // into the canonical `super(...)` call form.
            List<Statement> ctorBody = new ArrayList<>();
            boolean foundSuper = false;
            for (Statement stmt : body) {
                Statement transformed = stmt;
                if (stmt instanceof ExpressionStatement es
                    && es.expression() instanceof CallExpr call
                    && call.callee() instanceof MemberExpr me
                    && (me.property().equals("__init__") || me.property().equals("constructor"))
                    && me.object() instanceof CallExpr superCall
                    && superCall.callee() instanceof Identifier sid
                    && sid.name().equals("super")) {
                    transformed = new ExpressionStatement(
                        new CallExpr(new Identifier("super"), call.args()),
                        es.sourceLocation()
                    );
                    foundSuper = true;
                }
                ctorBody.add(transformed);
            }
            if (!foundSuper) {
                List<Expression> superArgs = new ArrayList<>(params.size());
                for (ParamNode p : params) {
                    superArgs.add(new Identifier(p.name()));
                }
                ctorBody.add(0, new ExpressionStatement(
                    new CallExpr(new Identifier("super"), superArgs),
                    location
                ));
            }

            return new MethodNode("constructor", params, ctorBody, Visibility.PUBLIC, location);
        }

        // -- Method parsing ---------------------------------------------------

        MethodNode parseMethod(String visibility) {
            SourceLocation location = loc();
            expectIdent("def");
            Token nameTok = expect(TokKind.IDENT);
            String name = pyConvertName(nameTok.value);

            List<ParamNode> params = parseParams();

            if (match(TokKind.ARROW)) {
                parseTypeAnnotation(); // skip return type
            }

            expect(TokKind.COLON);
            List<Statement> body = parseBlock();

            Visibility vis = visibility.equals("public") ? Visibility.PUBLIC : Visibility.PRIVATE;
            return new MethodNode(name, params, body, vis, location);
        }

        // -- Parameters -------------------------------------------------------

        List<ParamNode> parseParams() {
            expect(TokKind.LPAREN);
            List<ParamNode> params = new ArrayList<>();

            while (!check(TokKind.RPAREN) && !check(TokKind.EOF)) {
                Token nameTok = expect(TokKind.IDENT);
                String paramName = nameTok.value;

                if (paramName.equals("self")) {
                    if (!match(TokKind.COMMA)) break;
                    continue;
                }

                TypeNode typ = null;
                if (match(TokKind.COLON)) {
                    typ = parseTypeAnnotation();
                }

                params.add(new ParamNode(pyConvertName(paramName), typ));

                if (!match(TokKind.COMMA)) break;
            }

            expect(TokKind.RPAREN);
            return params;
        }

        // -- Block ------------------------------------------------------------

        List<Statement> parseBlock() {
            skipNewlines();
            expect(TokKind.INDENT);

            List<Statement> stmts = new ArrayList<>();
            while (!check(TokKind.DEDENT) && !check(TokKind.EOF)) {
                skipNewlines();
                if (check(TokKind.DEDENT) || check(TokKind.EOF)) break;
                Statement s = parseStatement();
                if (s != null) stmts.add(s);
            }
            match(TokKind.DEDENT);
            return stmts;
        }

        // -- Statement parsing -----------------------------------------------

        Statement parseStatement() {
            SourceLocation location = loc();

            if (checkIdent("assert") || checkIdent("assert_")) {
                return parseAssert(location);
            }
            if (checkIdent("if")) {
                return parseIf(location);
            }
            if (checkIdent("for")) {
                return parseFor(location);
            }
            if (checkIdent("return")) {
                return parseReturn(location);
            }
            if (matchIdent("pass")) {
                skipNewlines();
                return null;
            }
            if (checkIdent("break") || checkIdent("continue")) {
                String kw = peek().value;
                advance();
                skipNewlines();
                addError("line " + location.line() + ": Unsupported statement kind: "
                    + kw + " — Rúnar does not support loop early-exit");
                return null;
            }
            return parseExprOrAssign(location);
        }

        Statement parseAssert(SourceLocation location) {
            Token tok = advance();
            if (tok.value.equals("assert_")) {
                expect(TokKind.LPAREN);
                Expression expr = parseExpression();
                expect(TokKind.RPAREN);
                skipNewlines();
                return new ExpressionStatement(
                    new CallExpr(new Identifier("assert"), List.of(expr)),
                    location
                );
            }
            // Plain `assert` keyword: optional parens.
            if (check(TokKind.LPAREN)) {
                advance();
                Expression expr = parseExpression();
                expect(TokKind.RPAREN);
                skipNewlines();
                return new ExpressionStatement(
                    new CallExpr(new Identifier("assert"), List.of(expr)),
                    location
                );
            }
            Expression expr = parseExpression();
            skipNewlines();
            return new ExpressionStatement(
                new CallExpr(new Identifier("assert"), List.of(expr)),
                location
            );
        }

        Statement parseIf(SourceLocation location) {
            expectIdent("if");
            return parseIfBody(location);
        }

        Statement parseIfBody(SourceLocation location) {
            Expression condition = parseExpression();
            expect(TokKind.COLON);
            List<Statement> thenBlock = parseBlock();

            List<Statement> elseBlock = null;
            skipNewlines();
            if (checkIdent("elif")) {
                SourceLocation elifLoc = loc();
                advance();
                Statement elif = parseIfBody(elifLoc);
                elseBlock = new ArrayList<>();
                elseBlock.add(elif);
            } else if (matchIdent("else")) {
                expect(TokKind.COLON);
                elseBlock = parseBlock();
            }
            return new IfStatement(condition, thenBlock, elseBlock, location);
        }

        Statement parseFor(SourceLocation location) {
            expectIdent("for");
            Token varTok = expect(TokKind.IDENT);
            String varName = pyConvertName(varTok.value);

            expectIdent("in");
            expectIdent("range");
            expect(TokKind.LPAREN);

            Expression first = parseExpression();
            Expression initExpr;
            Expression limitExpr;
            if (match(TokKind.COMMA)) {
                initExpr = first;
                limitExpr = parseExpression();
            } else {
                initExpr = new BigIntLiteral(BigInteger.ZERO);
                limitExpr = first;
            }
            expect(TokKind.RPAREN);
            expect(TokKind.COLON);

            List<Statement> body = parseBlock();

            VariableDeclStatement init = new VariableDeclStatement(
                varName,
                new PrimitiveType(PrimitiveTypeName.BIGINT),
                initExpr,
                location
            );
            BinaryExpr condition = new BinaryExpr(
                Expression.BinaryOp.LT,
                new Identifier(varName),
                limitExpr
            );
            ExpressionStatement update = new ExpressionStatement(
                new IncrementExpr(new Identifier(varName), false),
                location
            );

            return new ForStatement(init, condition, update, body, location);
        }

        Statement parseReturn(SourceLocation location) {
            expectIdent("return");
            Expression value = null;
            if (!check(TokKind.NEWLINE) && !check(TokKind.DEDENT) && !check(TokKind.EOF)) {
                value = parseExpression();
            }
            skipNewlines();
            return new ReturnStatement(value, location);
        }

        Statement parseExprOrAssign(SourceLocation location) {
            // Variable declaration: name: Type [ = expr ]
            if (peek().kind == TokKind.IDENT
                && pos + 1 < tokens.size()
                && tokens.get(pos + 1).kind == TokKind.COLON) {
                Token nameTok = advance();
                String varName = pyConvertName(nameTok.value);
                expect(TokKind.COLON);
                TypeNode typeNode = parseTypeAnnotation();
                Expression init;
                if (match(TokKind.ASSIGN)) {
                    init = parseExpression();
                } else {
                    init = new BigIntLiteral(BigInteger.ZERO);
                }
                skipNewlines();
                return new VariableDeclStatement(varName, typeNode, init, location);
            }

            Expression expr = parseExpression();
            if (expr == null) {
                advance();
                skipNewlines();
                return null;
            }

            // Assignment: target = value
            if (match(TokKind.ASSIGN)) {
                Expression value = parseExpression();
                skipNewlines();
                if (expr instanceof Identifier id) {
                    return new VariableDeclStatement(id.name(), null, value, location);
                }
                return new AssignmentStatement(expr, value, location);
            }

            // Compound assignments: +=, -=, *=, /= (incl. //=), %=
            Expression.BinaryOp compoundOp = null;
            TokKind compoundKind = null;
            if (check(TokKind.PLUSEQ)) { compoundOp = Expression.BinaryOp.ADD; compoundKind = TokKind.PLUSEQ; }
            else if (check(TokKind.MINUSEQ)) { compoundOp = Expression.BinaryOp.SUB; compoundKind = TokKind.MINUSEQ; }
            else if (check(TokKind.STAREQ)) { compoundOp = Expression.BinaryOp.MUL; compoundKind = TokKind.STAREQ; }
            else if (check(TokKind.SLASHEQ)) { compoundOp = Expression.BinaryOp.DIV; compoundKind = TokKind.SLASHEQ; }
            else if (check(TokKind.PERCENTEQ)) { compoundOp = Expression.BinaryOp.MOD; compoundKind = TokKind.PERCENTEQ; }
            if (compoundOp != null) {
                advance(); // consume operator
                Expression right = parseExpression();
                skipNewlines();
                Expression value = new BinaryExpr(compoundOp, expr, right);
                return new AssignmentStatement(expr, value, location);
            }

            skipNewlines();
            return new ExpressionStatement(expr, location);
        }

        // -- Expression parsing ----------------------------------------------

        Expression parseExpression() {
            return parseTernary();
        }

        Expression parseTernary() {
            Expression expr = parseOr();
            if (checkIdent("if")) {
                advance();
                Expression condition = parseOr();
                expectIdent("else");
                Expression alternate = parseTernary();
                return new TernaryExpr(condition, expr, alternate);
            }
            return expr;
        }

        Expression parseOr() {
            Expression left = parseAnd();
            while (match(TokKind.PIPEPIPE)) {
                Expression right = parseAnd();
                left = new BinaryExpr(Expression.BinaryOp.OR, left, right);
            }
            return left;
        }

        Expression parseAnd() {
            Expression left = parseNot();
            while (match(TokKind.AMPAMP)) {
                Expression right = parseNot();
                left = new BinaryExpr(Expression.BinaryOp.AND, left, right);
            }
            return left;
        }

        Expression parseNot() {
            if (match(TokKind.BANG)) {
                Expression operand = parseNot();
                return new UnaryExpr(Expression.UnaryOp.NOT, operand);
            }
            return parseBitwiseOr();
        }

        Expression parseBitwiseOr() {
            Expression left = parseBitwiseXor();
            while (match(TokKind.PIPE)) {
                Expression right = parseBitwiseXor();
                left = new BinaryExpr(Expression.BinaryOp.BIT_OR, left, right);
            }
            return left;
        }

        Expression parseBitwiseXor() {
            Expression left = parseBitwiseAnd();
            while (match(TokKind.CARET)) {
                Expression right = parseBitwiseAnd();
                left = new BinaryExpr(Expression.BinaryOp.BIT_XOR, left, right);
            }
            return left;
        }

        Expression parseBitwiseAnd() {
            Expression left = parseEquality();
            while (match(TokKind.AMP)) {
                Expression right = parseEquality();
                left = new BinaryExpr(Expression.BinaryOp.BIT_AND, left, right);
            }
            return left;
        }

        Expression parseEquality() {
            Expression left = parseComparison();
            while (true) {
                if (match(TokKind.EQEQ)) {
                    Expression right = parseComparison();
                    left = new BinaryExpr(Expression.BinaryOp.EQ, left, right);
                } else if (match(TokKind.NOTEQ)) {
                    Expression right = parseComparison();
                    left = new BinaryExpr(Expression.BinaryOp.NEQ, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseComparison() {
            Expression left = parseShift();
            while (true) {
                if (match(TokKind.LT)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.LT, left, right);
                } else if (match(TokKind.LTEQ)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.LE, left, right);
                } else if (match(TokKind.GT)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.GT, left, right);
                } else if (match(TokKind.GTEQ)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.GE, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseShift() {
            Expression left = parseAdditive();
            while (true) {
                if (match(TokKind.LSHIFT)) {
                    Expression right = parseAdditive();
                    left = new BinaryExpr(Expression.BinaryOp.SHL, left, right);
                } else if (match(TokKind.RSHIFT)) {
                    Expression right = parseAdditive();
                    left = new BinaryExpr(Expression.BinaryOp.SHR, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseAdditive() {
            Expression left = parseMultiplicative();
            while (true) {
                if (match(TokKind.PLUS)) {
                    Expression right = parseMultiplicative();
                    left = new BinaryExpr(Expression.BinaryOp.ADD, left, right);
                } else if (match(TokKind.MINUS)) {
                    Expression right = parseMultiplicative();
                    left = new BinaryExpr(Expression.BinaryOp.SUB, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseMultiplicative() {
            Expression left = parseUnary();
            while (true) {
                if (match(TokKind.STAR)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.MUL, left, right);
                } else if (match(TokKind.SLASHSLASH)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.DIV, left, right);
                } else if (match(TokKind.SLASH)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.DIV, left, right);
                } else if (match(TokKind.PERCENT)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.MOD, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseUnary() {
            if (match(TokKind.MINUS)) {
                Expression operand = parseUnary();
                return new UnaryExpr(Expression.UnaryOp.NEG, operand);
            }
            if (match(TokKind.TILDE)) {
                Expression operand = parseUnary();
                return new UnaryExpr(Expression.UnaryOp.BIT_NOT, operand);
            }
            if (match(TokKind.BANG)) {
                Expression operand = parseUnary();
                return new UnaryExpr(Expression.UnaryOp.NOT, operand);
            }
            return parsePower();
        }

        Expression parsePower() {
            Expression base = parsePostfix();
            if (match(TokKind.STARSTAR)) {
                Expression exp = parseUnary();
                return new CallExpr(new Identifier("pow"), List.of(base, exp));
            }
            return base;
        }

        Expression parsePostfix() {
            Expression expr = parsePrimary();
            while (true) {
                if (match(TokKind.DOT)) {
                    Token propTok = expect(TokKind.IDENT);
                    String propName = pyConvertName(propTok.value);
                    if (check(TokKind.LPAREN)) {
                        List<Expression> args = parseCallArgs();
                        if (expr instanceof Identifier id && id.name().equals("self")) {
                            expr = new CallExpr(
                                new MemberExpr(new Identifier("this"), propName),
                                args
                            );
                        } else {
                            expr = new CallExpr(new MemberExpr(expr, propName), args);
                        }
                    } else {
                        if (expr instanceof Identifier id && id.name().equals("self")) {
                            expr = new PropertyAccessExpr(propName);
                        } else {
                            expr = new MemberExpr(expr, propName);
                        }
                    }
                } else if (match(TokKind.LBRACKET)) {
                    Expression index = parseExpression();
                    expect(TokKind.RBRACKET);
                    expr = new IndexAccessExpr(expr, index);
                } else if (match(TokKind.LPAREN)) {
                    List<Expression> args = new ArrayList<>();
                    while (!check(TokKind.RPAREN) && !check(TokKind.EOF)) {
                        args.add(parseExpression());
                        if (!match(TokKind.COMMA)) break;
                    }
                    expect(TokKind.RPAREN);
                    expr = new CallExpr(expr, args);
                } else {
                    break;
                }
            }
            return expr;
        }

        Expression parsePrimary() {
            Token tok = peek();

            if (tok.kind == TokKind.NUMBER) {
                advance();
                return numberLiteral(tok.value);
            }

            if (tok.kind == TokKind.STRING) {
                advance();
                return new ByteStringLiteral(tok.value);
            }

            if (tok.kind == TokKind.IDENT) {
                advance();
                String name = tok.value;
                if (name.equals("True") || name.equals("true")) return new BoolLiteral(true);
                if (name.equals("False") || name.equals("false")) return new BoolLiteral(false);
                if (name.equals("None")) return new BigIntLiteral(BigInteger.ZERO);
                if (name.equals("self")) return new Identifier("self");
                if (name.equals("super")) return new Identifier("super");

                // bytes.fromhex("dead") special form
                if (name.equals("bytes") && check(TokKind.DOT)) {
                    return parseBytesMethod();
                }

                String converted = pyConvertName(name);
                if (check(TokKind.LPAREN)) {
                    List<Expression> args = parseCallArgs();
                    return new CallExpr(new Identifier(converted), args);
                }
                return new Identifier(converted);
            }

            if (tok.kind == TokKind.LPAREN) {
                advance();
                Expression e = parseExpression();
                expect(TokKind.RPAREN);
                return e;
            }

            if (tok.kind == TokKind.LBRACKET) {
                return parseArrayLiteral();
            }

            addError("line " + tok.line + ": unexpected token " + repr(tok.value));
            advance();
            return new BigIntLiteral(BigInteger.ZERO);
        }

        Expression parseBytesMethod() {
            expect(TokKind.DOT);
            Token methodTok = expect(TokKind.IDENT);
            if (methodTok.value.equals("fromhex")) {
                expect(TokKind.LPAREN);
                Token strTok = expect(TokKind.STRING);
                expect(TokKind.RPAREN);
                return new ByteStringLiteral(strTok.value);
            }
            if (check(TokKind.LPAREN)) {
                List<Expression> args = parseCallArgs();
                return new CallExpr(
                    new MemberExpr(new Identifier("bytes"), methodTok.value),
                    args
                );
            }
            return new MemberExpr(new Identifier("bytes"), methodTok.value);
        }

        Expression parseArrayLiteral() {
            expect(TokKind.LBRACKET);
            List<Expression> elements = new ArrayList<>();
            while (!check(TokKind.RBRACKET) && !check(TokKind.EOF)) {
                elements.add(parseExpression());
                if (!match(TokKind.COMMA)) break;
            }
            expect(TokKind.RBRACKET);
            return new ArrayLiteralExpr(elements);
        }

        List<Expression> parseCallArgs() {
            expect(TokKind.LPAREN);
            List<Expression> args = new ArrayList<>();
            while (!check(TokKind.RPAREN) && !check(TokKind.EOF)) {
                args.add(parseExpression());
                if (!match(TokKind.COMMA)) break;
            }
            expect(TokKind.RPAREN);
            return args;
        }
    }

    // -----------------------------------------------------------------
    // Number parsing helper
    // -----------------------------------------------------------------

    private static Expression numberLiteral(String s) {
        try {
            return new BigIntLiteral(parseBigIntFlexible(s));
        } catch (NumberFormatException e) {
            return new BigIntLiteral(BigInteger.ZERO);
        }
    }

    /** Parses 0x / 0X hex prefixes as well as plain base-10. Mirrors {@code int(s, 0)}. */
    private static BigInteger parseBigIntFlexible(String s) {
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return new BigInteger(s.substring(2), 16);
        }
        if (s.isEmpty()) return BigInteger.ZERO;
        return new BigInteger(s);
    }

    private static int parseIntFlexible(String s) {
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Integer.parseInt(s.substring(2), 16);
        }
        return Integer.parseInt(s);
    }
}
