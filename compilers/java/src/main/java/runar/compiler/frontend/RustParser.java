package runar.compiler.frontend;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * Parses {@code .runar.rs} (Rust proc-macro DSL) source into a Rúnar
 * {@link ContractNode}.
 *
 * <p>Hand-written tokenizer + recursive descent parser, ported from
 * {@code compilers/python/runar_compiler/frontend/parser_rust.py}
 * (which is itself a port of
 * {@code compilers/rust/src/frontend/parser_rustmacro.rs}).
 *
 * <p>Recognised surface:
 * <ul>
 *   <li>{@code #[runar::contract]} or {@code #[runar::stateful_contract]} on a struct</li>
 *   <li>{@code #[readonly]} on struct fields</li>
 *   <li>{@code #[public]} on impl methods</li>
 *   <li>{@code #[runar::methods(Name)]} on impl block</li>
 *   <li>Rust types lowered to Rúnar primitives ({@code i64}/{@code u64}/{@code i128} →
 *       {@code bigint}, {@code bool} → {@code boolean}, {@code FixedArray<T, N>}, etc.)</li>
 *   <li>{@code assert!(expr)} / {@code assert_eq!(a, b)} macros</li>
 *   <li>{@code let [mut] name [: type] = expr;}, {@code if}/{@code else},
 *       {@code for i in start..end}, {@code return}, member calls</li>
 *   <li>snake_case identifiers automatically rewritten to camelCase</li>
 *   <li>{@code init()} method extracted as inline property initializers</li>
 * </ul>
 */
public final class RustParser {

    private RustParser() {}

    /** Checked exception for parse failures. */
    public static final class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
    }

    // -----------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------

    /** Parse Rust DSL source into a Rúnar contract AST. */
    public static ContractNode parse(String source, String filename) throws ParseException {
        State state = new State(filename);
        state.tokens = tokenize(source);
        ContractNode contract = parseContract(state);
        if (!state.errors.isEmpty()) {
            // Report first error to mirror Python behaviour where the caller
            // surfaces diagnostics; for the Java parser surface we promote
            // any error to a ParseException.
            throw new ParseException(String.join("\n", state.errors));
        }
        return contract;
    }

    // -----------------------------------------------------------------
    // Token kinds
    // -----------------------------------------------------------------

    private static final int TOK_EOF = 0;
    private static final int TOK_IDENT = 1;
    private static final int TOK_NUMBER = 2;
    private static final int TOK_HEX_STRING = 3;
    private static final int TOK_LPAREN = 4;
    private static final int TOK_RPAREN = 5;
    private static final int TOK_LBRACE = 6;
    private static final int TOK_RBRACE = 7;
    private static final int TOK_LBRACKET = 8;
    private static final int TOK_RBRACKET = 9;
    private static final int TOK_SEMI = 10;
    private static final int TOK_COMMA = 11;
    private static final int TOK_DOT = 12;
    private static final int TOK_COLON = 13;
    private static final int TOK_COLONCOLON = 14;
    private static final int TOK_ARROW = 15;
    private static final int TOK_PLUS = 16;
    private static final int TOK_MINUS = 17;
    private static final int TOK_STAR = 18;
    private static final int TOK_SLASH = 19;
    private static final int TOK_PERCENT = 20;
    private static final int TOK_EQEQ = 21;
    private static final int TOK_BANGEQ = 22;
    private static final int TOK_LT = 23;
    private static final int TOK_LTEQ = 24;
    private static final int TOK_GT = 25;
    private static final int TOK_GTEQ = 26;
    private static final int TOK_AMPAMP = 27;
    private static final int TOK_PIPEPIPE = 28;
    private static final int TOK_AMP = 29;
    private static final int TOK_PIPE = 30;
    private static final int TOK_CARET = 31;
    private static final int TOK_TILDE = 32;
    private static final int TOK_BANG = 33;
    private static final int TOK_EQ = 34;
    private static final int TOK_PLUSEQ = 35;
    private static final int TOK_MINUSEQ = 36;
    private static final int TOK_HASH_BRACKET = 37;
    // Keywords
    private static final int TOK_USE = 50;
    private static final int TOK_STRUCT = 51;
    private static final int TOK_IMPL = 52;
    private static final int TOK_FN = 53;
    private static final int TOK_PUB = 54;
    private static final int TOK_LET = 55;
    private static final int TOK_MUT = 56;
    private static final int TOK_IF = 57;
    private static final int TOK_ELSE = 58;
    private static final int TOK_FOR = 59;
    private static final int TOK_RETURN = 60;
    private static final int TOK_IN = 61;
    private static final int TOK_TRUE = 62;
    private static final int TOK_FALSE = 63;
    private static final int TOK_SELF = 64;
    private static final int TOK_ASSERT_MACRO = 65;
    private static final int TOK_ASSERT_EQ_MACRO = 66;
    private static final int TOK_LSHIFT = 67;
    private static final int TOK_RSHIFT = 68;
    private static final int TOK_DOTDOT = 69;

    private static final Map<String, Integer> KEYWORDS = new HashMap<>();
    static {
        KEYWORDS.put("use", TOK_USE);
        KEYWORDS.put("struct", TOK_STRUCT);
        KEYWORDS.put("impl", TOK_IMPL);
        KEYWORDS.put("fn", TOK_FN);
        KEYWORDS.put("pub", TOK_PUB);
        KEYWORDS.put("let", TOK_LET);
        KEYWORDS.put("mut", TOK_MUT);
        KEYWORDS.put("if", TOK_IF);
        KEYWORDS.put("else", TOK_ELSE);
        KEYWORDS.put("for", TOK_FOR);
        KEYWORDS.put("return", TOK_RETURN);
        KEYWORDS.put("in", TOK_IN);
        KEYWORDS.put("true", TOK_TRUE);
        KEYWORDS.put("false", TOK_FALSE);
        KEYWORDS.put("self", TOK_SELF);
    }

    private static final class Token {
        final int kind;
        final String value;
        final int line;
        final int col;

        Token(int kind, String value, int line, int col) {
            this.kind = kind;
            this.value = value;
            this.line = line;
            this.col = col;
        }
    }

    // -----------------------------------------------------------------
    // Name conversion: snake_case -> camelCase + builtin remapping
    // -----------------------------------------------------------------

    private static final Map<String, String> SPECIAL_BUILTINS = new HashMap<>();
    static {
        SPECIAL_BUILTINS.put("bool_cast", "bool");
        SPECIAL_BUILTINS.put("verify_wots", "verifyWOTS");
        SPECIAL_BUILTINS.put("verify_slh_dsa_sha2_128s", "verifySLHDSA_SHA2_128s");
        SPECIAL_BUILTINS.put("verify_slh_dsa_sha2_128f", "verifySLHDSA_SHA2_128f");
        SPECIAL_BUILTINS.put("verify_slh_dsa_sha2_192s", "verifySLHDSA_SHA2_192s");
        SPECIAL_BUILTINS.put("verify_slh_dsa_sha2_192f", "verifySLHDSA_SHA2_192f");
        SPECIAL_BUILTINS.put("verify_slh_dsa_sha2_256s", "verifySLHDSA_SHA2_256s");
        SPECIAL_BUILTINS.put("verify_slh_dsa_sha2_256f", "verifySLHDSA_SHA2_256f");
        SPECIAL_BUILTINS.put("bin_2_num", "bin2num");
        SPECIAL_BUILTINS.put("int_2_str", "int2str");
        SPECIAL_BUILTINS.put("to_byte_string", "toByteString");
        // P-256
        SPECIAL_BUILTINS.put("p256_add", "p256Add");
        SPECIAL_BUILTINS.put("p256_mul", "p256Mul");
        SPECIAL_BUILTINS.put("p256_mul_gen", "p256MulGen");
        SPECIAL_BUILTINS.put("p256_negate", "p256Negate");
        SPECIAL_BUILTINS.put("p256_on_curve", "p256OnCurve");
        SPECIAL_BUILTINS.put("p256_encode_compressed", "p256EncodeCompressed");
        SPECIAL_BUILTINS.put("verify_ecdsa_p256", "verifyECDSA_P256");
        // P-384
        SPECIAL_BUILTINS.put("p384_add", "p384Add");
        SPECIAL_BUILTINS.put("p384_mul", "p384Mul");
        SPECIAL_BUILTINS.put("p384_mul_gen", "p384MulGen");
        SPECIAL_BUILTINS.put("p384_negate", "p384Negate");
        SPECIAL_BUILTINS.put("p384_on_curve", "p384OnCurve");
        SPECIAL_BUILTINS.put("p384_encode_compressed", "p384EncodeCompressed");
        SPECIAL_BUILTINS.put("verify_ecdsa_p384", "verifyECDSA_P384");
    }

    private static String snakeToCamel(String name) {
        String[] parts = name.split("_", -1);
        if (parts.length <= 1) return name;
        StringBuilder sb = new StringBuilder(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            if (part.isEmpty()) continue;
            sb.append(Character.toUpperCase(part.charAt(0)));
            if (part.length() > 1) sb.append(part.substring(1));
        }
        return sb.toString();
    }

    private static String mapBuiltinName(String name) {
        String special = SPECIAL_BUILTINS.get(name);
        if (special != null) return special;
        return snakeToCamel(name);
    }

    // -----------------------------------------------------------------
    // Type mapping
    // -----------------------------------------------------------------

    private static final Map<String, String> TYPE_MAP = new HashMap<>();
    static {
        TYPE_MAP.put("Bigint", "bigint");
        TYPE_MAP.put("Int", "bigint");
        TYPE_MAP.put("i64", "bigint");
        TYPE_MAP.put("u64", "bigint");
        TYPE_MAP.put("i128", "bigint");
        TYPE_MAP.put("u128", "bigint");
        TYPE_MAP.put("bigint", "bigint");
        TYPE_MAP.put("Bool", "boolean");
        TYPE_MAP.put("bool", "boolean");
        TYPE_MAP.put("boolean", "boolean");
        TYPE_MAP.put("ByteString", "ByteString");
        TYPE_MAP.put("PubKey", "PubKey");
        TYPE_MAP.put("Sig", "Sig");
        TYPE_MAP.put("Sha256", "Sha256");
        TYPE_MAP.put("Sha256Digest", "Sha256");
        TYPE_MAP.put("Ripemd160", "Ripemd160");
        TYPE_MAP.put("Addr", "Addr");
        TYPE_MAP.put("SigHashPreimage", "SigHashPreimage");
        TYPE_MAP.put("RabinSig", "RabinSig");
        TYPE_MAP.put("RabinPubKey", "RabinPubKey");
        TYPE_MAP.put("Point", "Point");
        TYPE_MAP.put("P256Point", "P256Point");
        TYPE_MAP.put("P384Point", "P384Point");
    }

    private static final Set<String> PRIMITIVE_NAMES = new HashSet<>();
    static {
        for (PrimitiveTypeName p : PrimitiveTypeName.values()) {
            PRIMITIVE_NAMES.add(p.canonical());
        }
    }

    private static String mapRustType(String name) {
        String mapped = TYPE_MAP.get(name);
        return mapped != null ? mapped : name;
    }

    private static TypeNode parseTypeName(String name) {
        String mapped = mapRustType(name);
        if (PRIMITIVE_NAMES.contains(mapped)) {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(mapped));
        }
        return new CustomType(mapped);
    }

    // -----------------------------------------------------------------
    // Tokenizer
    // -----------------------------------------------------------------

    private static boolean isHexDigit(char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    }

    private static List<Token> tokenize(String source) {
        List<Token> tokens = new ArrayList<>();
        int n = source.length();
        int pos = 0;
        int line = 1;
        int col = 1;

        while (pos < n) {
            char ch = source.charAt(pos);

            // Whitespace
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                if (ch == '\n') {
                    line++;
                    col = 1;
                } else {
                    col++;
                }
                pos++;
                continue;
            }

            // Line comments
            if (ch == '/' && pos + 1 < n && source.charAt(pos + 1) == '/') {
                while (pos < n && source.charAt(pos) != '\n') {
                    pos++;
                }
                continue;
            }

            // Block comments
            if (ch == '/' && pos + 1 < n && source.charAt(pos + 1) == '*') {
                pos += 2;
                col += 2;
                while (pos + 1 < n) {
                    if (source.charAt(pos) == '\n') {
                        line++;
                        col = 1;
                    }
                    if (source.charAt(pos) == '*' && source.charAt(pos + 1) == '/') {
                        pos += 2;
                        col += 2;
                        break;
                    }
                    pos++;
                    col++;
                }
                continue;
            }

            int startLine = line;
            int startCol = col;

            // #[ attribute opener
            if (ch == '#' && pos + 1 < n && source.charAt(pos + 1) == '[') {
                tokens.add(new Token(TOK_HASH_BRACKET, "#[", startLine, startCol));
                pos += 2;
                col += 2;
                continue;
            }

            // Two-character operators
            if (pos + 1 < n) {
                String two = source.substring(pos, pos + 2);
                int twoKind = -1;
                switch (two) {
                    case "::": twoKind = TOK_COLONCOLON; break;
                    case "->": twoKind = TOK_ARROW; break;
                    case "==": twoKind = TOK_EQEQ; break;
                    case "!=": twoKind = TOK_BANGEQ; break;
                    case "<=": twoKind = TOK_LTEQ; break;
                    case ">=": twoKind = TOK_GTEQ; break;
                    case "&&": twoKind = TOK_AMPAMP; break;
                    case "||": twoKind = TOK_PIPEPIPE; break;
                    case "+=": twoKind = TOK_PLUSEQ; break;
                    case "-=": twoKind = TOK_MINUSEQ; break;
                    case "<<": twoKind = TOK_LSHIFT; break;
                    case ">>": twoKind = TOK_RSHIFT; break;
                    case "..": twoKind = TOK_DOTDOT; break;
                    default: break;
                }
                if (twoKind >= 0) {
                    tokens.add(new Token(twoKind, two, startLine, startCol));
                    pos += 2;
                    col += 2;
                    continue;
                }
            }

            // Single-character tokens
            int singleKind = singleCharKind(ch);
            if (singleKind >= 0) {
                tokens.add(new Token(singleKind, String.valueOf(ch), startLine, startCol));
                pos++;
                col++;
                continue;
            }

            // Hex literal
            if (ch == '0' && pos + 1 < n && (source.charAt(pos + 1) == 'x' || source.charAt(pos + 1) == 'X')) {
                pos += 2;
                col += 2;
                int start = pos;
                while (pos < n && isHexDigit(source.charAt(pos))) {
                    pos++;
                    col++;
                }
                String val = source.substring(start, pos);
                tokens.add(new Token(TOK_HEX_STRING, val, startLine, startCol));
                continue;
            }

            // Double-quoted string -> hex bytestring
            if (ch == '"') {
                pos++;
                col++;
                int start = pos;
                while (pos < n && source.charAt(pos) != '"') {
                    if (source.charAt(pos) == '\n') {
                        line++;
                        col = 1;
                    } else {
                        col++;
                    }
                    pos++;
                }
                String val = source.substring(start, Math.min(pos, n));
                if (pos < n) {
                    pos++;
                    col++;
                }
                tokens.add(new Token(TOK_HEX_STRING, val, startLine, startCol));
                continue;
            }

            // Number
            if (ch >= '0' && ch <= '9') {
                int start = pos;
                while (pos < n) {
                    char d = source.charAt(pos);
                    if ((d >= '0' && d <= '9') || d == '_') {
                        pos++;
                        col++;
                    } else {
                        break;
                    }
                }
                String val = source.substring(start, pos).replace("_", "");
                tokens.add(new Token(TOK_NUMBER, val, startLine, startCol));
                continue;
            }

            // Identifier / keyword
            if (Character.isLetter(ch) || ch == '_') {
                int start = pos;
                while (pos < n) {
                    char d = source.charAt(pos);
                    if (Character.isLetterOrDigit(d) || d == '_') {
                        pos++;
                        col++;
                    } else {
                        break;
                    }
                }
                String word = source.substring(start, pos);

                // assert!/assert_eq!
                if ((word.equals("assert") || word.equals("assert_eq")) && pos < n && source.charAt(pos) == '!') {
                    pos++;
                    col++;
                    if (word.equals("assert")) {
                        tokens.add(new Token(TOK_ASSERT_MACRO, "assert!", startLine, startCol));
                    } else {
                        tokens.add(new Token(TOK_ASSERT_EQ_MACRO, "assert_eq!", startLine, startCol));
                    }
                    continue;
                }

                Integer kw = KEYWORDS.get(word);
                if (kw != null) {
                    tokens.add(new Token(kw, word, startLine, startCol));
                } else {
                    tokens.add(new Token(TOK_IDENT, word, startLine, startCol));
                }
                continue;
            }

            // Unknown char — skip
            pos++;
            col++;
        }

        tokens.add(new Token(TOK_EOF, "", line, col));
        return tokens;
    }

    private static int singleCharKind(char ch) {
        switch (ch) {
            case '(': return TOK_LPAREN;
            case ')': return TOK_RPAREN;
            case '{': return TOK_LBRACE;
            case '}': return TOK_RBRACE;
            case '[': return TOK_LBRACKET;
            case ']': return TOK_RBRACKET;
            case ';': return TOK_SEMI;
            case ',': return TOK_COMMA;
            case '.': return TOK_DOT;
            case ':': return TOK_COLON;
            case '+': return TOK_PLUS;
            case '-': return TOK_MINUS;
            case '*': return TOK_STAR;
            case '/': return TOK_SLASH;
            case '%': return TOK_PERCENT;
            case '<': return TOK_LT;
            case '>': return TOK_GT;
            case '&': return TOK_AMP;
            case '|': return TOK_PIPE;
            case '^': return TOK_CARET;
            case '~': return TOK_TILDE;
            case '!': return TOK_BANG;
            case '=': return TOK_EQ;
            default: return -1;
        }
    }

    // -----------------------------------------------------------------
    // Parser state
    // -----------------------------------------------------------------

    private static final class State {
        final String filename;
        List<Token> tokens = new ArrayList<>();
        int pos = 0;
        final List<String> errors = new ArrayList<>();

        State(String filename) {
            this.filename = filename;
        }

        Token peek() {
            if (pos < tokens.size()) return tokens.get(pos);
            return tokens.isEmpty()
                ? new Token(TOK_EOF, "", 0, 0)
                : tokens.get(tokens.size() - 1);
        }

        Token advance() {
            Token tok = peek();
            if (pos < tokens.size() - 1) pos++;
            return tok;
        }

        boolean check(int kind) {
            return peek().kind == kind;
        }

        boolean matchTok(int kind) {
            if (check(kind)) {
                advance();
                return true;
            }
            return false;
        }

        Token expect(int kind) {
            Token tok = peek();
            if (tok.kind != kind) {
                addError("line " + tok.line + ":" + tok.col
                    + ": expected token kind " + kind + ", got " + tok.kind
                    + " (\"" + tok.value + "\")");
            }
            return advance();
        }

        void addError(String msg) {
            errors.add(msg);
        }

        SourceLocation loc() {
            Token tok = peek();
            return new SourceLocation(filename, tok.line, tok.col);
        }
    }

    // -----------------------------------------------------------------
    // Attribute parsing
    // -----------------------------------------------------------------

    /** Parse {@code #[...]}. The {@code #[} token is the current peek. */
    private static String parseAttribute(State s) {
        s.advance(); // consume #[
        StringBuilder attr = new StringBuilder();
        int depth = 1;
        while (depth > 0 && !s.check(TOK_EOF)) {
            Token tok = s.peek();
            if (tok.kind == TOK_LBRACKET) {
                depth++;
                s.advance();
            } else if (tok.kind == TOK_RBRACKET) {
                depth--;
                if (depth == 0) {
                    s.advance();
                    break;
                }
                s.advance();
            } else if (tok.kind == TOK_IDENT) {
                attr.append(tok.value);
                s.advance();
            } else if (tok.kind == TOK_COLONCOLON) {
                attr.append("::");
                s.advance();
            } else if (tok.kind == TOK_LPAREN) {
                attr.append('(');
                s.advance();
            } else if (tok.kind == TOK_RPAREN) {
                attr.append(')');
                s.advance();
            } else {
                s.advance();
            }
        }
        return attr.toString();
    }

    // -----------------------------------------------------------------
    // Type parsing
    // -----------------------------------------------------------------

    private static TypeNode parseRustType(State s) {
        Token tok = s.peek();
        if (tok.kind == TOK_IDENT) {
            String name = tok.value;
            s.advance();

            // FixedArray<T, N>
            if (name.equals("FixedArray") && s.check(TOK_LT)) {
                s.advance(); // <
                TypeNode element = parseRustType(s);
                s.expect(TOK_COMMA);
                Token sizeTok = s.expect(TOK_NUMBER);
                int size;
                try {
                    size = Integer.parseInt(sizeTok.value);
                } catch (NumberFormatException nfe) {
                    size = 0;
                    s.addError("line " + sizeTok.line + ": FixedArray size must be integer");
                }
                s.expect(TOK_GT);
                return new FixedArrayType(element, size);
            }

            // Skip generic parameters (e.g., Vec<u8>)
            if (s.check(TOK_LT)) {
                s.advance();
                int depth = 1;
                while (depth > 0 && !s.check(TOK_EOF)) {
                    if (s.check(TOK_LT)) {
                        depth++;
                    } else if (s.check(TOK_GT)) {
                        depth--;
                        if (depth == 0) {
                            s.advance();
                            break;
                        }
                    }
                    s.advance();
                }
            }
            return parseTypeName(name);
        }

        s.advance();
        return new CustomType("unknown");
    }

    // -----------------------------------------------------------------
    // Top-level / contract parsing
    // -----------------------------------------------------------------

    private static ContractNode parseContract(State s) {
        // Skip use declarations
        while (s.check(TOK_USE)) {
            while (!s.check(TOK_SEMI) && !s.check(TOK_EOF)) {
                s.advance();
            }
            if (s.check(TOK_SEMI)) s.advance();
        }

        List<PropertyNode> properties = new ArrayList<>();
        String contractName = "";
        ParentClass parentClass = ParentClass.SMART_CONTRACT;
        List<MethodNode> methods = new ArrayList<>();

        while (!s.check(TOK_EOF)) {
            if (s.check(TOK_HASH_BRACKET)) {
                String attr = parseAttribute(s);

                if (attr.equals("runar::contract") || attr.equals("runar::stateful_contract")) {
                    if (attr.equals("runar::stateful_contract")) {
                        parentClass = ParentClass.STATEFUL_SMART_CONTRACT;
                    }

                    // Parse struct
                    if (s.check(TOK_PUB)) s.advance();
                    s.expect(TOK_STRUCT);

                    Token nameTok = s.peek();
                    if (nameTok.kind == TOK_IDENT) {
                        contractName = nameTok.value;
                        s.advance();
                    }

                    s.expect(TOK_LBRACE);

                    while (!s.check(TOK_RBRACE) && !s.check(TOK_EOF)) {
                        boolean readonly = false;
                        if (s.check(TOK_HASH_BRACKET)) {
                            String fieldAttr = parseAttribute(s);
                            if (fieldAttr.equals("readonly")) {
                                readonly = true;
                            }
                        }

                        if (s.check(TOK_PUB)) s.advance();

                        SourceLocation fieldLoc = s.loc();
                        Token fieldTok = s.peek();
                        if (fieldTok.kind == TOK_IDENT) {
                            String fieldName = fieldTok.value;
                            s.advance();
                            s.expect(TOK_COLON);
                            TypeNode fieldType = parseRustType(s);
                            s.matchTok(TOK_COMMA);

                            String camelName = snakeToCamel(fieldName);
                            // Skip txPreimage — implicit stateful param
                            if (!camelName.equals("txPreimage")) {
                                properties.add(new PropertyNode(
                                    camelName,
                                    fieldType,
                                    readonly,
                                    null,
                                    fieldLoc,
                                    null
                                ));
                            }
                        } else {
                            s.advance();
                        }
                    }

                    s.expect(TOK_RBRACE);
                } else if (attr.startsWith("runar::methods")) {
                    if (s.check(TOK_IMPL)) s.advance();
                    if (s.peek().kind == TOK_IDENT) s.advance();
                    s.expect(TOK_LBRACE);

                    while (!s.check(TOK_RBRACE) && !s.check(TOK_EOF)) {
                        Visibility visibility = Visibility.PRIVATE;
                        if (s.check(TOK_HASH_BRACKET)) {
                            String methodAttr = parseAttribute(s);
                            if (methodAttr.equals("public")) {
                                visibility = Visibility.PUBLIC;
                            }
                        }
                        if (s.check(TOK_PUB)) {
                            s.advance();
                            visibility = Visibility.PUBLIC;
                        }
                        methods.add(parseFunction(s, visibility));
                    }

                    s.expect(TOK_RBRACE);
                } else {
                    // Unknown attribute — discard
                }
            } else {
                s.advance();
            }
        }

        // Promote to stateful if any property is mutable.
        boolean anyMutable = false;
        for (PropertyNode p : properties) {
            if (!p.readonly()) {
                anyMutable = true;
                break;
            }
        }
        if (anyMutable) parentClass = ParentClass.STATEFUL_SMART_CONTRACT;

        if (contractName.isEmpty()) {
            s.addError("No Runar contract struct found");
            SourceLocation loc = new SourceLocation(s.filename, 1, 1);
            return new ContractNode(
                "",
                parentClass,
                properties,
                new MethodNode("constructor", List.of(), List.of(), Visibility.PUBLIC, loc),
                methods,
                s.filename
            );
        }

        // Extract init() method as inline property initializers.
        List<MethodNode> finalMethods = new ArrayList<>(methods.size());
        Map<String, Expression> initOverrides = new HashMap<>();
        for (MethodNode m : methods) {
            if (m.name().equals("init") && m.params().isEmpty()) {
                for (Statement stmt : m.body()) {
                    if (stmt instanceof AssignmentStatement as
                        && as.target() instanceof PropertyAccessExpr pa) {
                        initOverrides.put(pa.property(), as.value());
                    }
                }
            } else {
                finalMethods.add(m);
            }
        }

        if (!initOverrides.isEmpty()) {
            List<PropertyNode> updated = new ArrayList<>(properties.size());
            for (PropertyNode p : properties) {
                Expression init = initOverrides.get(p.name());
                if (init != null) {
                    updated.add(new PropertyNode(
                        p.name(), p.type(), p.readonly(), init,
                        p.sourceLocation(), p.syntheticArrayChain()
                    ));
                } else {
                    updated.add(p);
                }
            }
            properties = updated;
        }
        methods = finalMethods;

        // Build auto-generated constructor (only properties without initializers).
        SourceLocation ctorLoc = new SourceLocation(s.filename, 1, 1);
        List<PropertyNode> uninit = new ArrayList<>();
        for (PropertyNode p : properties) {
            if (p.initializer() == null) uninit.add(p);
        }

        List<Expression> superArgs = new ArrayList<>(uninit.size());
        for (PropertyNode p : uninit) {
            superArgs.add(new Identifier(p.name()));
        }
        List<Statement> ctorBody = new ArrayList<>();
        ctorBody.add(new ExpressionStatement(
            new CallExpr(new Identifier("super"), superArgs),
            ctorLoc
        ));
        for (PropertyNode p : uninit) {
            ctorBody.add(new AssignmentStatement(
                new PropertyAccessExpr(p.name()),
                new Identifier(p.name()),
                ctorLoc
            ));
        }
        List<ParamNode> ctorParams = new ArrayList<>(uninit.size());
        for (PropertyNode p : uninit) {
            ctorParams.add(new ParamNode(p.name(), p.type()));
        }
        MethodNode constructor = new MethodNode(
            "constructor", ctorParams, ctorBody, Visibility.PUBLIC, ctorLoc
        );

        return new ContractNode(
            contractName, parentClass, properties, constructor, methods, s.filename
        );
    }

    // -----------------------------------------------------------------
    // Function parsing
    // -----------------------------------------------------------------

    private static MethodNode parseFunction(State s, Visibility visibility) {
        SourceLocation funcLoc = s.loc();
        s.expect(TOK_FN);

        String rawName = "unknown";
        if (s.peek().kind == TOK_IDENT) {
            rawName = s.peek().value;
            s.advance();
        } else {
            s.advance();
        }
        String name = snakeToCamel(rawName);

        s.expect(TOK_LPAREN);
        List<ParamNode> params = new ArrayList<>();

        while (!s.check(TOK_RPAREN) && !s.check(TOK_EOF)) {
            // &self / &mut self
            if (s.check(TOK_AMP)) {
                s.advance();
                if (s.check(TOK_MUT)) s.advance();
                if (s.check(TOK_SELF)) {
                    s.advance();
                    s.matchTok(TOK_COMMA);
                    continue;
                }
            }
            if (s.check(TOK_SELF)) {
                s.advance();
                s.matchTok(TOK_COMMA);
                continue;
            }

            Token paramTok = s.peek();
            if (paramTok.kind == TOK_IDENT) {
                String paramName = paramTok.value;
                s.advance();
                s.expect(TOK_COLON);
                if (s.check(TOK_AMP)) {
                    s.advance();
                    if (s.check(TOK_MUT)) s.advance();
                }
                TypeNode paramType = parseRustType(s);
                params.add(new ParamNode(snakeToCamel(paramName), paramType));
            } else {
                s.advance();
            }
            s.matchTok(TOK_COMMA);
        }

        s.expect(TOK_RPAREN);

        boolean hasReturnType = false;
        if (s.check(TOK_ARROW)) {
            hasReturnType = true;
            s.advance();
            parseRustType(s);
        }

        s.expect(TOK_LBRACE);
        List<Statement> body = new ArrayList<>();
        while (!s.check(TOK_RBRACE) && !s.check(TOK_EOF)) {
            Statement stmt = parseStatement(s);
            if (stmt != null) body.add(stmt);
        }
        s.expect(TOK_RBRACE);

        // Rust implicit return: convert last ExpressionStatement to ReturnStatement
        if (hasReturnType && !body.isEmpty()) {
            Statement last = body.get(body.size() - 1);
            if (last instanceof ExpressionStatement es) {
                body.set(body.size() - 1,
                    new ReturnStatement(es.expression(), es.sourceLocation()));
            }
        }

        return new MethodNode(name, params, body, visibility, funcLoc);
    }

    // -----------------------------------------------------------------
    // Statement parsing
    // -----------------------------------------------------------------

    private static Statement parseStatement(State s) {
        SourceLocation stmtLoc = s.loc();

        // assert!(expr)
        if (s.check(TOK_ASSERT_MACRO)) {
            s.advance();
            s.expect(TOK_LPAREN);
            Expression expr = parseExpression(s);
            s.expect(TOK_RPAREN);
            s.matchTok(TOK_SEMI);
            return new ExpressionStatement(
                new CallExpr(new Identifier("assert"), List.of(expr)),
                stmtLoc
            );
        }

        // assert_eq!(a, b) -> assert(a === b)
        if (s.check(TOK_ASSERT_EQ_MACRO)) {
            s.advance();
            s.expect(TOK_LPAREN);
            Expression left = parseExpression(s);
            s.expect(TOK_COMMA);
            Expression right = parseExpression(s);
            s.expect(TOK_RPAREN);
            s.matchTok(TOK_SEMI);
            return new ExpressionStatement(
                new CallExpr(new Identifier("assert"),
                    List.of(new BinaryExpr(Expression.BinaryOp.EQ, left, right))),
                stmtLoc
            );
        }

        // let [mut] name [: type] = expr;
        if (s.check(TOK_LET)) {
            s.advance();
            s.matchTok(TOK_MUT); // mutability flag — Rúnar AST has no field for this; the
                                  // ast PropertyNode tracks readonliness, but VariableDeclStatement
                                  // has no `mutable` slot, matching JavaParser behaviour.

            String varName = "unknown";
            if (s.peek().kind == TOK_IDENT) {
                varName = snakeToCamel(s.peek().value);
                s.advance();
            } else {
                s.advance();
            }

            TypeNode varType = null;
            if (s.check(TOK_COLON)) {
                s.advance();
                if (s.check(TOK_AMP)) s.advance();
                if (s.check(TOK_MUT)) s.advance();
                varType = parseRustType(s);
            }

            s.expect(TOK_EQ);
            Expression init = parseExpression(s);
            s.matchTok(TOK_SEMI);
            return new VariableDeclStatement(varName, varType, init, stmtLoc);
        }

        // if
        if (s.check(TOK_IF)) {
            s.advance();
            Expression cond = parseExpression(s);
            s.expect(TOK_LBRACE);
            List<Statement> thenBlock = new ArrayList<>();
            while (!s.check(TOK_RBRACE) && !s.check(TOK_EOF)) {
                Statement stmt = parseStatement(s);
                if (stmt != null) thenBlock.add(stmt);
            }
            s.expect(TOK_RBRACE);

            List<Statement> elseBlock = null;
            if (s.check(TOK_ELSE)) {
                s.advance();
                if (s.check(TOK_IF)) {
                    Statement nested = parseStatement(s);
                    elseBlock = new ArrayList<>();
                    if (nested != null) elseBlock.add(nested);
                } else {
                    s.expect(TOK_LBRACE);
                    elseBlock = new ArrayList<>();
                    while (!s.check(TOK_RBRACE) && !s.check(TOK_EOF)) {
                        Statement stmt = parseStatement(s);
                        if (stmt != null) elseBlock.add(stmt);
                    }
                    s.expect(TOK_RBRACE);
                }
            }
            return new IfStatement(cond, thenBlock, elseBlock, stmtLoc);
        }

        // for var in start..end { ... }
        if (s.check(TOK_FOR)) {
            s.advance();
            String varName = "i";
            if (s.peek().kind == TOK_IDENT) {
                varName = snakeToCamel(s.peek().value);
                s.advance();
            }

            s.expect(TOK_IN);
            Expression startExpr = parseExpression(s);
            s.expect(TOK_DOTDOT);
            Expression endExpr = parseExpression(s);

            s.expect(TOK_LBRACE);
            List<Statement> loopBody = new ArrayList<>();
            while (!s.check(TOK_RBRACE) && !s.check(TOK_EOF)) {
                Statement stmt = parseStatement(s);
                if (stmt != null) loopBody.add(stmt);
            }
            s.expect(TOK_RBRACE);

            VariableDeclStatement initStmt = new VariableDeclStatement(
                varName,
                new PrimitiveType(PrimitiveTypeName.BIGINT),
                startExpr,
                stmtLoc
            );
            Expression loopCondition = new BinaryExpr(
                Expression.BinaryOp.LT,
                new Identifier(varName),
                endExpr
            );
            ExpressionStatement update = new ExpressionStatement(
                new IncrementExpr(new Identifier(varName), false),
                stmtLoc
            );

            return new ForStatement(initStmt, loopCondition, update, loopBody, stmtLoc);
        }

        // return [value];
        if (s.check(TOK_RETURN)) {
            s.advance();
            Expression value = null;
            if (!s.check(TOK_SEMI) && !s.check(TOK_RBRACE)) {
                value = parseExpression(s);
            }
            s.matchTok(TOK_SEMI);
            return new ReturnStatement(value, stmtLoc);
        }

        // Expression / assignment statement
        Expression expr = parseExpression(s);

        if (s.check(TOK_EQ)) {
            s.advance();
            Expression value = parseExpression(s);
            s.matchTok(TOK_SEMI);
            Expression target = convertSelfAccess(expr);
            return new AssignmentStatement(target, value, stmtLoc);
        }

        if (s.check(TOK_PLUSEQ)) {
            s.advance();
            Expression rhs = parseExpression(s);
            s.matchTok(TOK_SEMI);
            Expression target = convertSelfAccess(expr);
            return new AssignmentStatement(
                target,
                new BinaryExpr(Expression.BinaryOp.ADD, target, rhs),
                stmtLoc
            );
        }

        if (s.check(TOK_MINUSEQ)) {
            s.advance();
            Expression rhs = parseExpression(s);
            s.matchTok(TOK_SEMI);
            Expression target = convertSelfAccess(expr);
            return new AssignmentStatement(
                target,
                new BinaryExpr(Expression.BinaryOp.SUB, target, rhs),
                stmtLoc
            );
        }

        s.matchTok(TOK_SEMI);
        return new ExpressionStatement(expr, stmtLoc);
    }

    private static Expression convertSelfAccess(Expression expr) {
        if (expr instanceof MemberExpr m
            && m.object() instanceof Identifier id
            && id.name().equals("self")) {
            return new PropertyAccessExpr(snakeToCamel(m.property()));
        }
        return expr;
    }

    // -----------------------------------------------------------------
    // Expression parsing (precedence climbing)
    // -----------------------------------------------------------------

    private static Expression parseExpression(State s) {
        return parseOr(s);
    }

    private static Expression parseOr(State s) {
        Expression left = parseAnd(s);
        while (s.matchTok(TOK_PIPEPIPE)) {
            Expression right = parseAnd(s);
            left = new BinaryExpr(Expression.BinaryOp.OR, left, right);
        }
        return left;
    }

    private static Expression parseAnd(State s) {
        Expression left = parseBitOr(s);
        while (s.matchTok(TOK_AMPAMP)) {
            Expression right = parseBitOr(s);
            left = new BinaryExpr(Expression.BinaryOp.AND, left, right);
        }
        return left;
    }

    private static Expression parseBitOr(State s) {
        Expression left = parseBitXor(s);
        while (s.matchTok(TOK_PIPE)) {
            Expression right = parseBitXor(s);
            left = new BinaryExpr(Expression.BinaryOp.BIT_OR, left, right);
        }
        return left;
    }

    private static Expression parseBitXor(State s) {
        Expression left = parseBitAnd(s);
        while (s.matchTok(TOK_CARET)) {
            Expression right = parseBitAnd(s);
            left = new BinaryExpr(Expression.BinaryOp.BIT_XOR, left, right);
        }
        return left;
    }

    private static Expression parseBitAnd(State s) {
        Expression left = parseEquality(s);
        while (s.matchTok(TOK_AMP)) {
            Expression right = parseEquality(s);
            left = new BinaryExpr(Expression.BinaryOp.BIT_AND, left, right);
        }
        return left;
    }

    private static Expression parseEquality(State s) {
        Expression left = parseComparison(s);
        while (true) {
            if (s.matchTok(TOK_EQEQ)) {
                Expression right = parseComparison(s);
                left = new BinaryExpr(Expression.BinaryOp.EQ, left, right);
            } else if (s.matchTok(TOK_BANGEQ)) {
                Expression right = parseComparison(s);
                left = new BinaryExpr(Expression.BinaryOp.NEQ, left, right);
            } else {
                break;
            }
        }
        return left;
    }

    private static Expression parseComparison(State s) {
        Expression left = parseShift(s);
        while (true) {
            if (s.matchTok(TOK_LT)) {
                Expression right = parseShift(s);
                left = new BinaryExpr(Expression.BinaryOp.LT, left, right);
            } else if (s.matchTok(TOK_LTEQ)) {
                Expression right = parseShift(s);
                left = new BinaryExpr(Expression.BinaryOp.LE, left, right);
            } else if (s.matchTok(TOK_GT)) {
                Expression right = parseShift(s);
                left = new BinaryExpr(Expression.BinaryOp.GT, left, right);
            } else if (s.matchTok(TOK_GTEQ)) {
                Expression right = parseShift(s);
                left = new BinaryExpr(Expression.BinaryOp.GE, left, right);
            } else {
                break;
            }
        }
        return left;
    }

    private static Expression parseShift(State s) {
        Expression left = parseAddSub(s);
        while (true) {
            if (s.matchTok(TOK_LSHIFT)) {
                Expression right = parseAddSub(s);
                left = new BinaryExpr(Expression.BinaryOp.SHL, left, right);
            } else if (s.matchTok(TOK_RSHIFT)) {
                Expression right = parseAddSub(s);
                left = new BinaryExpr(Expression.BinaryOp.SHR, left, right);
            } else {
                break;
            }
        }
        return left;
    }

    private static Expression parseAddSub(State s) {
        Expression left = parseMulDiv(s);
        while (true) {
            if (s.matchTok(TOK_PLUS)) {
                Expression right = parseMulDiv(s);
                left = new BinaryExpr(Expression.BinaryOp.ADD, left, right);
            } else if (s.matchTok(TOK_MINUS)) {
                Expression right = parseMulDiv(s);
                left = new BinaryExpr(Expression.BinaryOp.SUB, left, right);
            } else {
                break;
            }
        }
        return left;
    }

    private static Expression parseMulDiv(State s) {
        Expression left = parseUnary(s);
        while (true) {
            if (s.matchTok(TOK_STAR)) {
                Expression right = parseUnary(s);
                left = new BinaryExpr(Expression.BinaryOp.MUL, left, right);
            } else if (s.matchTok(TOK_SLASH)) {
                Expression right = parseUnary(s);
                left = new BinaryExpr(Expression.BinaryOp.DIV, left, right);
            } else if (s.matchTok(TOK_PERCENT)) {
                Expression right = parseUnary(s);
                left = new BinaryExpr(Expression.BinaryOp.MOD, left, right);
            } else {
                break;
            }
        }
        return left;
    }

    private static Expression parseUnary(State s) {
        if (s.matchTok(TOK_BANG)) {
            return new UnaryExpr(Expression.UnaryOp.NOT, parseUnary(s));
        }
        if (s.matchTok(TOK_MINUS)) {
            return new UnaryExpr(Expression.UnaryOp.NEG, parseUnary(s));
        }
        if (s.matchTok(TOK_TILDE)) {
            return new UnaryExpr(Expression.UnaryOp.BIT_NOT, parseUnary(s));
        }
        if (s.check(TOK_AMP)) {
            // & or &mut — borrow operators, no AST node.
            s.advance();
            if (s.check(TOK_MUT)) s.advance();
            return parsePostfix(s);
        }
        return parsePostfix(s);
    }

    private static Expression parsePostfix(State s) {
        Expression expr = parsePrimary(s);

        while (true) {
            if (s.check(TOK_LPAREN)) {
                s.advance();
                List<Expression> args = new ArrayList<>();
                while (!s.check(TOK_RPAREN) && !s.check(TOK_EOF)) {
                    args.add(parseExpression(s));
                    if (s.check(TOK_COMMA)) s.advance();
                }
                s.expect(TOK_RPAREN);
                // .clone() — strip Rust borrow-checker artifact.
                if (args.isEmpty()
                    && expr instanceof MemberExpr m
                    && m.property().equals("clone")) {
                    expr = m.object();
                    continue;
                }
                expr = new CallExpr(expr, args);
            } else if (s.check(TOK_DOT)) {
                s.advance();
                String prop = "unknown";
                if (s.peek().kind == TOK_IDENT) {
                    prop = snakeToCamel(s.peek().value);
                    s.advance();
                } else {
                    s.advance();
                }
                if (expr instanceof Identifier id && id.name().equals("self")) {
                    expr = new PropertyAccessExpr(prop);
                    continue;
                }
                expr = new MemberExpr(expr, prop);
            } else if (s.check(TOK_COLONCOLON)) {
                s.advance();
                if (s.peek().kind == TOK_IDENT) {
                    String name = snakeToCamel(s.peek().value);
                    s.advance();
                    expr = new Identifier(name);
                }
            } else if (s.check(TOK_LBRACKET)) {
                s.advance();
                Expression index = parseExpression(s);
                s.expect(TOK_RBRACKET);
                expr = new IndexAccessExpr(expr, index);
            } else {
                break;
            }
        }
        return expr;
    }

    private static Expression parsePrimary(State s) {
        Token tok = s.peek();

        if (tok.kind == TOK_NUMBER) {
            s.advance();
            BigInteger value;
            try {
                value = new BigInteger(tok.value);
            } catch (NumberFormatException nfe) {
                value = BigInteger.ZERO;
            }
            return new BigIntLiteral(value);
        }

        if (tok.kind == TOK_HEX_STRING) {
            s.advance();
            return new ByteStringLiteral(tok.value);
        }

        if (tok.kind == TOK_TRUE) {
            s.advance();
            return new BoolLiteral(true);
        }

        if (tok.kind == TOK_FALSE) {
            s.advance();
            return new BoolLiteral(false);
        }

        if (tok.kind == TOK_SELF) {
            s.advance();
            return new Identifier("self");
        }

        if (tok.kind == TOK_LPAREN) {
            s.advance();
            Expression expr = parseExpression(s);
            s.expect(TOK_RPAREN);
            return expr;
        }

        if (tok.kind == TOK_LBRACKET) {
            return parseArrayLiteral(s);
        }

        if (tok.kind == TOK_IDENT) {
            s.advance();
            return new Identifier(mapBuiltinName(tok.value));
        }

        s.addError("unsupported token \"" + tok.value + "\" (kind " + tok.kind
            + ") at " + tok.line + ":" + tok.col);
        s.advance();
        return new Identifier("unknown");
    }

    private static Expression parseArrayLiteral(State s) {
        s.expect(TOK_LBRACKET);
        List<Expression> elements = new ArrayList<>();
        while (!s.check(TOK_RBRACKET) && !s.check(TOK_EOF)) {
            elements.add(parseExpression(s));
            if (!s.matchTok(TOK_COMMA)) break;
        }
        s.expect(TOK_RBRACKET);
        return new CallExpr(new Identifier("FixedArray"), elements);
    }
}
