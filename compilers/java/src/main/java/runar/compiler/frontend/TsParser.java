package runar.compiler.frontend;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.BoolLiteral;
import runar.compiler.ir.ast.ByteStringLiteral;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.CustomType;
import runar.compiler.ir.ast.DecrementExpr;
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
 * Parses {@code .runar.ts} source into a Rúnar {@link ContractNode}.
 *
 * <p>Hand-rolled tokenizer + recursive-descent parser, ported from the
 * Python reference at {@code compilers/python/runar_compiler/frontend/parser_ts.py}.
 * The grammar accepts the Rúnar TypeScript subset: imports from
 * {@code 'runar-lang'}, a single class extending {@code SmartContract} or
 * {@code StatefulSmartContract}, property declarations with TS type
 * annotations, a constructor (which must call {@code super(...)} first),
 * and methods using if/else, while, return, assert, let/const, arithmetic,
 * bitwise, comparison, member access, indexing, and call forms.
 *
 * <p>Output AST is byte-identical to what the Python, Go, and Ruby
 * {@code .runar.ts} parsers produce.
 */
public final class TsParser {

    private TsParser() {}

    // ---------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------

    public static ContractNode parse(String source, String filename) throws ParseException {
        List<Token> tokens = tokenize(source);
        Parser p = new Parser(tokens, filename);
        ContractNode contract = p.parseContract();
        if (!p.errors.isEmpty()) {
            throw new ParseException(String.join("\n", p.errors));
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
    // Token kinds (mirror Python TOK_* constants)
    // ---------------------------------------------------------------

    private static final int TOK_EOF = 0;
    private static final int TOK_IDENT = 1;
    private static final int TOK_NUMBER = 2;
    private static final int TOK_STRING = 3;
    private static final int TOK_LBRACE = 4;
    private static final int TOK_RBRACE = 5;
    private static final int TOK_LPAREN = 6;
    private static final int TOK_RPAREN = 7;
    private static final int TOK_LBRACKET = 8;
    private static final int TOK_RBRACKET = 9;
    private static final int TOK_SEMICOLON = 10;
    private static final int TOK_COMMA = 11;
    private static final int TOK_DOT = 12;
    private static final int TOK_COLON = 13;
    private static final int TOK_ASSIGN = 14;
    private static final int TOK_EQEQ = 15;
    private static final int TOK_NOTEQ = 16;
    private static final int TOK_LT = 17;
    private static final int TOK_LTEQ = 18;
    private static final int TOK_GT = 19;
    private static final int TOK_GTEQ = 20;
    private static final int TOK_PLUS = 21;
    private static final int TOK_MINUS = 22;
    private static final int TOK_STAR = 23;
    private static final int TOK_SLASH = 24;
    private static final int TOK_PERCENT = 25;
    private static final int TOK_BANG = 26;
    private static final int TOK_TILDE = 27;
    private static final int TOK_AMP = 28;
    private static final int TOK_PIPE = 29;
    private static final int TOK_CARET = 30;
    private static final int TOK_AMPAMP = 31;
    private static final int TOK_PIPEPIPE = 32;
    private static final int TOK_PLUSEQ = 33;
    private static final int TOK_MINUSEQ = 34;
    private static final int TOK_STAREQ = 35;
    private static final int TOK_SLASHEQ = 36;
    private static final int TOK_PERCENTEQ = 37;
    private static final int TOK_QUESTION = 38;
    private static final int TOK_PLUSPLUS = 39;
    private static final int TOK_MINUSMINUS = 40;
    private static final int TOK_EQEQEQ = 41;
    private static final int TOK_NOTEQEQ = 42;
    private static final int TOK_LSHIFT = 43;
    private static final int TOK_RSHIFT = 44;
    private static final int TOK_ARROW = 45;

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

    // ---------------------------------------------------------------
    // Type mappings
    // ---------------------------------------------------------------

    private static final Map<String, String> TYPE_MAP = new HashMap<>();
    static {
        TYPE_MAP.put("bigint", "bigint");
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
        TYPE_MAP.put("void", "void");
    }

    private static TypeNode parseTsTypeName(String name) {
        String mapped = TYPE_MAP.get(name);
        if (mapped != null) {
            // "void" is not a Rúnar primitive; expose as CustomType so
            // downstream passes can recognise/strip it.
            try {
                return new PrimitiveType(PrimitiveTypeName.fromCanonical(mapped));
            } catch (IllegalArgumentException ex) {
                return new CustomType(mapped);
            }
        }
        // Try direct primitive lookup by canonical name.
        try {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(name));
        } catch (IllegalArgumentException ignored) {
        }
        if ("number".equals(name)) {
            return new PrimitiveType(PrimitiveTypeName.BIGINT);
        }
        return new CustomType(name);
    }

    // ---------------------------------------------------------------
    // Tokenizer
    // ---------------------------------------------------------------

    private static boolean isIdentStart(char ch) {
        return Character.isLetter(ch) || ch == '_' || ch == '$';
    }

    private static boolean isIdentPart(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '_' || ch == '$';
    }

    private static boolean isHexDigit(char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    }

    private static boolean isOctalDigit(char ch) {
        return ch >= '0' && ch <= '7';
    }

    private static boolean isBinaryDigit(char ch) {
        return ch == '0' || ch == '1';
    }

    private static List<Token> tokenize(String source) {
        List<Token> tokens = new ArrayList<>();
        int line = 1;
        int col = 0;
        int i = 0;
        int n = source.length();

        while (i < n) {
            char ch = source.charAt(i);

            if (ch == '\n') {
                i++;
                line++;
                col = 0;
                continue;
            }
            if (ch == '\r') {
                i++;
                if (i < n && source.charAt(i) == '\n') {
                    i++;
                }
                line++;
                col = 0;
                continue;
            }

            if (ch == ' ' || ch == '\t') {
                i++;
                col++;
                continue;
            }

            // Single-line comment //
            if (ch == '/' && i + 1 < n && source.charAt(i + 1) == '/') {
                while (i < n && source.charAt(i) != '\n' && source.charAt(i) != '\r') {
                    i++;
                }
                continue;
            }

            // Multi-line comment /* ... */
            if (ch == '/' && i + 1 < n && source.charAt(i + 1) == '*') {
                i += 2;
                col += 2;
                boolean closed = false;
                while (i + 1 < n) {
                    if (source.charAt(i) == '*' && source.charAt(i + 1) == '/') {
                        i += 2;
                        col += 2;
                        closed = true;
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
                if (!closed && i < n) {
                    i++;
                }
                continue;
            }

            int startCol = col;

            // Template string literals (backticks)
            if (ch == '`') {
                i++;
                col++;
                int start = i;
                while (i < n && source.charAt(i) != '`') {
                    if (source.charAt(i) == '\\') {
                        i++;
                        col++;
                    }
                    if (i < n) {
                        if (source.charAt(i) == '\n') {
                            line++;
                            col = 0;
                        } else {
                            col++;
                        }
                        i++;
                    }
                }
                String val = source.substring(start, i);
                if (i < n) {
                    i++;
                    col++;
                }
                tokens.add(new Token(TOK_STRING, val, line, startCol));
                continue;
            }

            // String literals: single or double quotes
            if (ch == '\'' || ch == '"') {
                char quote = ch;
                i++;
                col++;
                int start = i;
                while (i < n && source.charAt(i) != quote) {
                    if (source.charAt(i) == '\\') {
                        i++;
                        col++;
                    }
                    if (i < n) {
                        i++;
                        col++;
                    }
                }
                String val = source.substring(start, Math.min(i, n));
                if (i < n) {
                    i++;
                    col++;
                }
                tokens.add(new Token(TOK_STRING, val, line, startCol));
                continue;
            }

            // Numbers (with optional BigInt 'n' suffix)
            if (Character.isDigit(ch)) {
                int start = i;
                if (ch == '0' && i + 1 < n && (source.charAt(i + 1) == 'x' || source.charAt(i + 1) == 'X')) {
                    i += 2;
                    col += 2;
                    while (i < n && isHexDigit(source.charAt(i))) {
                        i++;
                        col++;
                    }
                } else if (ch == '0' && i + 1 < n && (source.charAt(i + 1) == 'o' || source.charAt(i + 1) == 'O')) {
                    i += 2;
                    col += 2;
                    while (i < n && isOctalDigit(source.charAt(i))) {
                        i++;
                        col++;
                    }
                } else if (ch == '0' && i + 1 < n && (source.charAt(i + 1) == 'b' || source.charAt(i + 1) == 'B')) {
                    i += 2;
                    col += 2;
                    while (i < n && isBinaryDigit(source.charAt(i))) {
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
                // BigInt suffix 'n'
                if (i < n && source.charAt(i) == 'n') {
                    i++;
                    col++;
                }
                tokens.add(new Token(TOK_NUMBER, numStr, line, startCol));
                continue;
            }

            // Identifiers / keywords
            if (isIdentStart(ch)) {
                int start = i;
                while (i < n && isIdentPart(source.charAt(i))) {
                    i++;
                    col++;
                }
                String word = source.substring(start, i);
                tokens.add(new Token(TOK_IDENT, word, line, startCol));
                continue;
            }

            // Three-character operators
            if (i + 2 < n) {
                String three = source.substring(i, i + 3);
                Integer threeKind = THREE_CHAR_OPS.get(three);
                if (threeKind != null) {
                    tokens.add(new Token(threeKind, three, line, startCol));
                    i += 3;
                    col += 3;
                    continue;
                }
            }

            // Two-character operators
            if (i + 1 < n) {
                String two = source.substring(i, i + 2);
                Integer twoKind = TWO_CHAR_OPS.get(two);
                if (twoKind != null) {
                    tokens.add(new Token(twoKind, two, line, startCol));
                    i += 2;
                    col += 2;
                    continue;
                }
            }

            // Single-character operators
            Integer oneKind = ONE_CHAR_OPS.get(ch);
            if (oneKind != null) {
                tokens.add(new Token(oneKind, String.valueOf(ch), line, startCol));
                i++;
                col++;
                continue;
            }

            // Skip unknown
            i++;
            col++;
        }

        tokens.add(new Token(TOK_EOF, "", line, col));
        return tokens;
    }

    private static final Map<String, Integer> THREE_CHAR_OPS = new HashMap<>();
    static {
        THREE_CHAR_OPS.put("===", TOK_EQEQEQ);
        THREE_CHAR_OPS.put("!==", TOK_NOTEQEQ);
    }

    private static final Map<String, Integer> TWO_CHAR_OPS = new HashMap<>();
    static {
        TWO_CHAR_OPS.put("==", TOK_EQEQ);
        TWO_CHAR_OPS.put("!=", TOK_NOTEQ);
        TWO_CHAR_OPS.put("<=", TOK_LTEQ);
        TWO_CHAR_OPS.put(">=", TOK_GTEQ);
        TWO_CHAR_OPS.put("+=", TOK_PLUSEQ);
        TWO_CHAR_OPS.put("-=", TOK_MINUSEQ);
        TWO_CHAR_OPS.put("*=", TOK_STAREQ);
        TWO_CHAR_OPS.put("/=", TOK_SLASHEQ);
        TWO_CHAR_OPS.put("%=", TOK_PERCENTEQ);
        TWO_CHAR_OPS.put("&&", TOK_AMPAMP);
        TWO_CHAR_OPS.put("||", TOK_PIPEPIPE);
        TWO_CHAR_OPS.put("++", TOK_PLUSPLUS);
        TWO_CHAR_OPS.put("--", TOK_MINUSMINUS);
        TWO_CHAR_OPS.put("<<", TOK_LSHIFT);
        TWO_CHAR_OPS.put(">>", TOK_RSHIFT);
        TWO_CHAR_OPS.put("=>", TOK_ARROW);
    }

    private static final Map<Character, Integer> ONE_CHAR_OPS = new HashMap<>();
    static {
        ONE_CHAR_OPS.put('(', TOK_LPAREN);
        ONE_CHAR_OPS.put(')', TOK_RPAREN);
        ONE_CHAR_OPS.put('[', TOK_LBRACKET);
        ONE_CHAR_OPS.put(']', TOK_RBRACKET);
        ONE_CHAR_OPS.put('{', TOK_LBRACE);
        ONE_CHAR_OPS.put('}', TOK_RBRACE);
        ONE_CHAR_OPS.put(',', TOK_COMMA);
        ONE_CHAR_OPS.put('.', TOK_DOT);
        ONE_CHAR_OPS.put(':', TOK_COLON);
        ONE_CHAR_OPS.put(';', TOK_SEMICOLON);
        ONE_CHAR_OPS.put('=', TOK_ASSIGN);
        ONE_CHAR_OPS.put('<', TOK_LT);
        ONE_CHAR_OPS.put('>', TOK_GT);
        ONE_CHAR_OPS.put('+', TOK_PLUS);
        ONE_CHAR_OPS.put('-', TOK_MINUS);
        ONE_CHAR_OPS.put('*', TOK_STAR);
        ONE_CHAR_OPS.put('/', TOK_SLASH);
        ONE_CHAR_OPS.put('%', TOK_PERCENT);
        ONE_CHAR_OPS.put('!', TOK_BANG);
        ONE_CHAR_OPS.put('~', TOK_TILDE);
        ONE_CHAR_OPS.put('&', TOK_AMP);
        ONE_CHAR_OPS.put('|', TOK_PIPE);
        ONE_CHAR_OPS.put('^', TOK_CARET);
        ONE_CHAR_OPS.put('?', TOK_QUESTION);
    }

    // ---------------------------------------------------------------
    // Parser
    // ---------------------------------------------------------------

    private static final class Parser {
        final List<Token> tokens;
        final String fileName;
        int pos = 0;
        final List<String> errors = new ArrayList<>();
        boolean fatal = false;
        String fatalMsg = null;

        Parser(List<Token> tokens, String fileName) {
            this.tokens = tokens;
            this.fileName = fileName;
        }

        void addError(String msg) {
            errors.add(msg);
        }

        Token peek() {
            if (pos < tokens.size()) {
                return tokens.get(pos);
            }
            return new Token(TOK_EOF, "", 0, 0);
        }

        Token advance() {
            Token tok = peek();
            if (pos < tokens.size()) {
                pos++;
            }
            return tok;
        }

        Token expect(int kind) {
            Token tok = advance();
            if (tok.kind != kind) {
                addError(String.format("line %d: expected token kind %d, got %d ('%s')",
                    tok.line, kind, tok.kind, tok.value));
            }
            return tok;
        }

        Token expectIdent(String value) {
            Token tok = advance();
            if (tok.kind != TOK_IDENT || !tok.value.equals(value)) {
                addError(String.format("line %d: expected '%s', got '%s'",
                    tok.line, value, tok.value));
            }
            return tok;
        }

        boolean check(int kind) {
            return peek().kind == kind;
        }

        boolean checkIdent(String value) {
            Token t = peek();
            return t.kind == TOK_IDENT && t.value.equals(value);
        }

        boolean match(int kind) {
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

        void skipSemicolons() {
            while (check(TOK_SEMICOLON)) {
                advance();
            }
        }

        int peekNextKind() {
            if (pos + 1 < tokens.size()) {
                return tokens.get(pos + 1).kind;
            }
            return TOK_EOF;
        }

        // -- Top-level ------------------------------------------------

        ContractNode parseContract() throws ParseException {
            while (!check(TOK_EOF)) {
                if (checkIdent("import")) {
                    skipImport();
                    continue;
                }

                if (checkIdent("export")) {
                    advance();
                    if (checkIdent("class")) {
                        return parseClass();
                    }
                    if (checkIdent("default")) {
                        advance();
                        if (checkIdent("class")) {
                            return parseClass();
                        }
                    }
                    skipStatement();
                    continue;
                }

                if (checkIdent("class")) {
                    return parseClass();
                }

                skipStatement();
            }

            throw new ParseException("no class extending SmartContract or StatefulSmartContract found");
        }

        void skipImport() {
            advance(); // consume 'import'
            while (!check(TOK_EOF)) {
                Token t = peek();
                if (t.kind == TOK_SEMICOLON) {
                    advance();
                    return;
                }
                if (t.kind == TOK_IDENT
                    && (t.value.equals("import") || t.value.equals("export") || t.value.equals("class"))) {
                    return;
                }
                advance();
            }
        }

        void skipStatement() {
            int depth = 0;
            while (!check(TOK_EOF)) {
                Token t = peek();
                if (t.kind == TOK_LBRACE) {
                    depth++;
                    advance();
                } else if (t.kind == TOK_RBRACE) {
                    if (depth <= 0) {
                        return;
                    }
                    depth--;
                    advance();
                    if (depth == 0) {
                        return;
                    }
                } else if (t.kind == TOK_SEMICOLON && depth == 0) {
                    advance();
                    return;
                } else {
                    advance();
                }
            }
        }

        ContractNode parseClass() throws ParseException {
            expectIdent("class");

            Token nameTok = expect(TOK_IDENT);
            String contractName = nameTok.value;

            String parentClass = "SmartContract";
            if (matchIdent("extends")) {
                Token parentTok = expect(TOK_IDENT);
                parentClass = parentTok.value;
            }

            if (!parentClass.equals("SmartContract") && !parentClass.equals("StatefulSmartContract")) {
                throw new ParseException("no class extending SmartContract or StatefulSmartContract found");
            }

            expect(TOK_LBRACE);

            List<PropertyNode> properties = new ArrayList<>();
            MethodNode constructor = null;
            List<MethodNode> methods = new ArrayList<>();

            while (!check(TOK_RBRACE) && !check(TOK_EOF)) {
                skipSemicolons();
                if (check(TOK_RBRACE) || check(TOK_EOF)) {
                    break;
                }

                Object member = parseClassMember();
                if (member == null) {
                    continue;
                }
                if (member instanceof PropertyNode pn) {
                    properties.add(pn);
                } else if (member instanceof MethodNode mn) {
                    if (mn.name().equals("constructor")) {
                        if (constructor != null) {
                            addError("duplicate constructor");
                        }
                        constructor = mn;
                    } else {
                        methods.add(mn);
                    }
                }
            }

            expect(TOK_RBRACE);

            if (constructor == null) {
                addError("contract must have a constructor");
                constructor = new MethodNode(
                    "constructor",
                    new ArrayList<>(),
                    new ArrayList<>(),
                    Visibility.PUBLIC,
                    new SourceLocation(fileName, 1, 0)
                );
            }

            ParentClass pc = ParentClass.fromCanonical(parentClass);
            return new ContractNode(contractName, pc, properties, constructor, methods, fileName);
        }

        // -- Class members --------------------------------------------

        Object parseClassMember() throws ParseException {
            SourceLocation location = loc();

            String visibility = "private";
            boolean isReadonly = false;

            while (true) {
                if (checkIdent("public")) {
                    visibility = "public";
                    advance();
                } else if (checkIdent("private")) {
                    visibility = "private";
                    advance();
                } else if (checkIdent("protected")) {
                    visibility = "private";
                    advance();
                } else if (checkIdent("readonly")) {
                    isReadonly = true;
                    advance();
                } else {
                    break;
                }
            }

            if (checkIdent("constructor")) {
                return parseConstructorMethod(location);
            }

            if (peek().kind != TOK_IDENT) {
                advance();
                return null;
            }

            Token nameTok = advance();
            String memberName = nameTok.value;

            // Method: name(...)
            if (check(TOK_LPAREN)) {
                return parseMethod(memberName, visibility, location);
            }

            // Property: name: Type
            if (check(TOK_COLON)) {
                advance();
                TypeNode typeNode = parseType();

                Expression initializer = null;
                if (check(TOK_ASSIGN)) {
                    advance();
                    initializer = parseExpression();
                }

                skipSemicolons();
                return new PropertyNode(
                    memberName,
                    typeNode,
                    isReadonly,
                    initializer,
                    location,
                    null
                );
            }

            // Property without type annotation
            if (check(TOK_SEMICOLON)) {
                advance();
                addError(String.format("property '%s' must have an explicit type annotation", memberName));
                return new PropertyNode(
                    memberName,
                    new CustomType("unknown"),
                    isReadonly,
                    null,
                    location,
                    null
                );
            }

            skipToNextMember();
            return null;
        }

        void skipToNextMember() {
            int depth = 0;
            while (!check(TOK_EOF)) {
                Token t = peek();
                if (t.kind == TOK_LBRACE) {
                    depth++;
                    advance();
                } else if (t.kind == TOK_RBRACE) {
                    if (depth <= 0) {
                        return;
                    }
                    depth--;
                    advance();
                } else if (t.kind == TOK_SEMICOLON && depth == 0) {
                    advance();
                    return;
                } else {
                    advance();
                }
            }
        }

        // -- Constructor ----------------------------------------------

        MethodNode parseConstructorMethod(SourceLocation location) throws ParseException {
            expectIdent("constructor");
            List<ParamNode> params = parseParams();

            if (check(TOK_COLON)) {
                advance();
                parseType();
            }

            List<Statement> body = parseBlock();
            return new MethodNode("constructor", params, body, Visibility.PUBLIC, location);
        }

        // -- Methods --------------------------------------------------

        MethodNode parseMethod(String name, String visibility, SourceLocation location) throws ParseException {
            List<ParamNode> params = parseParams();

            if (check(TOK_COLON)) {
                advance();
                parseType();
            }

            List<Statement> body = parseBlock();

            Visibility vis = visibility.equals("public") ? Visibility.PUBLIC : Visibility.PRIVATE;
            return new MethodNode(name, params, body, vis, location);
        }

        // -- Parameters -----------------------------------------------

        List<ParamNode> parseParams() throws ParseException {
            expect(TOK_LPAREN);
            List<ParamNode> params = new ArrayList<>();

            while (!check(TOK_RPAREN) && !check(TOK_EOF)) {
                while (peek().kind == TOK_IDENT
                    && (peek().value.equals("public") || peek().value.equals("private")
                        || peek().value.equals("protected") || peek().value.equals("readonly"))) {
                    advance();
                }

                Token nameTok = expect(TOK_IDENT);
                String paramName = nameTok.value;

                match(TOK_QUESTION);

                TypeNode typ = null;
                if (match(TOK_COLON)) {
                    typ = parseType();
                }
                if (typ == null) {
                    addError(String.format("parameter '%s' must have an explicit type annotation", paramName));
                    typ = new CustomType("unknown");
                }
                params.add(new ParamNode(paramName, typ));

                if (!match(TOK_COMMA)) {
                    break;
                }
            }

            expect(TOK_RPAREN);
            return params;
        }

        // -- Type parsing ---------------------------------------------

        TypeNode parseType() throws ParseException {
            Token tok = peek();

            if (tok.kind != TOK_IDENT) {
                addError(String.format("line %d: expected type name, got '%s'", tok.line, tok.value));
                advance();
                return new CustomType("unknown");
            }

            String name = tok.value;
            advance();

            if (name.equals("FixedArray")) {
                if (match(TOK_LT)) {
                    TypeNode elem = parseType();
                    expect(TOK_COMMA);
                    Token sizeTok = expect(TOK_NUMBER);
                    int size;
                    try {
                        size = Integer.parseInt(sizeTok.value);
                    } catch (NumberFormatException ex) {
                        size = 0;
                        addError(String.format(
                            "line %d: FixedArray size must be a non-negative integer literal",
                            sizeTok.line));
                    }
                    expect(TOK_GT);
                    return new FixedArrayType(elem, size);
                }
                return new CustomType(name);
            }

            // Generic types we don't support — skip type args
            if (check(TOK_LT)) {
                skipTypeArgs();
            }

            // Array type T[]
            if (check(TOK_LBRACKET) && peekNextKind() == TOK_RBRACKET) {
                advance();
                advance();
                addError(String.format("use FixedArray<T, N> instead of %s[]", name));
            }

            return parseTsTypeName(name);
        }

        void skipTypeArgs() {
            if (!match(TOK_LT)) {
                return;
            }
            int depth = 1;
            while (depth > 0 && !check(TOK_EOF)) {
                if (check(TOK_LT)) {
                    depth++;
                } else if (check(TOK_GT)) {
                    depth--;
                }
                advance();
            }
        }

        // -- Block ----------------------------------------------------

        List<Statement> parseBlock() throws ParseException {
            expect(TOK_LBRACE);
            List<Statement> stmts = new ArrayList<>();

            while (!check(TOK_RBRACE) && !check(TOK_EOF)) {
                skipSemicolons();
                if (check(TOK_RBRACE) || check(TOK_EOF)) {
                    break;
                }
                Statement stmt = parseStatement();
                if (stmt != null) {
                    stmts.add(stmt);
                }
            }

            expect(TOK_RBRACE);
            return stmts;
        }

        // -- Statements -----------------------------------------------

        Statement parseStatement() throws ParseException {
            SourceLocation location = loc();
            Token tok = peek();

            if (tok.kind == TOK_IDENT && (tok.value.equals("const") || tok.value.equals("let"))) {
                return parseVariableDecl(location);
            }
            if (tok.kind == TOK_IDENT && tok.value.equals("if")) {
                return parseIf(location);
            }
            if (tok.kind == TOK_IDENT && tok.value.equals("for")) {
                return parseFor(location);
            }
            if (tok.kind == TOK_IDENT && tok.value.equals("return")) {
                return parseReturn(location);
            }
            return parseExpressionStatement(location);
        }

        Statement parseVariableDecl(SourceLocation locArg) throws ParseException {
            Token keyword = advance();
            // mutability tracked indirectly: VariableDeclStatement records type/init only;
            // 'let' vs 'const' is enforced upstream (validate pass) — but the AST shape
            // here matches the Python parser which does record it. The Java AST does
            // not carry a mutable flag, so we drop it.
            // (Reference: VariableDeclStatement record has no mutable field.)
            // 'let'/'const' equally produce VariableDeclStatement.

            Token nameTok = expect(TOK_IDENT);
            String varName = nameTok.value;

            TypeNode typeNode = null;
            if (match(TOK_COLON)) {
                typeNode = parseType();
            }

            Expression init = null;
            if (match(TOK_ASSIGN)) {
                init = parseExpression();
            }
            if (init == null) {
                init = new BigIntLiteral(BigInteger.ZERO);
            }

            skipSemicolons();
            return new VariableDeclStatement(varName, typeNode, init, locArg);
        }

        Statement parseIf(SourceLocation locArg) throws ParseException {
            expectIdent("if");
            expect(TOK_LPAREN);
            Expression condition = parseExpression();
            expect(TOK_RPAREN);

            List<Statement> thenBlock = parseBlockOrStatement();

            List<Statement> elseBlock = null;
            if (matchIdent("else")) {
                if (checkIdent("if")) {
                    SourceLocation elifLoc = loc();
                    Statement elifStmt = parseIf(elifLoc);
                    elseBlock = new ArrayList<>();
                    elseBlock.add(elifStmt);
                } else {
                    elseBlock = parseBlockOrStatement();
                }
            }

            return new IfStatement(condition, thenBlock, elseBlock, locArg);
        }

        List<Statement> parseBlockOrStatement() throws ParseException {
            if (check(TOK_LBRACE)) {
                return parseBlock();
            }
            Statement stmt = parseStatement();
            List<Statement> out = new ArrayList<>();
            if (stmt != null) {
                out.add(stmt);
            }
            return out;
        }

        Statement parseFor(SourceLocation locArg) throws ParseException {
            expectIdent("for");
            expect(TOK_LPAREN);

            SourceLocation initLoc = loc();
            VariableDeclStatement initStmt;
            if (checkIdent("let") || checkIdent("const")) {
                Statement stmt = parseVariableDecl(initLoc);
                if (stmt instanceof VariableDeclStatement vds) {
                    initStmt = vds;
                } else {
                    initStmt = new VariableDeclStatement(
                        "_i", null, new BigIntLiteral(BigInteger.ZERO), initLoc);
                }
            } else {
                initStmt = new VariableDeclStatement(
                    "_i", null, new BigIntLiteral(BigInteger.ZERO), initLoc);
                while (!check(TOK_SEMICOLON) && !check(TOK_EOF)) {
                    advance();
                }
            }

            match(TOK_SEMICOLON);

            Expression condition;
            if (check(TOK_SEMICOLON)) {
                condition = new BoolLiteral(false);
            } else {
                condition = parseExpression();
            }
            expect(TOK_SEMICOLON);

            SourceLocation updateLoc = loc();
            Statement update;
            if (check(TOK_RPAREN)) {
                update = new ExpressionStatement(new BigIntLiteral(BigInteger.ZERO), updateLoc);
            } else {
                Expression updateExpr = parseExpression();
                update = new ExpressionStatement(updateExpr, updateLoc);
            }

            expect(TOK_RPAREN);

            List<Statement> body = parseBlockOrStatement();
            return new ForStatement(initStmt, condition, update, body, locArg);
        }

        Statement parseReturn(SourceLocation locArg) throws ParseException {
            expectIdent("return");

            Expression value = null;
            if (!check(TOK_SEMICOLON) && !check(TOK_RBRACE) && !check(TOK_EOF)) {
                value = parseExpression();
            }
            skipSemicolons();
            return new ReturnStatement(value, locArg);
        }

        Statement parseExpressionStatement(SourceLocation locArg) throws ParseException {
            Expression expr = parseExpression();

            if (match(TOK_ASSIGN)) {
                Expression value = parseExpression();
                skipSemicolons();
                return new AssignmentStatement(expr, value, locArg);
            }

            // Compound assignments
            int[] compoundKinds = {
                TOK_PLUSEQ, TOK_MINUSEQ, TOK_STAREQ, TOK_SLASHEQ, TOK_PERCENTEQ
            };
            String[] compoundOps = {"+", "-", "*", "/", "%"};
            for (int idx = 0; idx < compoundKinds.length; idx++) {
                if (match(compoundKinds[idx])) {
                    Expression right = parseExpression();
                    skipSemicolons();
                    Expression.BinaryOp op = Expression.BinaryOp.fromCanonical(compoundOps[idx]);
                    Expression value = new BinaryExpr(op, expr, right);
                    return new AssignmentStatement(expr, value, locArg);
                }
            }

            skipSemicolons();
            return new ExpressionStatement(expr, locArg);
        }

        // -- Expressions ----------------------------------------------

        Expression parseExpression() throws ParseException {
            return parseTernary();
        }

        Expression parseTernary() throws ParseException {
            Expression expr = parseOr();
            if (match(TOK_QUESTION)) {
                Expression consequent = parseTernary();
                expect(TOK_COLON);
                Expression alternate = parseTernary();
                return new TernaryExpr(expr, consequent, alternate);
            }
            return expr;
        }

        Expression parseOr() throws ParseException {
            Expression left = parseAnd();
            while (match(TOK_PIPEPIPE)) {
                Expression right = parseAnd();
                left = new BinaryExpr(Expression.BinaryOp.OR, left, right);
            }
            return left;
        }

        Expression parseAnd() throws ParseException {
            Expression left = parseBitwiseOr();
            while (match(TOK_AMPAMP)) {
                Expression right = parseBitwiseOr();
                left = new BinaryExpr(Expression.BinaryOp.AND, left, right);
            }
            return left;
        }

        Expression parseBitwiseOr() throws ParseException {
            Expression left = parseBitwiseXor();
            while (match(TOK_PIPE)) {
                Expression right = parseBitwiseXor();
                left = new BinaryExpr(Expression.BinaryOp.BIT_OR, left, right);
            }
            return left;
        }

        Expression parseBitwiseXor() throws ParseException {
            Expression left = parseBitwiseAnd();
            while (match(TOK_CARET)) {
                Expression right = parseBitwiseAnd();
                left = new BinaryExpr(Expression.BinaryOp.BIT_XOR, left, right);
            }
            return left;
        }

        Expression parseBitwiseAnd() throws ParseException {
            Expression left = parseEquality();
            while (match(TOK_AMP)) {
                Expression right = parseEquality();
                left = new BinaryExpr(Expression.BinaryOp.BIT_AND, left, right);
            }
            return left;
        }

        Expression parseEquality() throws ParseException {
            Expression left = parseComparison();
            while (true) {
                if (match(TOK_EQEQEQ) || match(TOK_EQEQ)) {
                    Expression right = parseComparison();
                    left = new BinaryExpr(Expression.BinaryOp.EQ, left, right);
                } else if (match(TOK_NOTEQEQ) || match(TOK_NOTEQ)) {
                    Expression right = parseComparison();
                    left = new BinaryExpr(Expression.BinaryOp.NEQ, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseComparison() throws ParseException {
            Expression left = parseShift();
            while (true) {
                if (match(TOK_LT)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.LT, left, right);
                } else if (match(TOK_LTEQ)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.LE, left, right);
                } else if (match(TOK_GT)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.GT, left, right);
                } else if (match(TOK_GTEQ)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.GE, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseShift() throws ParseException {
            Expression left = parseAdditive();
            while (true) {
                if (match(TOK_LSHIFT)) {
                    Expression right = parseAdditive();
                    left = new BinaryExpr(Expression.BinaryOp.SHL, left, right);
                } else if (match(TOK_RSHIFT)) {
                    Expression right = parseAdditive();
                    left = new BinaryExpr(Expression.BinaryOp.SHR, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseAdditive() throws ParseException {
            Expression left = parseMultiplicative();
            while (true) {
                if (match(TOK_PLUS)) {
                    Expression right = parseMultiplicative();
                    left = new BinaryExpr(Expression.BinaryOp.ADD, left, right);
                } else if (match(TOK_MINUS)) {
                    Expression right = parseMultiplicative();
                    left = new BinaryExpr(Expression.BinaryOp.SUB, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseMultiplicative() throws ParseException {
            Expression left = parseUnary();
            while (true) {
                if (match(TOK_STAR)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.MUL, left, right);
                } else if (match(TOK_SLASH)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.DIV, left, right);
                } else if (match(TOK_PERCENT)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.MOD, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseUnary() throws ParseException {
            if (match(TOK_BANG)) {
                Expression operand = parseUnary();
                return new UnaryExpr(Expression.UnaryOp.NOT, operand);
            }
            if (match(TOK_MINUS)) {
                Expression operand = parseUnary();
                return new UnaryExpr(Expression.UnaryOp.NEG, operand);
            }
            if (match(TOK_TILDE)) {
                Expression operand = parseUnary();
                return new UnaryExpr(Expression.UnaryOp.BIT_NOT, operand);
            }
            if (match(TOK_PLUSPLUS)) {
                Expression operand = parseUnary();
                return new IncrementExpr(operand, true);
            }
            if (match(TOK_MINUSMINUS)) {
                Expression operand = parseUnary();
                return new DecrementExpr(operand, true);
            }
            return parsePostfix();
        }

        Expression parsePostfix() throws ParseException {
            Expression expr = parsePrimary();
            while (true) {
                if (match(TOK_DOT)) {
                    Token propTok = expect(TOK_IDENT);
                    String propName = propTok.value;

                    if (check(TOK_LPAREN)) {
                        List<Expression> args = parseCallArgs();
                        if (expr instanceof Identifier id && id.name().equals("this")) {
                            expr = new CallExpr(
                                new MemberExpr(new Identifier("this"), propName),
                                args
                            );
                        } else {
                            expr = new CallExpr(
                                new MemberExpr(expr, propName),
                                args
                            );
                        }
                    } else {
                        if (expr instanceof Identifier id && id.name().equals("this")) {
                            expr = new PropertyAccessExpr(propName);
                        } else {
                            expr = new MemberExpr(expr, propName);
                        }
                    }
                } else if (match(TOK_LBRACKET)) {
                    Expression index = parseExpression();
                    expect(TOK_RBRACKET);
                    expr = new IndexAccessExpr(expr, index);
                } else if (check(TOK_LPAREN) && isCallable(expr)) {
                    List<Expression> args = parseCallArgs();
                    expr = new CallExpr(expr, args);
                } else if (match(TOK_PLUSPLUS)) {
                    expr = new IncrementExpr(expr, false);
                } else if (match(TOK_MINUSMINUS)) {
                    expr = new DecrementExpr(expr, false);
                } else if (checkIdent("as")) {
                    advance();
                    parseType();
                } else {
                    break;
                }
            }
            return expr;
        }

        boolean isCallable(Expression expr) {
            return expr instanceof Identifier;
        }

        List<Expression> parseCallArgs() throws ParseException {
            expect(TOK_LPAREN);
            List<Expression> args = new ArrayList<>();
            while (!check(TOK_RPAREN) && !check(TOK_EOF)) {
                Expression arg = parseExpression();
                args.add(arg);
                if (!match(TOK_COMMA)) {
                    break;
                }
            }
            expect(TOK_RPAREN);
            return args;
        }

        Expression parsePrimary() throws ParseException {
            Token tok = peek();

            if (tok.kind == TOK_NUMBER) {
                advance();
                return parseNumberLiteral(tok.value);
            }

            if (tok.kind == TOK_STRING) {
                advance();
                return new ByteStringLiteral(tok.value);
            }

            if (tok.kind == TOK_IDENT) {
                advance();
                String name = tok.value;
                if (name.equals("true")) {
                    return new BoolLiteral(true);
                }
                if (name.equals("false")) {
                    return new BoolLiteral(false);
                }
                if (name.equals("this")) {
                    return new Identifier("this");
                }
                if (name.equals("super")) {
                    return new Identifier("super");
                }
                if (check(TOK_LPAREN)) {
                    List<Expression> args = parseCallArgs();
                    return new CallExpr(new Identifier(name), args);
                }
                return new Identifier(name);
            }

            if (tok.kind == TOK_LPAREN) {
                advance();
                Expression expr = parseExpression();
                expect(TOK_RPAREN);
                return expr;
            }

            if (tok.kind == TOK_LBRACKET) {
                return parseArrayLiteral();
            }

            addError(String.format("line %d: unexpected token '%s'", tok.line, tok.value));
            advance();
            return new BigIntLiteral(BigInteger.ZERO);
        }

        Expression parseArrayLiteral() throws ParseException {
            expect(TOK_LBRACKET);
            List<Expression> elements = new ArrayList<>();
            while (!check(TOK_RBRACKET) && !check(TOK_EOF)) {
                Expression elem = parseExpression();
                elements.add(elem);
                if (!match(TOK_COMMA)) {
                    break;
                }
            }
            expect(TOK_RBRACKET);
            return new ArrayLiteralExpr(elements);
        }
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private static Expression parseNumberLiteral(String s) {
        BigInteger val;
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) {
                val = new BigInteger(s.substring(2), 16);
            } else if (s.startsWith("0o") || s.startsWith("0O")) {
                val = new BigInteger(s.substring(2), 8);
            } else if (s.startsWith("0b") || s.startsWith("0B")) {
                val = new BigInteger(s.substring(2), 2);
            } else {
                val = new BigInteger(s);
            }
        } catch (NumberFormatException ex) {
            val = BigInteger.ZERO;
        }
        // Match Python: clamp to int64 range; otherwise emit 0.
        BigInteger maxInt64 = BigInteger.valueOf(9223372036854775807L);
        BigInteger minInt64 = BigInteger.valueOf(-9223372036854775808L);
        if (val.compareTo(maxInt64) > 0 || val.compareTo(minInt64) < 0) {
            return new BigIntLiteral(BigInteger.ZERO);
        }
        return new BigIntLiteral(val);
    }
}
