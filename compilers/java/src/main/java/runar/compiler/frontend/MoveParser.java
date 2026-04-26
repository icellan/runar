package runar.compiler.frontend;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
 * Move-style ({@code .runar.move}) parser for the Rúnar Java compiler.
 *
 * <p>Hand-rolled tokenizer + recursive-descent parser ported from
 * {@code compilers/python/runar_compiler/frontend/parser_move.py} (and the
 * Go reference at {@code compilers/go/frontend/parser_move.go}). All six
 * compilers must produce byte-identical Rúnar AST for the same source.
 */
public final class MoveParser {

    private MoveParser() {}

    // ---------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------

    /** Parse a {@code .runar.move} source file into a Rúnar contract AST. */
    public static ContractNode parse(String source, String filename) throws ParseException {
        List<Token> tokens = tokenize(source);
        Parser p = new Parser(tokens, filename);
        ContractNode contract = p.parseModule();
        if (!p.errors.isEmpty()) {
            throw new ParseException(String.join("; ", p.errors));
        }
        return contract;
    }

    // ---------------------------------------------------------------
    // Token kinds
    // ---------------------------------------------------------------

    private enum Kind {
        EOF, IDENT, NUMBER, STRING,
        LBRACE, RBRACE, LPAREN, RPAREN, LBRACKET, RBRACKET,
        SEMICOLON, COMMA, DOT, COLON, COLONCOLON,
        ASSIGN, EQEQ, NOTEQ,
        LT, LTEQ, GT, GTEQ,
        PLUS, MINUS, STAR, SLASH, PERCENT,
        BANG, TILDE,
        AMP, PIPE, CARET,
        AMPAMP, PIPEPIPE,
        PLUSPLUS, MINUSMINUS,
        PLUSEQ, MINUSEQ, STAREQ, SLASHEQ, PERCENTEQ,
        QUESTION, ARROW,
        SHL, SHR
    }

    private record Token(Kind kind, String value, int line, int column) {}

    // ---------------------------------------------------------------
    // Tokenizer
    // ---------------------------------------------------------------

    private static List<Token> tokenize(String source) {
        List<Token> out = new ArrayList<>();
        int i = 0;
        int n = source.length();
        int line = 1;
        int col = 0;

        while (i < n) {
            char ch = source.charAt(i);

            if (ch == '\n') {
                line++;
                col = 0;
                i++;
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
                while (i < n && source.charAt(i) != '\n') {
                    i++;
                }
                continue;
            }

            // Multi-line comment /* ... */
            if (ch == '/' && i + 1 < n && source.charAt(i + 1) == '*') {
                i += 2;
                col += 2;
                while (i + 1 < n) {
                    if (source.charAt(i) == '*' && source.charAt(i + 1) == '/') {
                        i += 2;
                        col += 2;
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
                continue;
            }

            int startCol = col;

            // String literals (" or ')
            if (ch == '"' || ch == '\'') {
                char quote = ch;
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
                out.add(new Token(Kind.STRING, val, line, startCol));
                continue;
            }

            // Numbers
            if (ch >= '0' && ch <= '9') {
                int start = i;
                boolean isHex = false;
                if (ch == '0' && i + 1 < n
                    && (source.charAt(i + 1) == 'x' || source.charAt(i + 1) == 'X')) {
                    isHex = true;
                    i += 2;
                    col += 2;
                    while (i < n && isHexDigit(source.charAt(i))) {
                        i++;
                        col++;
                    }
                } else {
                    while (i < n && source.charAt(i) >= '0' && source.charAt(i) <= '9') {
                        i++;
                        col++;
                    }
                }
                if (!isHex && i < n && source.charAt(i) == 'u') {
                    i++;
                    col++;
                    while (i < n && source.charAt(i) >= '0' && source.charAt(i) <= '9') {
                        i++;
                        col++;
                    }
                }
                if (isHex) {
                    String hexDigits = source.substring(start + 2, i);
                    if (!hexDigits.isEmpty() && hexDigits.length() % 2 == 0) {
                        out.add(new Token(Kind.STRING, hexDigits, line, startCol));
                        continue;
                    }
                }
                out.add(new Token(Kind.NUMBER, source.substring(start, i), line, startCol));
                continue;
            }

            // Identifiers and keywords
            if (isIdentStart(ch)) {
                int start = i;
                while (i < n && isIdentPart(source.charAt(i))) {
                    i++;
                    col++;
                }
                if (i < n && source.charAt(i) == '!') {
                    out.add(new Token(Kind.IDENT, source.substring(start, i) + "!", line, startCol));
                    i++;
                    col++;
                    continue;
                }
                out.add(new Token(Kind.IDENT, source.substring(start, i), line, startCol));
                continue;
            }

            // Two-character operators
            if (i + 1 < n) {
                String two = source.substring(i, i + 2);
                Kind k = TWO_CHAR_OPS.get(two);
                if (k != null) {
                    out.add(new Token(k, two, line, startCol));
                    i += 2;
                    col += 2;
                    continue;
                }
            }

            // Single-character operators
            Kind k1 = ONE_CHAR_OPS.get(ch);
            if (k1 != null) {
                out.add(new Token(k1, String.valueOf(ch), line, startCol));
                i++;
                col++;
                continue;
            }

            // Skip unknown characters
            i++;
            col++;
        }

        out.add(new Token(Kind.EOF, "", line, col));
        return out;
    }

    private static boolean isHexDigit(char ch) {
        return (ch >= '0' && ch <= '9')
            || (ch >= 'a' && ch <= 'f')
            || (ch >= 'A' && ch <= 'F');
    }

    private static boolean isIdentStart(char ch) {
        return Character.isLetter(ch) || ch == '_';
    }

    private static boolean isIdentPart(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '_';
    }

    private static final Map<String, Kind> TWO_CHAR_OPS = Map.ofEntries(
        Map.entry("::", Kind.COLONCOLON),
        Map.entry("==", Kind.EQEQ),
        Map.entry("!=", Kind.NOTEQ),
        Map.entry("<=", Kind.LTEQ),
        Map.entry(">=", Kind.GTEQ),
        Map.entry("&&", Kind.AMPAMP),
        Map.entry("||", Kind.PIPEPIPE),
        Map.entry("++", Kind.PLUSPLUS),
        Map.entry("--", Kind.MINUSMINUS),
        Map.entry("+=", Kind.PLUSEQ),
        Map.entry("-=", Kind.MINUSEQ),
        Map.entry("*=", Kind.STAREQ),
        Map.entry("/=", Kind.SLASHEQ),
        Map.entry("%=", Kind.PERCENTEQ),
        Map.entry("->", Kind.ARROW),
        Map.entry("<<", Kind.SHL),
        Map.entry(">>", Kind.SHR)
    );

    private static final Map<Character, Kind> ONE_CHAR_OPS = Map.ofEntries(
        Map.entry('{', Kind.LBRACE),
        Map.entry('}', Kind.RBRACE),
        Map.entry('(', Kind.LPAREN),
        Map.entry(')', Kind.RPAREN),
        Map.entry('[', Kind.LBRACKET),
        Map.entry(']', Kind.RBRACKET),
        Map.entry(';', Kind.SEMICOLON),
        Map.entry(',', Kind.COMMA),
        Map.entry('.', Kind.DOT),
        Map.entry(':', Kind.COLON),
        Map.entry('=', Kind.ASSIGN),
        Map.entry('<', Kind.LT),
        Map.entry('>', Kind.GT),
        Map.entry('+', Kind.PLUS),
        Map.entry('-', Kind.MINUS),
        Map.entry('*', Kind.STAR),
        Map.entry('/', Kind.SLASH),
        Map.entry('%', Kind.PERCENT),
        Map.entry('!', Kind.BANG),
        Map.entry('~', Kind.TILDE),
        Map.entry('&', Kind.AMP),
        Map.entry('|', Kind.PIPE),
        Map.entry('^', Kind.CARET),
        Map.entry('?', Kind.QUESTION)
    );

    // ---------------------------------------------------------------
    // Name conversion: snake_case → camelCase
    // ---------------------------------------------------------------

    private static String snakeToCamel(String s) {
        String[] parts = s.split("_");
        if (parts.length <= 1) {
            return s;
        }
        StringBuilder sb = new StringBuilder(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            if (!part.isEmpty()) {
                sb.append(Character.toUpperCase(part.charAt(0))).append(part.substring(1));
            }
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------
    // Move builtin / type maps (mirrors parser_move.py exactly)
    // ---------------------------------------------------------------

    private static final Map<String, String> MOVE_BUILTIN_MAP = Map.<String, String>ofEntries(
        Map.entry("check_sig",       "checkSig"),
        Map.entry("check_multi_sig", "checkMultiSig"),
        Map.entry("check_preimage",  "checkPreimage"),
        Map.entry("hash_160",        "hash160"),
        Map.entry("hash_256",        "hash256"),
        Map.entry("sha_256",         "sha256"),
        Map.entry("ripemd_160",      "ripemd160"),
        Map.entry("num_2_bin",       "num2bin"),
        Map.entry("bin_2_num",       "bin2num"),
        Map.entry("reverse_bytes",   "reverseBytes"),
        Map.entry("hash160",         "hash160"),
        Map.entry("hash256",         "hash256"),
        Map.entry("sha256",          "sha256"),
        Map.entry("ripemd160",       "ripemd160"),
        Map.entry("num2bin",         "num2bin"),
        Map.entry("bin2num",         "bin2num"),
        Map.entry("abs",             "abs"),
        Map.entry("min",             "min"),
        Map.entry("max",             "max"),
        Map.entry("within",          "within"),
        Map.entry("len",             "len"),
        Map.entry("pack",            "pack"),
        Map.entry("unpack",          "unpack"),
        Map.entry("verify_wots",                   "verifyWOTS"),
        Map.entry("verifyWots",                    "verifyWOTS"),
        Map.entry("verifyWOTS",                    "verifyWOTS"),
        Map.entry("verify_slhdsa_sha2_128s",       "verifySLHDSA_SHA2_128s"),
        Map.entry("verify_slh_dsa_sha2_128s",      "verifySLHDSA_SHA2_128s"),
        Map.entry("verifySlhdsaSha2128s",          "verifySLHDSA_SHA2_128s"),
        Map.entry("verifySlhDsaSha2128s",          "verifySLHDSA_SHA2_128s"),
        Map.entry("verify_slhdsa_sha2_128f",       "verifySLHDSA_SHA2_128f"),
        Map.entry("verify_slh_dsa_sha2_128f",      "verifySLHDSA_SHA2_128f"),
        Map.entry("verifySlhdsaSha2128f",          "verifySLHDSA_SHA2_128f"),
        Map.entry("verifySlhDsaSha2128f",          "verifySLHDSA_SHA2_128f"),
        Map.entry("verify_slhdsa_sha2_192s",       "verifySLHDSA_SHA2_192s"),
        Map.entry("verify_slh_dsa_sha2_192s",      "verifySLHDSA_SHA2_192s"),
        Map.entry("verifySlhdsaSha2192s",          "verifySLHDSA_SHA2_192s"),
        Map.entry("verifySlhDsaSha2192s",          "verifySLHDSA_SHA2_192s"),
        Map.entry("verify_slhdsa_sha2_192f",       "verifySLHDSA_SHA2_192f"),
        Map.entry("verify_slh_dsa_sha2_192f",      "verifySLHDSA_SHA2_192f"),
        Map.entry("verifySlhdsaSha2192f",          "verifySLHDSA_SHA2_192f"),
        Map.entry("verifySlhDsaSha2192f",          "verifySLHDSA_SHA2_192f"),
        Map.entry("verify_slhdsa_sha2_256s",       "verifySLHDSA_SHA2_256s"),
        Map.entry("verify_slh_dsa_sha2_256s",      "verifySLHDSA_SHA2_256s"),
        Map.entry("verifySlhdsaSha2256s",          "verifySLHDSA_SHA2_256s"),
        Map.entry("verifySlhDsaSha2256s",          "verifySLHDSA_SHA2_256s"),
        Map.entry("verify_slhdsa_sha2_256f",       "verifySLHDSA_SHA2_256f"),
        Map.entry("verify_slh_dsa_sha2_256f",      "verifySLHDSA_SHA2_256f"),
        Map.entry("verifySlhdsaSha2256f",          "verifySLHDSA_SHA2_256f"),
        Map.entry("verifySlhDsaSha2256f",          "verifySLHDSA_SHA2_256f"),
        Map.entry("p256_add",               "p256Add"),
        Map.entry("p256_mul",               "p256Mul"),
        Map.entry("p256_mul_gen",           "p256MulGen"),
        Map.entry("p256_negate",            "p256Negate"),
        Map.entry("p256_on_curve",          "p256OnCurve"),
        Map.entry("p256_encode_compressed", "p256EncodeCompressed"),
        Map.entry("verify_ecdsa_p256",      "verifyECDSA_P256"),
        Map.entry("p384_add",               "p384Add"),
        Map.entry("p384_mul",               "p384Mul"),
        Map.entry("p384_mul_gen",           "p384MulGen"),
        Map.entry("p384_negate",            "p384Negate"),
        Map.entry("p384_on_curve",          "p384OnCurve"),
        Map.entry("p384_encode_compressed", "p384EncodeCompressed"),
        Map.entry("verify_ecdsa_p384",      "verifyECDSA_P384"),
        // Pre-camelCased forms also accepted (matches the canonical TS Move
        // parser, whose regex preserves the literal `_P` boundary).
        Map.entry("verifyECDSA_P256",       "verifyECDSA_P256"),
        Map.entry("verifyECDSA_P384",       "verifyECDSA_P384")
    );

    private static String mapBuiltin(String name) {
        String mapped = MOVE_BUILTIN_MAP.get(name);
        if (mapped != null) {
            return mapped;
        }
        return snakeToCamel(name);
    }

    private static TypeNode mapType(String name) {
        if (name.equals("u64") || name.equals("u128") || name.equals("u256")
            || name.equals("Int") || name.equals("Bigint")) {
            return new PrimitiveType(PrimitiveTypeName.BIGINT);
        }
        if (name.equals("bool") || name.equals("Bool")) {
            return new PrimitiveType(PrimitiveTypeName.BOOLEAN);
        }
        if (name.equals("vector")) {
            return new PrimitiveType(PrimitiveTypeName.BYTE_STRING);
        }
        String camel = snakeToCamel(name);
        try {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(camel));
        } catch (IllegalArgumentException ignored) {
            // not a primitive in canonical form
        }
        try {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(name));
        } catch (IllegalArgumentException ignored) {
            // not a primitive in original form
        }
        return new CustomType(camel);
    }

    // ---------------------------------------------------------------
    // Parser
    // ---------------------------------------------------------------

    private static final class Parser {
        final List<Token> tokens;
        final String filename;
        int pos = 0;
        final List<String> errors = new ArrayList<>();

        Parser(List<Token> tokens, String filename) {
            this.tokens = tokens;
            this.filename = filename;
        }

        // -- token helpers ---------------------------------------------------

        Token peek() {
            if (pos < tokens.size()) {
                return tokens.get(pos);
            }
            return new Token(Kind.EOF, "", 0, 0);
        }

        Token advance() {
            Token t = peek();
            if (pos < tokens.size()) {
                pos++;
            }
            return t;
        }

        Token expect(Kind k) {
            Token t = advance();
            if (t.kind() != k) {
                errors.add("line " + t.line() + ": expected token kind " + k
                    + ", got " + t.kind() + " (" + repr(t.value()) + ")");
            }
            return t;
        }

        Token expectIdent(String value) {
            Token t = advance();
            if (t.kind() != Kind.IDENT || !t.value().equals(value)) {
                errors.add("line " + t.line() + ": expected '" + value
                    + "', got " + repr(t.value()));
            }
            return t;
        }

        boolean check(Kind k) {
            return peek().kind() == k;
        }

        boolean checkIdent(String value) {
            Token t = peek();
            return t.kind() == Kind.IDENT && t.value().equals(value);
        }

        boolean match(Kind k) {
            if (check(k)) {
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
            return new SourceLocation(filename, t.line(), t.column());
        }

        // -- module ----------------------------------------------------------

        ContractNode parseModule() throws ParseException {
            while (checkIdent("use")) {
                skipUseDecl();
            }

            if (!matchIdent("module")) {
                throw new ParseException("expected 'module' keyword");
            }

            Token nameTok = expect(Kind.IDENT);
            String moduleName = nameTok.value();

            expect(Kind.LBRACE);

            List<PropertyNode> properties = new ArrayList<>();
            List<MethodNode> methods = new ArrayList<>();
            ParentClass parentClass = ParentClass.SMART_CONTRACT;

            while (!check(Kind.RBRACE) && !check(Kind.EOF)) {
                if (checkIdent("use")) {
                    skipUseDecl();
                    continue;
                }

                if (checkIdent("resource") || checkIdent("struct")) {
                    boolean isResource = checkIdent("resource");
                    if (isResource) {
                        advance();
                    }
                    List<PropertyNode> props = parseStruct();
                    boolean anyMutable = false;
                    for (PropertyNode p : props) {
                        if (!p.readonly()) {
                            anyMutable = true;
                            break;
                        }
                    }
                    if (isResource || anyMutable) {
                        parentClass = ParentClass.STATEFUL_SMART_CONTRACT;
                    }
                    properties.addAll(props);
                    continue;
                }

                if (checkIdent("public") || checkIdent("fun")) {
                    FnResult r = parseFunction();
                    if (r.hasMut) {
                        parentClass = ParentClass.STATEFUL_SMART_CONTRACT;
                    }
                    methods.add(r.method);
                    continue;
                }

                advance();
            }

            expect(Kind.RBRACE);

            MethodNode constructor = buildConstructor(properties);

            return new ContractNode(
                moduleName,
                parentClass,
                properties,
                constructor,
                methods,
                filename
            );
        }

        void skipUseDecl() {
            while (!check(Kind.SEMICOLON) && !check(Kind.EOF)) {
                advance();
            }
            match(Kind.SEMICOLON);
        }

        // -- struct ----------------------------------------------------------

        List<PropertyNode> parseStruct() {
            expectIdent("struct");

            expect(Kind.IDENT);

            if (checkIdent("has")) {
                advance();
                while (peek().kind() == Kind.IDENT || peek().kind() == Kind.COMMA) {
                    advance();
                }
            }

            expect(Kind.LBRACE);

            List<PropertyNode> props = new ArrayList<>();
            while (!check(Kind.RBRACE) && !check(Kind.EOF)) {
                Token nameTok = expect(Kind.IDENT);
                String fieldName = snakeToCamel(nameTok.value());

                expect(Kind.COLON);

                boolean isMut = check(Kind.AMP)
                    && pos + 1 < tokens.size()
                    && tokens.get(pos + 1).kind() == Kind.IDENT
                    && tokens.get(pos + 1).value().equals("mut");

                String typeName = parseTypeName();
                TypeNode typeNode = mapType(typeName);

                boolean readonly = !isMut;

                Expression initializer = null;
                if (match(Kind.ASSIGN)) {
                    initializer = parseExpression();
                }

                props.add(new PropertyNode(
                    fieldName,
                    typeNode,
                    readonly,
                    initializer,
                    loc(),
                    null
                ));

                match(Kind.COMMA);
            }

            expect(Kind.RBRACE);
            return props;
        }

        String parseTypeName() {
            if (match(Kind.AMP)) {
                matchIdent("mut");
            }

            Token nameTok = expect(Kind.IDENT);
            String name = nameTok.value();

            while (match(Kind.COLONCOLON)) {
                Token nxt = expect(Kind.IDENT);
                name = nxt.value();
            }

            if (match(Kind.LT)) {
                int depth = 1;
                while (depth > 0 && !check(Kind.EOF)) {
                    if (check(Kind.LT)) depth++;
                    if (check(Kind.GT)) depth--;
                    advance();
                }
            }

            return name;
        }

        // -- function --------------------------------------------------------

        private record FnResult(MethodNode method, boolean hasMut) {}

        FnResult parseFunction() {
            SourceLocation location = loc();
            Visibility visibility = Visibility.PRIVATE;

            if (matchIdent("public")) {
                visibility = Visibility.PUBLIC;
                if (check(Kind.LPAREN)) {
                    advance();
                    while (!check(Kind.RPAREN) && !check(Kind.EOF)) {
                        advance();
                    }
                    match(Kind.RPAREN);
                }
            }

            expectIdent("fun");

            Token nameTok = expect(Kind.IDENT);
            String name = snakeToCamel(nameTok.value());

            ParamsResult pr = parseParams();
            List<ParamNode> params = pr.params;
            boolean hasMut = pr.hasMut;

            boolean hasReturnType = false;
            if (match(Kind.COLON)) {
                parseTypeName();
                hasReturnType = true;
            }

            List<Statement> body = parseBlock();

            if (hasReturnType && !body.isEmpty()) {
                Statement last = body.get(body.size() - 1);
                if (last instanceof ExpressionStatement es) {
                    body.set(body.size() - 1, new ReturnStatement(es.expression(), es.sourceLocation()));
                }
            }

            return new FnResult(
                new MethodNode(name, params, body, visibility, location),
                hasMut
            );
        }

        private record ParamsResult(List<ParamNode> params, boolean hasMut) {}

        ParamsResult parseParams() {
            expect(Kind.LPAREN);
            List<ParamNode> params = new ArrayList<>();
            boolean hasMutReceiver = false;

            while (!check(Kind.RPAREN) && !check(Kind.EOF)) {
                if (checkIdent("self")) {
                    advance();
                    if (match(Kind.COMMA)) continue;
                    break;
                }

                boolean isMut = false;
                if (check(Kind.AMP)) {
                    advance();
                    if (matchIdent("mut")) {
                        isMut = true;
                    }
                }

                Token nameTok = expect(Kind.IDENT);
                String paramName = nameTok.value();

                expect(Kind.COLON);

                boolean typeIsMut = false;
                if (check(Kind.AMP)) {
                    advance();
                    if (matchIdent("mut")) {
                        typeIsMut = true;
                    }
                }

                String typeName = parseTypeName();

                if (paramName.equals("self") || paramName.equals("contract")) {
                    if (isMut || typeIsMut) {
                        hasMutReceiver = true;
                    }
                    if (match(Kind.COMMA)) continue;
                    break;
                }

                String camelName = snakeToCamel(paramName);
                params.add(new ParamNode(camelName, mapType(typeName)));

                if (!match(Kind.COMMA)) break;
            }

            expect(Kind.RPAREN);
            return new ParamsResult(params, hasMutReceiver);
        }

        // -- blocks ----------------------------------------------------------

        List<Statement> parseBlock() {
            expect(Kind.LBRACE);
            List<Statement> stmts = new ArrayList<>();
            while (!check(Kind.RBRACE) && !check(Kind.EOF)) {
                if (match(Kind.SEMICOLON)) continue;
                Statement s = parseStatement();
                if (s != null) {
                    stmts.add(s);
                }
            }
            expect(Kind.RBRACE);
            return foldWhileAsFor(stmts);
        }

        // -- statements ------------------------------------------------------

        Statement parseStatement() {
            SourceLocation location = loc();

            if (checkIdent("let")) return parseLetDecl(location);
            if (checkIdent("assert!") || checkIdent("assert_eq!")) return parseAssert(location);
            if (checkIdent("if")) return parseIf(location);
            if (checkIdent("while")) return parseWhile(location);
            if (checkIdent("loop")) return parseLoop(location);
            if (checkIdent("return")) return parseReturn(location);
            return parseExprStatement(location);
        }

        Statement parseLetDecl(SourceLocation location) {
            expectIdent("let");

            matchIdent("mut");
            Token nameTok = expect(Kind.IDENT);
            String varName = snakeToCamel(nameTok.value());

            TypeNode typeNode = null;
            if (match(Kind.COLON)) {
                String typeName = parseTypeName();
                typeNode = mapType(typeName);
            }

            Expression init;
            if (match(Kind.ASSIGN)) {
                init = parseExpression();
            } else {
                init = new BigIntLiteral(BigInteger.ZERO);
            }

            expect(Kind.SEMICOLON);

            return new VariableDeclStatement(varName, typeNode, init, location);
        }

        Statement parseAssert(SourceLocation location) {
            Token tok = advance();

            expect(Kind.LPAREN);

            if (tok.value().equals("assert_eq!")) {
                Expression left = parseExpression();
                expect(Kind.COMMA);
                Expression right = parseExpression();
                if (match(Kind.COMMA)) {
                    parseExpression();
                }
                expect(Kind.RPAREN);
                expect(Kind.SEMICOLON);

                Expression assertCall = new CallExpr(
                    new Identifier("assert"),
                    List.of(new BinaryExpr(Expression.BinaryOp.EQ, left, right))
                );
                return new ExpressionStatement(assertCall, location);
            }

            Expression expr = parseExpression();
            if (match(Kind.COMMA)) {
                parseExpression();
            }
            expect(Kind.RPAREN);
            expect(Kind.SEMICOLON);

            return new ExpressionStatement(
                new CallExpr(new Identifier("assert"), List.of(expr)),
                location
            );
        }

        Statement parseIf(SourceLocation location) {
            expectIdent("if");

            boolean hasParen = match(Kind.LPAREN);
            Expression condition = parseExpression();
            if (hasParen) {
                expect(Kind.RPAREN);
            }

            List<Statement> thenBlock = parseBlock();

            List<Statement> elseBlock = null;
            if (matchIdent("else")) {
                if (checkIdent("if")) {
                    Statement nested = parseIf(loc());
                    elseBlock = new ArrayList<>();
                    elseBlock.add(nested);
                } else {
                    elseBlock = parseBlock();
                }
            }

            return new IfStatement(condition, thenBlock, elseBlock, location);
        }

        Statement parseWhile(SourceLocation location) {
            expectIdent("while");

            boolean hasParen = match(Kind.LPAREN);
            Expression condition = parseExpression();
            if (hasParen) {
                expect(Kind.RPAREN);
            }

            List<Statement> body = parseBlock();

            VariableDeclStatement init = new VariableDeclStatement(
                "_w", null, new BigIntLiteral(BigInteger.ZERO), location
            );
            Statement update = new ExpressionStatement(
                new BigIntLiteral(BigInteger.ZERO), location
            );
            return new ForStatement(init, condition, update, body, location);
        }

        Statement parseLoop(SourceLocation location) {
            expectIdent("loop");

            List<Statement> body = parseBlock();

            VariableDeclStatement init = new VariableDeclStatement(
                "_l", null, new BigIntLiteral(BigInteger.ZERO), location
            );
            Statement update = new ExpressionStatement(
                new BigIntLiteral(BigInteger.ZERO), location
            );
            return new ForStatement(init, new BoolLiteral(true), update, body, location);
        }

        Statement parseReturn(SourceLocation location) {
            expectIdent("return");
            Expression value = null;
            if (!check(Kind.SEMICOLON) && !check(Kind.RBRACE)) {
                value = parseExpression();
            }
            match(Kind.SEMICOLON);
            return new ReturnStatement(value, location);
        }

        Statement parseExprStatement(SourceLocation location) {
            Expression expr = parseExpression();
            if (expr == null) {
                advance();
                return null;
            }

            if (match(Kind.ASSIGN)) {
                Expression value = parseExpression();
                expect(Kind.SEMICOLON);
                return new AssignmentStatement(expr, value, location);
            }

            Expression.BinaryOp compound = compoundOpFor(peek().kind());
            if (compound != null) {
                advance();
                Expression right = parseExpression();
                expect(Kind.SEMICOLON);
                Expression value = new BinaryExpr(compound, expr, right);
                return new AssignmentStatement(expr, value, location);
            }

            match(Kind.SEMICOLON);
            return new ExpressionStatement(expr, location);
        }

        private static Expression.BinaryOp compoundOpFor(Kind k) {
            return switch (k) {
                case PLUSEQ -> Expression.BinaryOp.ADD;
                case MINUSEQ -> Expression.BinaryOp.SUB;
                case STAREQ -> Expression.BinaryOp.MUL;
                case SLASHEQ -> Expression.BinaryOp.DIV;
                case PERCENTEQ -> Expression.BinaryOp.MOD;
                default -> null;
            };
        }

        // -- expressions (precedence climbing) ------------------------------

        Expression parseExpression() {
            return parseOr();
        }

        Expression parseOr() {
            Expression left = parseAnd();
            while (match(Kind.PIPEPIPE)) {
                Expression right = parseAnd();
                left = new BinaryExpr(Expression.BinaryOp.OR, left, right);
            }
            return left;
        }

        Expression parseAnd() {
            Expression left = parseBitOr();
            while (match(Kind.AMPAMP)) {
                Expression right = parseBitOr();
                left = new BinaryExpr(Expression.BinaryOp.AND, left, right);
            }
            return left;
        }

        Expression parseBitOr() {
            Expression left = parseBitXor();
            while (match(Kind.PIPE)) {
                Expression right = parseBitXor();
                left = new BinaryExpr(Expression.BinaryOp.BIT_OR, left, right);
            }
            return left;
        }

        Expression parseBitXor() {
            Expression left = parseBitAnd();
            while (match(Kind.CARET)) {
                Expression right = parseBitAnd();
                left = new BinaryExpr(Expression.BinaryOp.BIT_XOR, left, right);
            }
            return left;
        }

        Expression parseBitAnd() {
            Expression left = parseEquality();
            while (match(Kind.AMP)) {
                Expression right = parseEquality();
                left = new BinaryExpr(Expression.BinaryOp.BIT_AND, left, right);
            }
            return left;
        }

        Expression parseEquality() {
            Expression left = parseComparison();
            while (true) {
                if (match(Kind.EQEQ)) {
                    Expression right = parseComparison();
                    left = new BinaryExpr(Expression.BinaryOp.EQ, left, right);
                } else if (match(Kind.NOTEQ)) {
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
                if (match(Kind.LT)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.LT, left, right);
                } else if (match(Kind.LTEQ)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.LE, left, right);
                } else if (match(Kind.GT)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.GT, left, right);
                } else if (match(Kind.GTEQ)) {
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
                if (match(Kind.SHL)) {
                    Expression right = parseAdditive();
                    left = new BinaryExpr(Expression.BinaryOp.SHL, left, right);
                } else if (match(Kind.SHR)) {
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
                if (match(Kind.PLUS)) {
                    Expression right = parseMultiplicative();
                    left = new BinaryExpr(Expression.BinaryOp.ADD, left, right);
                } else if (match(Kind.MINUS)) {
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
                if (match(Kind.STAR)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.MUL, left, right);
                } else if (match(Kind.SLASH)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.DIV, left, right);
                } else if (match(Kind.PERCENT)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.MOD, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseUnary() {
            if (match(Kind.BANG)) {
                return new UnaryExpr(Expression.UnaryOp.NOT, parseUnary());
            }
            if (match(Kind.MINUS)) {
                return new UnaryExpr(Expression.UnaryOp.NEG, parseUnary());
            }
            if (match(Kind.TILDE)) {
                return new UnaryExpr(Expression.UnaryOp.BIT_NOT, parseUnary());
            }
            if (match(Kind.AMP)) {
                matchIdent("mut");
                return parseUnary();
            }
            if (check(Kind.STAR) && isDeref()) {
                advance();
                return parseUnary();
            }
            return parsePostfix();
        }

        boolean isDeref() {
            if (pos + 1 < tokens.size()) {
                Token nxt = tokens.get(pos + 1);
                return nxt.kind() == Kind.IDENT || nxt.kind() == Kind.LPAREN;
            }
            return false;
        }

        Expression parsePostfix() {
            Expression expr = parsePrimary();
            while (true) {
                if (match(Kind.DOT)) {
                    Token propTok = expect(Kind.IDENT);
                    String propName = snakeToCamel(propTok.value());

                    if (check(Kind.LPAREN)) {
                        List<Expression> args = parseCallArgs();
                        if (expr instanceof Identifier id
                            && (id.name().equals("self") || id.name().equals("contract"))) {
                            expr = new CallExpr(
                                new MemberExpr(new Identifier("this"), propName),
                                args
                            );
                        } else {
                            expr = new CallExpr(new MemberExpr(expr, propName), args);
                        }
                    } else {
                        if (expr instanceof Identifier id
                            && (id.name().equals("self") || id.name().equals("contract"))) {
                            expr = new PropertyAccessExpr(propName);
                        } else {
                            expr = new MemberExpr(expr, propName);
                        }
                    }
                } else if (match(Kind.LBRACKET)) {
                    Expression index = parseExpression();
                    expect(Kind.RBRACKET);
                    expr = new IndexAccessExpr(expr, index);
                } else if (match(Kind.PLUSPLUS)) {
                    expr = new IncrementExpr(expr, false);
                } else if (match(Kind.MINUSMINUS)) {
                    expr = new DecrementExpr(expr, false);
                } else {
                    break;
                }
            }
            return expr;
        }

        Expression parsePrimary() {
            Token tok = peek();

            if (tok.kind() == Kind.NUMBER) {
                advance();
                return parseMoveNumber(tok.value());
            }

            if (tok.kind() == Kind.STRING) {
                advance();
                return new ByteStringLiteral(tok.value());
            }

            if (tok.kind() == Kind.IDENT) {
                advance();
                String name = tok.value();

                if (name.equals("true")) {
                    return new BoolLiteral(true);
                }
                if (name.equals("false")) {
                    return new BoolLiteral(false);
                }
                if (name.equals("self") || name.equals("contract")) {
                    return new Identifier(name);
                }

                if (match(Kind.COLONCOLON)) {
                    Token nxt = expect(Kind.IDENT);
                    name = nxt.value();
                    while (match(Kind.COLONCOLON)) {
                        Token segment = expect(Kind.IDENT);
                        name = segment.value();
                    }
                }

                String mappedName = mapBuiltin(name);

                if (check(Kind.LPAREN)) {
                    List<Expression> args = parseCallArgs();
                    if (!args.isEmpty()
                        && args.get(0) instanceof Identifier id
                        && (id.name().equals("contract") || id.name().equals("self"))) {
                        args = new ArrayList<>(args.subList(1, args.size()));
                    }
                    return new CallExpr(new Identifier(mappedName), args);
                }

                return new Identifier(mappedName);
            }

            if (tok.kind() == Kind.LPAREN) {
                advance();
                Expression e = parseExpression();
                expect(Kind.RPAREN);
                return e;
            }

            errors.add("line " + tok.line() + ": unexpected token " + repr(tok.value()));
            advance();
            return new BigIntLiteral(BigInteger.ZERO);
        }

        List<Expression> parseCallArgs() {
            expect(Kind.LPAREN);
            List<Expression> args = new ArrayList<>();
            while (!check(Kind.RPAREN) && !check(Kind.EOF)) {
                args.add(parseExpression());
                if (!match(Kind.COMMA)) break;
            }
            expect(Kind.RPAREN);
            return args;
        }

        // -- constructor synthesis ------------------------------------------

        MethodNode buildConstructor(List<PropertyNode> properties) {
            List<PropertyNode> uninit = new ArrayList<>();
            for (PropertyNode p : properties) {
                if (p.initializer() == null) uninit.add(p);
            }

            List<ParamNode> params = new ArrayList<>(uninit.size());
            List<Expression> superArgs = new ArrayList<>(uninit.size());
            for (PropertyNode p : uninit) {
                params.add(new ParamNode(p.name(), p.type()));
                superArgs.add(new Identifier(p.name()));
            }

            SourceLocation loc = new SourceLocation(filename, 1, 0);
            List<Statement> body = new ArrayList<>();
            body.add(new ExpressionStatement(
                new CallExpr(new Identifier("super"), superArgs),
                loc
            ));
            for (PropertyNode p : uninit) {
                body.add(new AssignmentStatement(
                    new PropertyAccessExpr(p.name()),
                    new Identifier(p.name()),
                    loc
                ));
            }

            return new MethodNode("constructor", params, body, Visibility.PUBLIC, loc);
        }
    }

    // ---------------------------------------------------------------
    // Post-pass: fold while-with-counter into a canonical for-loop
    // ---------------------------------------------------------------

    private static List<Statement> foldWhileAsFor(List<Statement> stmts) {
        List<Statement> out = new ArrayList<>(stmts.size());
        int i = 0;
        while (i < stmts.size()) {
            Statement s = stmts.get(i);
            if (i + 1 < stmts.size() && s instanceof VariableDeclStatement vd) {
                Statement next = stmts.get(i + 1);
                if (next instanceof ForStatement fs
                    && fs.init() != null
                    && fs.init().name().equals("_w")) {
                    String iterName = vd.name();
                    Expression cond = fs.condition();
                    if (cond instanceof BinaryExpr be
                        && be.left() instanceof Identifier idLeft
                        && idLeft.name().equals(iterName)
                        && !fs.body().isEmpty()) {
                        Statement last = fs.body().get(fs.body().size() - 1);
                        if (last instanceof AssignmentStatement asg
                            && asg.target() instanceof Identifier asgTgt
                            && asgTgt.name().equals(iterName)
                            && asg.value() instanceof BinaryExpr asgVal
                            && asgVal.op() == Expression.BinaryOp.ADD
                            && asgVal.left() instanceof Identifier asgLeft
                            && asgLeft.name().equals(iterName)) {
                            List<Statement> trimmed = new ArrayList<>(
                                fs.body().subList(0, fs.body().size() - 1)
                            );
                            ForStatement folded = new ForStatement(
                                new VariableDeclStatement(
                                    iterName,
                                    vd.type(),
                                    vd.init(),
                                    vd.sourceLocation()
                                ),
                                cond,
                                new ExpressionStatement(
                                    new IncrementExpr(new Identifier(iterName), false),
                                    fs.sourceLocation()
                                ),
                                trimmed,
                                fs.sourceLocation()
                            );
                            out.add(folded);
                            i += 2;
                            continue;
                        }
                    }
                }
            }
            out.add(s);
            i++;
        }
        return out;
    }

    // ---------------------------------------------------------------
    // Number parsing
    // ---------------------------------------------------------------

    private static Expression parseMoveNumber(String s) {
        for (String suffix : new String[]{"u256", "u128", "u64", "u32", "u16", "u8"}) {
            if (s.endsWith(suffix)) {
                s = s.substring(0, s.length() - suffix.length());
                break;
            }
        }
        BigInteger v;
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) {
                v = new BigInteger(s.substring(2), 16);
            } else if (s.isEmpty()) {
                v = BigInteger.ZERO;
            } else {
                v = new BigInteger(s, 10);
            }
        } catch (NumberFormatException e) {
            v = BigInteger.ZERO;
        }
        return new BigIntLiteral(v);
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private static String repr(String s) {
        return "'" + s + "'";
    }

    /** Checked exception for parse-time problems. */
    public static final class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
    }
}
