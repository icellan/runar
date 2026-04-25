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
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * Parses {@code .runar.sol} (Solidity-like) source into a Rúnar
 * {@link ContractNode}.
 *
 * <p>Hand-rolled tokenizer + recursive-descent parser, ported from the
 * Python and Go reference implementations
 * ({@code compilers/python/runar_compiler/frontend/parser_sol.py},
 * {@code compilers/go/frontend/parser_sol.go}). All six compilers must
 * produce byte-identical Rúnar AST for the same {@code .runar.sol} source.
 *
 * <p>Surface syntax:
 * <ul>
 *   <li>{@code contract Name is SmartContract { ... }} /
 *       {@code is StatefulSmartContract { ... }}</li>
 *   <li>{@code immutable} qualifier on properties (maps to readonly)</li>
 *   <li>{@code constructor(...) { ... }}</li>
 *   <li>{@code function name(...) public { ... }}</li>
 *   <li>Solidity-style type names: {@code uint}/{@code uint256}/{@code int}/{@code int256}
 *       map to {@code bigint}; {@code bytes} maps to {@code ByteString};
 *       {@code address} maps to {@code Addr}; {@code bool} maps to {@code boolean}</li>
 *   <li>{@code require(expr)} lowers to {@code assert(expr)}</li>
 * </ul>
 */
public final class SolParser {

    private SolParser() {}

    // ---------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------

    /** Parse Solidity-syntax source into a Rúnar contract AST. */
    public static ContractNode parse(String source, String filename) throws ParseException {
        Parser p = new Parser(filename);
        p.tokens = tokenize(source);
        p.pos = 0;
        ContractNode contract = p.parseContract();
        rewriteContractProps(contract);
        if (!p.errors.isEmpty()) {
            throw new ParseException(String.join("; ", p.errors));
        }
        return contract;
    }

    // ---------------------------------------------------------------
    // Token kinds
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
    private static final int TOK_PLUSPLUS = 33;
    private static final int TOK_MINUSMINUS = 34;
    private static final int TOK_PLUSEQ = 35;
    private static final int TOK_MINUSEQ = 36;
    private static final int TOK_STAREQ = 37;
    private static final int TOK_SLASHEQ = 38;
    private static final int TOK_PERCENTEQ = 39;
    private static final int TOK_QUESTION = 40;
    private static final int TOK_LSHIFT = 41;
    private static final int TOK_RSHIFT = 42;
    private static final int TOK_HEXSTRING = 43;

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
    // Solidity type mapping
    // ---------------------------------------------------------------

    /**
     * Names recognised as Rúnar primitives. Mirrors the Python
     * {@code PRIMITIVE_TYPE_NAMES} set, which is consulted only for the
     * "is this token a type-start?" lookahead — so {@code void} (which
     * the Java enum doesn't model) still belongs here.
     */
    private static final Set<String> RUNAR_PRIMITIVE_NAMES = Set.of(
        "bigint", "boolean", "ByteString", "PubKey", "Sig", "Sha256",
        "Ripemd160", "Addr", "SigHashPreimage", "RabinSig", "RabinPubKey",
        "void", "Point", "P256Point", "P384Point"
    );

    private static TypeNode parseSolType(String name) {
        switch (name) {
            case "uint":
            case "uint256":
            case "int":
            case "int256":
                return new PrimitiveType(PrimitiveTypeName.BIGINT);
            case "bool":
                return new PrimitiveType(PrimitiveTypeName.BOOLEAN);
            case "bytes":
                return new PrimitiveType(PrimitiveTypeName.BYTE_STRING);
            case "address":
                return new PrimitiveType(PrimitiveTypeName.ADDR);
            default:
                if (RUNAR_PRIMITIVE_NAMES.contains(name)) {
                    try {
                        return new PrimitiveType(PrimitiveTypeName.fromCanonical(name));
                    } catch (IllegalArgumentException ignored) {
                        // "void" is in the primitive set for type-start
                        // lookahead but not in the enum — fall through to
                        // CustomType, matching how the Python reference
                        // would treat it after _parse_sol_type if no
                        // matching record existed.
                        return new CustomType(name);
                    }
                }
                return new CustomType(name);
        }
    }

    private static boolean isKnownSolType(String name) {
        return parseSolType(name) instanceof PrimitiveType;
    }

    // ---------------------------------------------------------------
    // Tokenizer
    // ---------------------------------------------------------------

    private static boolean isHexDigit(char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    }

    private static boolean isIdentStart(char ch) {
        return Character.isLetter(ch) || ch == '_' || ch == '$';
    }

    private static boolean isIdentPart(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '_' || ch == '$';
    }

    private static List<Token> tokenize(String source) {
        List<Token> tokens = new ArrayList<>();
        int line = 1;
        int col = 0;
        int i = 0;
        int n = source.length();

        while (i < n) {
            char ch = source.charAt(i);

            // Newlines
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

            // Whitespace
            if (ch == ' ' || ch == '\t') {
                i++;
                col++;
                continue;
            }

            // Single-line comment //
            if (i + 1 < n && ch == '/' && source.charAt(i + 1) == '/') {
                while (i < n && source.charAt(i) != '\n') {
                    i++;
                }
                continue;
            }

            // Multi-line comment /* ... */
            if (i + 1 < n && ch == '/' && source.charAt(i + 1) == '*') {
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

            // String literals (single or double quoted)
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

            // Numbers (and hex byte string literals: 0x... -> ByteString)
            if (ch >= '0' && ch <= '9') {
                if (ch == '0' && i + 1 < n && (source.charAt(i + 1) == 'x' || source.charAt(i + 1) == 'X')) {
                    i += 2;
                    col += 2;
                    int hexStart = i;
                    while (i < n && isHexDigit(source.charAt(i))) {
                        i++;
                        col++;
                    }
                    tokens.add(new Token(TOK_HEXSTRING, source.substring(hexStart, i), line, startCol));
                    continue;
                }
                int start = i;
                while (i < n && source.charAt(i) >= '0' && source.charAt(i) <= '9') {
                    i++;
                    col++;
                }
                // Skip trailing 'n' for bigint literals (TS-style)
                if (i < n && source.charAt(i) == 'n') {
                    i++;
                    col++;
                }
                tokens.add(new Token(TOK_NUMBER, source.substring(start, i), line, startCol));
                continue;
            }

            // Identifiers and keywords
            if (isIdentStart(ch)) {
                int start = i;
                while (i < n && isIdentPart(source.charAt(i))) {
                    i++;
                    col++;
                }
                tokens.add(new Token(TOK_IDENT, source.substring(start, i), line, startCol));
                continue;
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

            // Skip unknown characters
            i++;
            col++;
        }

        tokens.add(new Token(TOK_EOF, "", line, col));
        return tokens;
    }

    private static final Map<String, Integer> TWO_CHAR_OPS;
    static {
        Map<String, Integer> m = new HashMap<>();
        m.put("==", TOK_EQEQ);
        m.put("!=", TOK_NOTEQ);
        m.put("<=", TOK_LTEQ);
        m.put(">=", TOK_GTEQ);
        m.put("&&", TOK_AMPAMP);
        m.put("||", TOK_PIPEPIPE);
        m.put("++", TOK_PLUSPLUS);
        m.put("--", TOK_MINUSMINUS);
        m.put("+=", TOK_PLUSEQ);
        m.put("-=", TOK_MINUSEQ);
        m.put("*=", TOK_STAREQ);
        m.put("/=", TOK_SLASHEQ);
        m.put("%=", TOK_PERCENTEQ);
        m.put("<<", TOK_LSHIFT);
        m.put(">>", TOK_RSHIFT);
        TWO_CHAR_OPS = Map.copyOf(m);
    }

    private static final Map<Character, Integer> ONE_CHAR_OPS;
    static {
        Map<Character, Integer> m = new HashMap<>();
        m.put('{', TOK_LBRACE);
        m.put('}', TOK_RBRACE);
        m.put('(', TOK_LPAREN);
        m.put(')', TOK_RPAREN);
        m.put('[', TOK_LBRACKET);
        m.put(']', TOK_RBRACKET);
        m.put(';', TOK_SEMICOLON);
        m.put(',', TOK_COMMA);
        m.put('.', TOK_DOT);
        m.put(':', TOK_COLON);
        m.put('=', TOK_ASSIGN);
        m.put('<', TOK_LT);
        m.put('>', TOK_GT);
        m.put('+', TOK_PLUS);
        m.put('-', TOK_MINUS);
        m.put('*', TOK_STAR);
        m.put('/', TOK_SLASH);
        m.put('%', TOK_PERCENT);
        m.put('!', TOK_BANG);
        m.put('~', TOK_TILDE);
        m.put('&', TOK_AMP);
        m.put('|', TOK_PIPE);
        m.put('^', TOK_CARET);
        m.put('?', TOK_QUESTION);
        ONE_CHAR_OPS = Map.copyOf(m);
    }

    // ---------------------------------------------------------------
    // Parser core
    // ---------------------------------------------------------------

    private static final class Parser {
        final String fileName;
        List<Token> tokens = new ArrayList<>();
        int pos = 0;
        final List<String> errors = new ArrayList<>();

        Parser(String fileName) {
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
                addError("line " + tok.line + ": expected token kind " + kind
                    + ", got " + tok.kind + " ('" + tok.value + "')");
            }
            return tok;
        }

        Token expectIdent(String value) {
            Token tok = advance();
            if (tok.kind != TOK_IDENT || !tok.value.equals(value)) {
                addError("line " + tok.line + ": expected '" + value + "', got '" + tok.value + "'");
            }
            return tok;
        }

        boolean check(int kind) {
            return peek().kind == kind;
        }

        boolean checkIdent(String value) {
            Token tok = peek();
            return tok.kind == TOK_IDENT && tok.value.equals(value);
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
            Token tok = peek();
            return new SourceLocation(fileName, tok.line, tok.col);
        }

        // ---- Contract parsing -----------------------------------------

        ContractNode parseContract() throws ParseException {
            // Skip pragma
            if (checkIdent("pragma")) {
                while (!check(TOK_SEMICOLON) && !check(TOK_EOF)) {
                    advance();
                }
                match(TOK_SEMICOLON);
            }

            // Skip import statements
            while (checkIdent("import")) {
                while (!check(TOK_SEMICOLON) && !check(TOK_EOF)) {
                    advance();
                }
                match(TOK_SEMICOLON);
            }

            if (!matchIdent("contract")) {
                throw new ParseException("expected 'contract' keyword");
            }

            Token nameTok = expect(TOK_IDENT);
            String contractName = nameTok.value;

            String parentClassName = "SmartContract";
            if (matchIdent("is")) {
                Token parentTok = expect(TOK_IDENT);
                parentClassName = parentTok.value;
            }

            ParentClass parentClass;
            switch (parentClassName) {
                case "SmartContract":
                    parentClass = ParentClass.SMART_CONTRACT;
                    break;
                case "StatefulSmartContract":
                    parentClass = ParentClass.STATEFUL_SMART_CONTRACT;
                    break;
                default:
                    throw new ParseException("unknown parent class: " + parentClassName);
            }

            expect(TOK_LBRACE);

            List<PropertyNode> properties = new ArrayList<>();
            MethodNode constructor = null;
            List<MethodNode> methods = new ArrayList<>();

            while (!check(TOK_RBRACE) && !check(TOK_EOF)) {
                if (checkIdent("function")) {
                    methods.add(parseFunction());
                } else if (checkIdent("constructor")) {
                    constructor = parseSolConstructor(properties);
                } else {
                    PropertyNode prop = parseSolProperty();
                    if (prop != null) {
                        properties.add(prop);
                    }
                }
            }

            expect(TOK_RBRACE);

            if (constructor == null) {
                constructor = new MethodNode(
                    "constructor",
                    List.of(),
                    List.of(),
                    Visibility.PUBLIC,
                    new SourceLocation(fileName, 1, 0)
                );
            }

            return new ContractNode(
                contractName,
                parentClass,
                properties,
                constructor,
                methods,
                fileName
            );
        }

        // ---- Property: Type [immutable] name [= initializer]; ---------

        PropertyNode parseSolProperty() {
            SourceLocation location = loc();

            Token typeTok = advance();
            if (typeTok.kind != TOK_IDENT) {
                return null;
            }

            String typeName = typeTok.value;

            boolean isReadonly = false;
            if (checkIdent("immutable")) {
                advance();
                isReadonly = true;
            }

            Token nameTok = expect(TOK_IDENT);
            String propName = nameTok.value;

            Expression initializer = null;
            if (match(TOK_ASSIGN)) {
                initializer = parseExpression();
            }

            expect(TOK_SEMICOLON);

            return new PropertyNode(
                propName,
                parseSolType(typeName),
                isReadonly,
                initializer,
                location,
                null
            );
        }

        // ---- Constructor: constructor(Type _name, ...) { ... } -------

        MethodNode parseSolConstructor(List<PropertyNode> properties) {
            SourceLocation location = loc();
            expectIdent("constructor");
            List<ParamNode> params = parseSolParams();
            List<Statement> body = parseSolBlock();

            List<Statement> constructorBody = new ArrayList<>();

            // super(...) call with all param names
            List<Expression> superArgs = new ArrayList<>();
            for (ParamNode p : params) {
                superArgs.add(new Identifier(p.name()));
            }
            constructorBody.add(new ExpressionStatement(
                new CallExpr(new Identifier("super"), superArgs),
                location
            ));

            // Build a rename map for _-prefixed params (parseSolParams strips
            // the leading underscore, but the body was parsed with the
            // original spellings — fix them up here).
            Map<String, String> renameMap = new HashMap<>();
            for (ParamNode p : params) {
                renameMap.put("_" + p.name(), p.name());
            }

            Set<String> propNames = new HashSet<>();
            for (PropertyNode pn : properties) {
                propNames.add(pn.name());
            }

            for (Statement stmt : body) {
                Statement s = stmt;
                if (!renameMap.isEmpty()) {
                    s = renameInStmt(s, renameMap);
                }
                // Convert bare property-name assignments to this.property form
                if (s instanceof AssignmentStatement assign
                    && assign.target() instanceof Identifier id
                    && propNames.contains(id.name())) {
                    s = new AssignmentStatement(
                        new PropertyAccessExpr(id.name()),
                        assign.value(),
                        assign.sourceLocation()
                    );
                }
                constructorBody.add(s);
            }

            return new MethodNode(
                "constructor",
                params,
                constructorBody,
                Visibility.PUBLIC,
                location
            );
        }

        // ---- Function: function name(...) [public|private] { ... } ---

        MethodNode parseFunction() {
            SourceLocation location = loc();
            expectIdent("function");

            Token nameTok = expect(TOK_IDENT);
            String name = nameTok.value;

            List<ParamNode> params = parseSolParams();

            Visibility visibility = Visibility.PRIVATE;
            while (checkIdent("public") || checkIdent("private")
                || checkIdent("external") || checkIdent("internal")
                || checkIdent("view") || checkIdent("pure")
                || checkIdent("returns") || checkIdent("payable")) {
                Token tok = advance();
                if (tok.value.equals("public") || tok.value.equals("external")) {
                    visibility = Visibility.PUBLIC;
                }
                if (tok.value.equals("returns")) {
                    if (check(TOK_LPAREN)) {
                        advance();
                        int depth = 1;
                        while (depth > 0 && !check(TOK_EOF)) {
                            if (check(TOK_LPAREN)) depth++;
                            if (check(TOK_RPAREN)) depth--;
                            advance();
                        }
                    }
                }
            }

            List<Statement> body = parseSolBlock();

            return new MethodNode(name, params, body, visibility, location);
        }

        // ---- Parameter list -------------------------------------------

        List<ParamNode> parseSolParams() {
            expect(TOK_LPAREN);
            List<ParamNode> params = new ArrayList<>();

            while (!check(TOK_RPAREN) && !check(TOK_EOF)) {
                Token typeTok = expect(TOK_IDENT);
                String typeName = typeTok.value;

                while (checkIdent("memory") || checkIdent("storage") || checkIdent("calldata")) {
                    advance();
                }

                Token nameTok = expect(TOK_IDENT);
                String paramName = nameTok.value;
                if (paramName.startsWith("_")) {
                    paramName = paramName.substring(1);
                }

                params.add(new ParamNode(paramName, parseSolType(typeName)));

                if (!match(TOK_COMMA)) {
                    break;
                }
            }

            expect(TOK_RPAREN);
            return params;
        }

        // ---- Block ----------------------------------------------------

        List<Statement> parseSolBlock() {
            expect(TOK_LBRACE);
            List<Statement> stmts = new ArrayList<>();
            while (!check(TOK_RBRACE) && !check(TOK_EOF)) {
                Statement s = parseSolStatement();
                if (s != null) {
                    stmts.add(s);
                }
            }
            expect(TOK_RBRACE);
            return stmts;
        }

        // ---- Statements -----------------------------------------------

        Statement parseSolStatement() {
            SourceLocation location = loc();

            if (checkIdent("require")) {
                return parseRequire(location);
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
            if (checkIdent("let")) {
                advance();
                return parseVarDecl(location);
            }
            if (peek().kind == TOK_IDENT && isTypeStart()) {
                return parseVarDecl(location);
            }

            return parseExprStatement(location);
        }

        boolean isTypeStart() {
            if (pos + 1 >= tokens.size()) {
                return false;
            }
            Token nextTok = tokens.get(pos + 1);
            if (nextTok.kind != TOK_IDENT) {
                return false;
            }
            String name = peek().value;
            if (RUNAR_PRIMITIVE_NAMES.contains(name) || isKnownSolType(name)) {
                return true;
            }
            if (!name.isEmpty() && Character.isUpperCase(name.charAt(0))) {
                return true;
            }
            switch (name) {
                case "uint":
                case "uint256":
                case "int":
                case "int256":
                case "bool":
                case "bytes":
                case "address":
                case "string":
                    return true;
                default:
                    return false;
            }
        }

        Statement parseRequire(SourceLocation loc) {
            expectIdent("require");
            expect(TOK_LPAREN);
            Expression expr = parseExpression();
            if (match(TOK_COMMA)) {
                parseExpression();
            }
            expect(TOK_RPAREN);
            expect(TOK_SEMICOLON);
            return new ExpressionStatement(
                new CallExpr(new Identifier("assert"), List.of(expr)),
                loc
            );
        }

        Statement parseIf(SourceLocation loc) {
            expectIdent("if");
            expect(TOK_LPAREN);
            Expression condition = parseExpression();
            expect(TOK_RPAREN);

            List<Statement> thenBlock = parseSolBlock();

            List<Statement> elseBlock = null;
            if (matchIdent("else")) {
                if (checkIdent("if")) {
                    Statement elseStmt = parseIf(loc());
                    elseBlock = new ArrayList<>();
                    elseBlock.add(elseStmt);
                } else {
                    elseBlock = parseSolBlock();
                }
            }

            // Match the Python reference: an `if` without an else has
            // else_=[] (empty list, not None). The Java AST treats null
            // as "no else"; mapping empty-list -> empty-list keeps the
            // shape parallel for callers.
            if (elseBlock == null) {
                elseBlock = List.of();
            }

            return new IfStatement(condition, thenBlock, elseBlock, loc);
        }

        Statement parseFor(SourceLocation loc) {
            expectIdent("for");
            expect(TOK_LPAREN);

            VariableDeclStatement initStmt;
            if (isTypeStart() || checkIdent("uint") || checkIdent("int")) {
                Token typeTok = advance();
                Token nameTok = expect(TOK_IDENT);
                expect(TOK_ASSIGN);
                Expression initExpr = parseExpression();
                expect(TOK_SEMICOLON);
                initStmt = new VariableDeclStatement(
                    nameTok.value,
                    parseSolType(typeTok.value),
                    initExpr,
                    loc
                );
            } else {
                expect(TOK_SEMICOLON);
                initStmt = new VariableDeclStatement(
                    "_i",
                    null,
                    new BigIntLiteral(BigInteger.ZERO),
                    loc
                );
            }

            Expression condition = parseExpression();
            expect(TOK_SEMICOLON);

            Expression updateExpr = parseExpression();
            Statement update = new ExpressionStatement(updateExpr, loc);

            expect(TOK_RPAREN);

            List<Statement> body = parseSolBlock();

            return new ForStatement(initStmt, condition, update, body, loc);
        }

        Statement parseReturn(SourceLocation loc) {
            expectIdent("return");
            Expression value = null;
            if (!check(TOK_SEMICOLON)) {
                value = parseExpression();
            }
            expect(TOK_SEMICOLON);
            return new ReturnStatement(value, loc);
        }

        Statement parseVarDecl(SourceLocation loc) {
            Token typeTok = advance();
            String typeName = typeTok.value;

            Token nameTok = expect(TOK_IDENT);
            String varName = nameTok.value;

            Expression init;
            if (match(TOK_ASSIGN)) {
                init = parseExpression();
            } else {
                init = new BigIntLiteral(BigInteger.ZERO);
            }

            expect(TOK_SEMICOLON);

            return new VariableDeclStatement(varName, parseSolType(typeName), init, loc);
        }

        Statement parseExprStatement(SourceLocation loc) {
            Expression expr = parseExpression();
            if (expr == null) {
                advance();
                return null;
            }

            if (match(TOK_ASSIGN)) {
                Expression value = parseExpression();
                expect(TOK_SEMICOLON);
                return new AssignmentStatement(expr, value, loc);
            }

            // Compound assignments: +=, -=, *=, /=, %=
            int[] kinds = {TOK_PLUSEQ, TOK_MINUSEQ, TOK_STAREQ, TOK_SLASHEQ, TOK_PERCENTEQ};
            Expression.BinaryOp[] ops = {
                Expression.BinaryOp.ADD, Expression.BinaryOp.SUB,
                Expression.BinaryOp.MUL, Expression.BinaryOp.DIV,
                Expression.BinaryOp.MOD
            };
            for (int idx = 0; idx < kinds.length; idx++) {
                if (match(kinds[idx])) {
                    Expression right = parseExpression();
                    expect(TOK_SEMICOLON);
                    Expression value = new BinaryExpr(ops[idx], expr, right);
                    return new AssignmentStatement(expr, value, loc);
                }
            }

            expect(TOK_SEMICOLON);
            return new ExpressionStatement(expr, loc);
        }

        // ---- Expression parsing (precedence climbing) -----------------

        Expression parseExpression() {
            return parseTernary();
        }

        Expression parseTernary() {
            Expression expr = parseOr();
            if (match(TOK_QUESTION)) {
                Expression consequent = parseExpression();
                expect(TOK_COLON);
                Expression alternate = parseExpression();
                return new TernaryExpr(expr, consequent, alternate);
            }
            return expr;
        }

        Expression parseOr() {
            Expression left = parseAnd();
            while (match(TOK_PIPEPIPE)) {
                Expression right = parseAnd();
                left = new BinaryExpr(Expression.BinaryOp.OR, left, right);
            }
            return left;
        }

        Expression parseAnd() {
            Expression left = parseBitwiseOr();
            while (match(TOK_AMPAMP)) {
                Expression right = parseBitwiseOr();
                left = new BinaryExpr(Expression.BinaryOp.AND, left, right);
            }
            return left;
        }

        Expression parseBitwiseOr() {
            Expression left = parseBitwiseXor();
            while (match(TOK_PIPE)) {
                Expression right = parseBitwiseXor();
                left = new BinaryExpr(Expression.BinaryOp.BIT_OR, left, right);
            }
            return left;
        }

        Expression parseBitwiseXor() {
            Expression left = parseBitwiseAnd();
            while (match(TOK_CARET)) {
                Expression right = parseBitwiseAnd();
                left = new BinaryExpr(Expression.BinaryOp.BIT_XOR, left, right);
            }
            return left;
        }

        Expression parseBitwiseAnd() {
            Expression left = parseEquality();
            while (match(TOK_AMP)) {
                Expression right = parseEquality();
                left = new BinaryExpr(Expression.BinaryOp.BIT_AND, left, right);
            }
            return left;
        }

        Expression parseEquality() {
            Expression left = parseComparison();
            while (true) {
                if (match(TOK_EQEQ)) {
                    Expression right = parseComparison();
                    left = new BinaryExpr(Expression.BinaryOp.EQ, left, right);
                } else if (match(TOK_NOTEQ)) {
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

        Expression parseShift() {
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

        Expression parseAdditive() {
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

        Expression parseMultiplicative() {
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

        Expression parseUnary() {
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

        Expression parsePostfix() {
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
                            expr = new CallExpr(new MemberExpr(expr, propName), args);
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
                } else if (match(TOK_PLUSPLUS)) {
                    expr = new IncrementExpr(expr, false);
                } else if (match(TOK_MINUSMINUS)) {
                    expr = new DecrementExpr(expr, false);
                } else {
                    break;
                }
            }
            return expr;
        }

        Expression parsePrimary() {
            Token tok = peek();

            if (tok.kind == TOK_NUMBER) {
                advance();
                return parseSolNumber(tok.value);
            }

            if (tok.kind == TOK_HEXSTRING) {
                advance();
                return new ByteStringLiteral(tok.value);
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

            addError("line " + tok.line + ": unexpected token '" + tok.value + "'");
            advance();
            return new BigIntLiteral(BigInteger.ZERO);
        }

        List<Expression> parseCallArgs() {
            expect(TOK_LPAREN);
            List<Expression> args = new ArrayList<>();
            while (!check(TOK_RPAREN) && !check(TOK_EOF)) {
                args.add(parseExpression());
                if (!match(TOK_COMMA)) {
                    break;
                }
            }
            expect(TOK_RPAREN);
            return args;
        }
    }

    // ---------------------------------------------------------------
    // Number parsing
    // ---------------------------------------------------------------

    private static Expression parseSolNumber(String s) {
        String trimmed = s;
        if (trimmed.endsWith("n")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        BigInteger val;
        try {
            if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                val = new BigInteger(trimmed.substring(2), 16);
            } else if (trimmed.startsWith("0o") || trimmed.startsWith("0O")) {
                val = new BigInteger(trimmed.substring(2), 8);
            } else if (trimmed.startsWith("0b") || trimmed.startsWith("0B")) {
                val = new BigInteger(trimmed.substring(2), 2);
            } else {
                val = new BigInteger(trimmed);
            }
        } catch (NumberFormatException nfe) {
            val = BigInteger.ZERO;
        }
        return new BigIntLiteral(val);
    }

    // ---------------------------------------------------------------
    // Constructor identifier renaming
    // ---------------------------------------------------------------

    private static Expression renameInExpr(Expression expr, Map<String, String> renameMap) {
        if (expr == null) return null;
        if (expr instanceof Identifier id) {
            String newName = renameMap.get(id.name());
            return newName != null ? new Identifier(newName) : id;
        }
        if (expr instanceof BinaryExpr be) {
            return new BinaryExpr(be.op(),
                renameInExpr(be.left(), renameMap),
                renameInExpr(be.right(), renameMap));
        }
        if (expr instanceof UnaryExpr ue) {
            return new UnaryExpr(ue.op(), renameInExpr(ue.operand(), renameMap));
        }
        if (expr instanceof CallExpr ce) {
            List<Expression> newArgs = new ArrayList<>(ce.args().size());
            for (Expression a : ce.args()) {
                newArgs.add(renameInExpr(a, renameMap));
            }
            return new CallExpr(renameInExpr(ce.callee(), renameMap), newArgs);
        }
        if (expr instanceof MemberExpr me) {
            return new MemberExpr(renameInExpr(me.object(), renameMap), me.property());
        }
        if (expr instanceof TernaryExpr te) {
            return new TernaryExpr(
                renameInExpr(te.condition(), renameMap),
                renameInExpr(te.consequent(), renameMap),
                renameInExpr(te.alternate(), renameMap)
            );
        }
        if (expr instanceof IndexAccessExpr ia) {
            return new IndexAccessExpr(renameInExpr(ia.object(), renameMap), renameInExpr(ia.index(), renameMap));
        }
        if (expr instanceof IncrementExpr ie) {
            return new IncrementExpr(renameInExpr(ie.operand(), renameMap), ie.prefix());
        }
        if (expr instanceof DecrementExpr de) {
            return new DecrementExpr(renameInExpr(de.operand(), renameMap), de.prefix());
        }
        // PropertyAccessExpr, literals: nothing to rename
        return expr;
    }

    private static Statement renameInStmt(Statement stmt, Map<String, String> renameMap) {
        if (renameMap.isEmpty()) return stmt;
        if (stmt instanceof AssignmentStatement as) {
            return new AssignmentStatement(
                renameInExpr(as.target(), renameMap),
                renameInExpr(as.value(), renameMap),
                as.sourceLocation()
            );
        }
        if (stmt instanceof ExpressionStatement es) {
            return new ExpressionStatement(renameInExpr(es.expression(), renameMap), es.sourceLocation());
        }
        if (stmt instanceof VariableDeclStatement vd) {
            return new VariableDeclStatement(
                vd.name(),
                vd.type(),
                vd.init() != null ? renameInExpr(vd.init(), renameMap) : null,
                vd.sourceLocation()
            );
        }
        if (stmt instanceof IfStatement ifs) {
            List<Statement> newThen = new ArrayList<>(ifs.thenBody().size());
            for (Statement s : ifs.thenBody()) newThen.add(renameInStmt(s, renameMap));
            List<Statement> newElse = null;
            if (ifs.elseBody() != null) {
                newElse = new ArrayList<>(ifs.elseBody().size());
                for (Statement s : ifs.elseBody()) newElse.add(renameInStmt(s, renameMap));
            }
            return new IfStatement(
                renameInExpr(ifs.condition(), renameMap),
                newThen,
                newElse,
                ifs.sourceLocation()
            );
        }
        if (stmt instanceof ForStatement fs) {
            VariableDeclStatement newInit = fs.init() != null
                ? (VariableDeclStatement) renameInStmt(fs.init(), renameMap)
                : null;
            Expression newCond = fs.condition() != null
                ? renameInExpr(fs.condition(), renameMap)
                : null;
            Statement newUpdate = fs.update() != null
                ? renameInStmt(fs.update(), renameMap)
                : null;
            List<Statement> newBody = new ArrayList<>(fs.body().size());
            for (Statement s : fs.body()) newBody.add(renameInStmt(s, renameMap));
            return new ForStatement(newInit, newCond, newUpdate, newBody, fs.sourceLocation());
        }
        if (stmt instanceof ReturnStatement rs) {
            return new ReturnStatement(
                rs.value() != null ? renameInExpr(rs.value(), renameMap) : null,
                rs.sourceLocation()
            );
        }
        return stmt;
    }

    // ---------------------------------------------------------------
    // Bare-identifier rewrite: foo -> this.foo for property names,
    // bareCall(...) -> this.bareCall(...) for sibling-method names.
    // ---------------------------------------------------------------

    private static Expression rewriteBareProps(
        Expression expr,
        Set<String> propNames,
        Set<String> paramNames,
        Set<String> methodNames
    ) {
        if (expr == null) return null;
        if (expr instanceof Identifier id) {
            if (propNames.contains(id.name()) && !paramNames.contains(id.name())) {
                return new PropertyAccessExpr(id.name());
            }
            return id;
        }
        if (expr instanceof BinaryExpr be) {
            return new BinaryExpr(
                be.op(),
                rewriteBareProps(be.left(), propNames, paramNames, methodNames),
                rewriteBareProps(be.right(), propNames, paramNames, methodNames)
            );
        }
        if (expr instanceof UnaryExpr ue) {
            return new UnaryExpr(ue.op(), rewriteBareProps(ue.operand(), propNames, paramNames, methodNames));
        }
        if (expr instanceof CallExpr ce) {
            // Bare method call: foo(args) -> this.foo(args)
            if (ce.callee() instanceof Identifier callId
                && methodNames.contains(callId.name())) {
                List<Expression> newArgs = new ArrayList<>(ce.args().size());
                for (Expression a : ce.args()) {
                    newArgs.add(rewriteBareProps(a, propNames, paramNames, methodNames));
                }
                return new CallExpr(
                    new MemberExpr(new Identifier("this"), callId.name()),
                    newArgs
                );
            }
            List<Expression> newArgs = new ArrayList<>(ce.args().size());
            for (Expression a : ce.args()) {
                newArgs.add(rewriteBareProps(a, propNames, paramNames, methodNames));
            }
            return new CallExpr(rewriteBareProps(ce.callee(), propNames, paramNames, methodNames), newArgs);
        }
        if (expr instanceof TernaryExpr te) {
            return new TernaryExpr(
                rewriteBareProps(te.condition(), propNames, paramNames, methodNames),
                rewriteBareProps(te.consequent(), propNames, paramNames, methodNames),
                rewriteBareProps(te.alternate(), propNames, paramNames, methodNames)
            );
        }
        if (expr instanceof IndexAccessExpr ia) {
            return new IndexAccessExpr(
                rewriteBareProps(ia.object(), propNames, paramNames, methodNames),
                rewriteBareProps(ia.index(), propNames, paramNames, methodNames)
            );
        }
        // MemberExpr, PropertyAccessExpr, literals, increment/decrement: leave alone
        return expr;
    }

    private static Statement rewriteStmtProps(
        Statement stmt,
        Set<String> propNames,
        Set<String> paramNames,
        Set<String> methodNames
    ) {
        if (stmt instanceof ExpressionStatement es) {
            return new ExpressionStatement(
                rewriteBareProps(es.expression(), propNames, paramNames, methodNames),
                es.sourceLocation()
            );
        }
        if (stmt instanceof VariableDeclStatement vd) {
            return new VariableDeclStatement(
                vd.name(),
                vd.type(),
                vd.init() != null ? rewriteBareProps(vd.init(), propNames, paramNames, methodNames) : null,
                vd.sourceLocation()
            );
        }
        if (stmt instanceof AssignmentStatement as) {
            return new AssignmentStatement(
                rewriteBareProps(as.target(), propNames, paramNames, methodNames),
                rewriteBareProps(as.value(), propNames, paramNames, methodNames),
                as.sourceLocation()
            );
        }
        if (stmt instanceof ReturnStatement rs) {
            return new ReturnStatement(
                rs.value() != null ? rewriteBareProps(rs.value(), propNames, paramNames, methodNames) : null,
                rs.sourceLocation()
            );
        }
        if (stmt instanceof IfStatement ifs) {
            List<Statement> newThen = rewriteStmtBlock(ifs.thenBody(), propNames, new HashSet<>(paramNames), methodNames);
            List<Statement> newElse = ifs.elseBody() != null
                ? rewriteStmtBlock(ifs.elseBody(), propNames, new HashSet<>(paramNames), methodNames)
                : List.of();
            return new IfStatement(
                rewriteBareProps(ifs.condition(), propNames, paramNames, methodNames),
                newThen,
                newElse,
                ifs.sourceLocation()
            );
        }
        if (stmt instanceof ForStatement fs) {
            Set<String> forParams = new HashSet<>(paramNames);
            VariableDeclStatement newInit = null;
            if (fs.init() != null) {
                newInit = (VariableDeclStatement) rewriteStmtProps(fs.init(), propNames, forParams, methodNames);
                forParams.add(fs.init().name());
            }
            Expression newCond = fs.condition() != null
                ? rewriteBareProps(fs.condition(), propNames, forParams, methodNames)
                : null;
            Statement newUpdate = fs.update() != null
                ? rewriteStmtProps(fs.update(), propNames, forParams, methodNames)
                : null;
            List<Statement> newBody = rewriteStmtBlock(fs.body(), propNames, new HashSet<>(forParams), methodNames);
            return new ForStatement(newInit, newCond, newUpdate, newBody, fs.sourceLocation());
        }
        return stmt;
    }

    private static List<Statement> rewriteStmtBlock(
        List<Statement> stmts,
        Set<String> propNames,
        Set<String> paramNames,
        Set<String> methodNames
    ) {
        List<Statement> result = new ArrayList<>(stmts.size());
        for (Statement s : stmts) {
            Statement rewritten = rewriteStmtProps(s, propNames, paramNames, methodNames);
            result.add(rewritten);
            if (s instanceof VariableDeclStatement vd) {
                paramNames.add(vd.name());
            }
        }
        return result;
    }

    private static void rewriteContractProps(ContractNode contract) {
        if (contract == null) return;
        Set<String> propNames = new HashSet<>();
        for (PropertyNode p : contract.properties()) {
            propNames.add(p.name());
        }
        Set<String> methodNames = new HashSet<>();
        for (MethodNode m : contract.methods()) {
            methodNames.add(m.name());
        }
        if (propNames.isEmpty() && methodNames.isEmpty()) {
            return;
        }
        for (MethodNode method : contract.methods()) {
            Set<String> paramNames = new HashSet<>();
            for (ParamNode p : method.params()) {
                paramNames.add(p.name());
            }
            List<Statement> rewritten = rewriteStmtBlock(method.body(), propNames, paramNames, methodNames);
            // Replace body in-place. MethodNode is a record so we can't
            // mutate `body` directly; we mutate the list contents to
            // preserve identity for downstream consumers that may have
            // captured the list reference.
            method.body().clear();
            method.body().addAll(rewritten);
        }
    }

    // ---------------------------------------------------------------
    // Exception
    // ---------------------------------------------------------------

    /** Checked exception for parse-time problems. */
    public static class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
    }
}
