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
 * Hand-rolled tokenizer + recursive-descent parser for {@code .runar.zig}
 * source. Mirrors {@code compilers/python/runar_compiler/frontend/parser_zig.py}
 * (the canonical reference implementation) so all six compilers produce the
 * same Rúnar AST for the same input.
 *
 * <p>Zig surface accepted:
 * <ul>
 *   <li>{@code const runar = @import("runar");}</li>
 *   <li>{@code pub const Name = struct { ... };} for the contract</li>
 *   <li>{@code pub const Contract = runar.SmartContract;} or
 *       {@code runar.StatefulSmartContract;} for the parent class</li>
 *   <li>Fields: {@code name: runar.Type [= default],}</li>
 *   <li>Methods: {@code [pub] fn name(self: *Name, ...) ReturnType { ... }}</li>
 *   <li>Constructor: {@code pub fn init(...) Name { return .{ .field = value }; }}</li>
 *   <li>Statements: {@code if/else}, {@code while}, {@code return},
 *       {@code const}/{@code var}, assignments, expressions, {@code _ = expr;}</li>
 *   <li>Operators: arithmetic, bitwise, shift, comparison, logical
 *       ({@code and}/{@code or} mapped to {@code &&}/{@code ||})</li>
 *   <li>Zig builtins: {@code @divTrunc}, {@code @mod}, {@code @shlExact},
 *       {@code @shrExact}, {@code @intCast}, {@code @truncate}, {@code @as},
 *       {@code @import}, {@code @embedFile}</li>
 * </ul>
 */
public final class ZigParser {

    private ZigParser() {}

    /** Parse a {@code .runar.zig} source into a Rúnar contract AST. */
    public static ContractNode parse(String source, String filename) throws ParseException {
        List<Token> tokens = tokenize(source);
        State s = new State(tokens, filename);
        return s.parseTopLevel();
    }

    /** Checked exception raised on parse-time problems. */
    public static final class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
    }

    // ===================================================================
    // Tokens
    // ===================================================================

    enum Kind {
        EOF, IDENT, NUMBER, STRING,
        LPAREN, RPAREN, LBRACE, RBRACE, LBRACKET, RBRACKET,
        SEMICOLON, COMMA, DOT, COLON, AT,
        PLUS, MINUS, STAR, SLASH, PERCENT,
        AMP, PIPE, CARET, TILDE, BANG,
        EQEQ, NOTEQ, LT, LTEQ, GT, GTEQ,
        AMPAMP, PIPEPIPE, LSHIFT, RSHIFT,
        ASSIGN, PLUSEQ, MINUSEQ, STAREQ, SLASHEQ, PERCENTEQ,
        // Keywords
        PUB, CONST, VAR, FN, STRUCT, IF, ELSE, FOR, WHILE, RETURN, TRUE, FALSE, VOID
    }

    private static final class Token {
        final Kind kind;
        final String value;
        final int line;
        final int col;

        Token(Kind kind, String value, int line, int col) {
            this.kind = kind;
            this.value = value;
            this.line = line;
            this.col = col;
        }
    }

    private static final Map<String, Kind> KEYWORDS = new HashMap<>();
    static {
        KEYWORDS.put("pub", Kind.PUB);
        KEYWORDS.put("const", Kind.CONST);
        KEYWORDS.put("var", Kind.VAR);
        KEYWORDS.put("fn", Kind.FN);
        KEYWORDS.put("struct", Kind.STRUCT);
        KEYWORDS.put("if", Kind.IF);
        KEYWORDS.put("else", Kind.ELSE);
        KEYWORDS.put("for", Kind.FOR);
        KEYWORDS.put("while", Kind.WHILE);
        KEYWORDS.put("return", Kind.RETURN);
        KEYWORDS.put("true", Kind.TRUE);
        KEYWORDS.put("false", Kind.FALSE);
        KEYWORDS.put("void", Kind.VOID);
        KEYWORDS.put("and", Kind.AMPAMP);
        KEYWORDS.put("or", Kind.PIPEPIPE);
    }

    private static final Map<Kind, Expression.BinaryOp> COMPOUND_OPS = new HashMap<>();
    static {
        COMPOUND_OPS.put(Kind.PLUSEQ, Expression.BinaryOp.ADD);
        COMPOUND_OPS.put(Kind.MINUSEQ, Expression.BinaryOp.SUB);
        COMPOUND_OPS.put(Kind.STAREQ, Expression.BinaryOp.MUL);
        COMPOUND_OPS.put(Kind.SLASHEQ, Expression.BinaryOp.DIV);
        COMPOUND_OPS.put(Kind.PERCENTEQ, Expression.BinaryOp.MOD);
    }

    // ===================================================================
    // Type mapping
    // ===================================================================

    private static final Map<String, String> ZIG_TYPE_MAP = new HashMap<>();
    static {
        ZIG_TYPE_MAP.put("i8", "bigint");
        ZIG_TYPE_MAP.put("i16", "bigint");
        ZIG_TYPE_MAP.put("i32", "bigint");
        ZIG_TYPE_MAP.put("i64", "bigint");
        ZIG_TYPE_MAP.put("i128", "bigint");
        ZIG_TYPE_MAP.put("isize", "bigint");
        ZIG_TYPE_MAP.put("u8", "bigint");
        ZIG_TYPE_MAP.put("u16", "bigint");
        ZIG_TYPE_MAP.put("u32", "bigint");
        ZIG_TYPE_MAP.put("u64", "bigint");
        ZIG_TYPE_MAP.put("u128", "bigint");
        ZIG_TYPE_MAP.put("usize", "bigint");
        ZIG_TYPE_MAP.put("comptime_int", "bigint");
        ZIG_TYPE_MAP.put("bool", "boolean");
        ZIG_TYPE_MAP.put("void", "void");
        ZIG_TYPE_MAP.put("Bigint", "bigint");
        ZIG_TYPE_MAP.put("ByteString", "ByteString");
        ZIG_TYPE_MAP.put("PubKey", "PubKey");
        ZIG_TYPE_MAP.put("Sig", "Sig");
        ZIG_TYPE_MAP.put("Sha256", "Sha256");
        ZIG_TYPE_MAP.put("Sha256Digest", "Sha256");
        ZIG_TYPE_MAP.put("Ripemd160", "Ripemd160");
        ZIG_TYPE_MAP.put("Addr", "Addr");
        ZIG_TYPE_MAP.put("SigHashPreimage", "SigHashPreimage");
        ZIG_TYPE_MAP.put("RabinSig", "RabinSig");
        ZIG_TYPE_MAP.put("RabinPubKey", "RabinPubKey");
        ZIG_TYPE_MAP.put("Point", "Point");
        ZIG_TYPE_MAP.put("P256Point", "P256Point");
        ZIG_TYPE_MAP.put("P384Point", "P384Point");
    }

    private static String mapZigType(String name) {
        return ZIG_TYPE_MAP.getOrDefault(name, name);
    }

    private static boolean isPrimitiveCanonical(String name) {
        // Mirrors PRIMITIVE_TYPE_NAMES in the Python reference. The Java
        // PrimitiveTypeName enum lacks "void" but our parser still tags void
        // return types as primitives so callers can recognise them.
        if ("void".equals(name)) return true;
        try {
            PrimitiveTypeName.fromCanonical(name);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static TypeNode makeTypeNode(String mappedName) {
        if ("void".equals(mappedName)) {
            // Java's PrimitiveTypeName enum has no VOID member. Emit a custom
            // type so the AST stays well-formed; type-check rejects calls
            // that try to use void as a value type anyway.
            return new CustomType("void");
        }
        if (isPrimitiveCanonical(mappedName)) {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(mappedName));
        }
        return new CustomType(mappedName);
    }

    // ===================================================================
    // Tokenizer
    // ===================================================================

    private static boolean isIdentStart(char ch) {
        return Character.isLetter(ch) || ch == '_';
    }

    private static boolean isIdentPart(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '_';
    }

    static List<Token> tokenize(String source) {
        List<Token> out = new ArrayList<>();
        int pos = 0;
        int line = 1;
        int col = 1;
        int n = source.length();

        while (pos < n) {
            char ch = source.charAt(pos);
            int tokLine = line;
            int tokCol = col;

            if (ch == ' ' || ch == '\t' || ch == '\r') {
                pos++;
                col++;
                continue;
            }
            if (ch == '\n') {
                pos++;
                line++;
                col = 1;
                continue;
            }

            // Line comment
            if (ch == '/' && pos + 1 < n && source.charAt(pos + 1) == '/') {
                while (pos < n && source.charAt(pos) != '\n') {
                    pos++;
                }
                continue;
            }
            // Block comment
            if (ch == '/' && pos + 1 < n && source.charAt(pos + 1) == '*') {
                pos += 2;
                col += 2;
                while (pos < n - 1) {
                    if (source.charAt(pos) == '*' && source.charAt(pos + 1) == '/') {
                        pos += 2;
                        col += 2;
                        break;
                    }
                    if (source.charAt(pos) == '\n') {
                        line++;
                        col = 1;
                    } else {
                        col++;
                    }
                    pos++;
                }
                continue;
            }

            // Two-character operators
            if (pos + 1 < n) {
                String two = source.substring(pos, pos + 2);
                Kind two2 = switch (two) {
                    case "==" -> Kind.EQEQ;
                    case "!=" -> Kind.NOTEQ;
                    case "<=" -> Kind.LTEQ;
                    case ">=" -> Kind.GTEQ;
                    case "<<" -> Kind.LSHIFT;
                    case ">>" -> Kind.RSHIFT;
                    case "&&" -> Kind.AMPAMP;
                    case "||" -> Kind.PIPEPIPE;
                    case "+=" -> Kind.PLUSEQ;
                    case "-=" -> Kind.MINUSEQ;
                    case "*=" -> Kind.STAREQ;
                    case "/=" -> Kind.SLASHEQ;
                    case "%=" -> Kind.PERCENTEQ;
                    default -> null;
                };
                if (two2 != null) {
                    out.add(new Token(two2, two, tokLine, tokCol));
                    pos += 2;
                    col += 2;
                    continue;
                }
            }

            // Single-character tokens
            Kind single = switch (ch) {
                case '(' -> Kind.LPAREN;
                case ')' -> Kind.RPAREN;
                case '{' -> Kind.LBRACE;
                case '}' -> Kind.RBRACE;
                case '[' -> Kind.LBRACKET;
                case ']' -> Kind.RBRACKET;
                case ';' -> Kind.SEMICOLON;
                case ',' -> Kind.COMMA;
                case '.' -> Kind.DOT;
                case ':' -> Kind.COLON;
                case '@' -> Kind.AT;
                case '+' -> Kind.PLUS;
                case '-' -> Kind.MINUS;
                case '*' -> Kind.STAR;
                case '/' -> Kind.SLASH;
                case '%' -> Kind.PERCENT;
                case '<' -> Kind.LT;
                case '>' -> Kind.GT;
                case '=' -> Kind.ASSIGN;
                case '&' -> Kind.AMP;
                case '|' -> Kind.PIPE;
                case '^' -> Kind.CARET;
                case '~' -> Kind.TILDE;
                case '!' -> Kind.BANG;
                default -> null;
            };
            if (single != null) {
                out.add(new Token(single, String.valueOf(ch), tokLine, tokCol));
                pos++;
                col++;
                continue;
            }

            // String literal
            if (ch == '"') {
                pos++;
                col++;
                StringBuilder sb = new StringBuilder();
                while (pos < n && source.charAt(pos) != '"') {
                    if (source.charAt(pos) == '\\' && pos + 1 < n) {
                        pos++;
                        col++;
                        sb.append(source.charAt(pos));
                        pos++;
                        col++;
                    } else {
                        sb.append(source.charAt(pos));
                        pos++;
                        col++;
                    }
                }
                if (pos < n) {
                    pos++; // skip closing quote
                    col++;
                }
                out.add(new Token(Kind.STRING, sb.toString(), tokLine, tokCol));
                continue;
            }

            // Number literal
            if (Character.isDigit(ch)) {
                StringBuilder sb = new StringBuilder();
                if (ch == '0' && pos + 1 < n && (source.charAt(pos + 1) == 'x' || source.charAt(pos + 1) == 'X')) {
                    sb.append("0x");
                    pos += 2;
                    col += 2;
                    while (pos < n && isHexDigitOrUnderscore(source.charAt(pos))) {
                        if (source.charAt(pos) != '_') sb.append(source.charAt(pos));
                        pos++;
                        col++;
                    }
                } else {
                    while (pos < n && (Character.isDigit(source.charAt(pos)) || source.charAt(pos) == '_')) {
                        if (source.charAt(pos) != '_') sb.append(source.charAt(pos));
                        pos++;
                        col++;
                    }
                }
                out.add(new Token(Kind.NUMBER, sb.toString(), tokLine, tokCol));
                continue;
            }

            // Identifier / keyword
            if (isIdentStart(ch)) {
                int start = pos;
                while (pos < n && isIdentPart(source.charAt(pos))) {
                    pos++;
                    col++;
                }
                String word = source.substring(start, pos);
                Kind kw = KEYWORDS.get(word);
                if (kw != null) {
                    out.add(new Token(kw, word, tokLine, tokCol));
                } else {
                    out.add(new Token(Kind.IDENT, word, tokLine, tokCol));
                }
                continue;
            }

            // Skip unknown character
            pos++;
            col++;
        }

        out.add(new Token(Kind.EOF, "", line, col));
        return out;
    }

    private static boolean isHexDigitOrUnderscore(char c) {
        return (c >= '0' && c <= '9')
            || (c >= 'a' && c <= 'f')
            || (c >= 'A' && c <= 'F')
            || c == '_';
    }

    // ===================================================================
    // Parser state (mutable)
    // ===================================================================

    private static final class State {
        final List<Token> tokens;
        final String file;
        int pos = 0;
        final List<String> errors = new ArrayList<>();

        // Contract being built.
        String contractName = "UnnamedContract";
        ParentClass parentClass = ParentClass.SMART_CONTRACT;
        List<PropertyNode> properties = new ArrayList<>();
        List<MethodNode> methods = new ArrayList<>();
        MethodNode constructor = null;

        // Per-method scope tracking.
        Set<String> selfNames = new HashSet<>();
        Set<String> statefulContextNames = new HashSet<>();

        State(List<Token> tokens, String file) {
            this.tokens = tokens;
            this.file = file;
        }

        // ------------------ Token cursor ------------------

        Token current() {
            if (pos < tokens.size()) return tokens.get(pos);
            return tokens.get(tokens.size() - 1);
        }

        Token advance() {
            Token t = current();
            if (pos < tokens.size() - 1) pos++;
            return t;
        }

        Token peekAhead(int offset) {
            int idx = pos + offset;
            if (idx < tokens.size()) return tokens.get(idx);
            return tokens.get(tokens.size() - 1);
        }

        boolean match(Kind k) {
            if (current().kind == k) {
                advance();
                return true;
            }
            return false;
        }

        Token expect(Kind k, String label) {
            Token t = current();
            if (t.kind != k) {
                errors.add(file + ":" + t.line + ":" + t.col + ": expected '" + label
                    + "', got '" + (t.value == null || t.value.isEmpty() ? t.kind : t.value) + "'");
            }
            return advance();
        }

        SourceLocation loc() {
            Token t = current();
            return new SourceLocation(file, t.line, t.col);
        }

        // ------------------ Top-level parse ------------------

        ContractNode parseTopLevel() throws ParseException {
            skipRunarImport();

            while (current().kind != Kind.EOF) {
                if (current().kind == Kind.PUB
                        && peekAhead(1).kind == Kind.CONST
                        && peekAhead(2).kind == Kind.IDENT
                        && peekAhead(3).kind == Kind.ASSIGN) {
                    ContractNode c = tryParseContractDecl();
                    if (c != null) {
                        if (!errors.isEmpty()) {
                            throw new ParseException(String.join("\n", errors));
                        }
                        return c;
                    }
                }
                advance();
            }

            errors.add(file + ":1:1: Expected Zig contract declaration "
                + "`pub const Name = struct { ... };`");
            throw new ParseException(String.join("\n", errors));
        }

        void skipRunarImport() {
            int start = pos;
            if (current().kind == Kind.CONST) {
                advance();
                if (current().kind == Kind.IDENT && "runar".equals(current().value)) {
                    advance();
                    if (match(Kind.ASSIGN)) {
                        if (match(Kind.AT)
                                && current().kind == Kind.IDENT
                                && "import".equals(current().value)) {
                            advance(); // 'import'
                            expect(Kind.LPAREN, "(");
                            if (current().kind == Kind.STRING) {
                                advance();
                            }
                            expect(Kind.RPAREN, ")");
                            match(Kind.SEMICOLON);
                            return;
                        }
                    }
                }
            }
            pos = start;
            errors.add(file + ":1:1: Expected `const runar = @import(\"runar\");` "
                + "at the top of the file");
        }

        ContractNode tryParseContractDecl() {
            int start = pos;
            expect(Kind.PUB, "pub");
            expect(Kind.CONST, "const");
            Token nameTok = expect(Kind.IDENT, "identifier");

            if (current().kind != Kind.ASSIGN) {
                pos = start;
                return null;
            }
            expect(Kind.ASSIGN, "=");
            if (current().kind != Kind.STRUCT) {
                pos = start;
                return null;
            }

            contractName = nameTok.value;
            parentClass = ParentClass.SMART_CONTRACT;
            properties = new ArrayList<>();
            methods = new ArrayList<>();
            constructor = null;

            expect(Kind.STRUCT, "struct");
            expect(Kind.LBRACE, "{");

            while (current().kind != Kind.RBRACE && current().kind != Kind.EOF) {
                // pub const Contract = runar.SmartContract;
                if (current().kind == Kind.PUB
                        && peekAhead(1).kind == Kind.CONST
                        && peekAhead(2).kind == Kind.IDENT
                        && "Contract".equals(peekAhead(2).value)) {
                    parseContractMarker();
                    continue;
                }
                // pub fn name(...)
                if (current().kind == Kind.PUB && peekAhead(1).kind == Kind.FN) {
                    MethodNode m = parseMethod(true);
                    if (m != null) methods.add(m);
                    continue;
                }
                // fn name(...)
                if (current().kind == Kind.FN) {
                    MethodNode m = parseMethod(false);
                    if (m != null) methods.add(m);
                    continue;
                }
                // field
                if (current().kind == Kind.IDENT) {
                    properties.add(parseField());
                    continue;
                }
                advance();
            }
            expect(Kind.RBRACE, "}");
            match(Kind.SEMICOLON);

            // Determine which property names are mutated in any method body.
            Set<String> mutated = new HashSet<>();
            for (MethodNode m : methods) {
                collectMutatedProperties(m.body(), mutated);
            }

            // Constructor parameter names — used to strip property
            // initializers overridden by an explicit ctor param.
            Set<String> ctorParamNames = new HashSet<>();
            if (constructor != null) {
                for (ParamNode p : constructor.params()) {
                    ctorParamNames.add(p.name());
                }
            }

            // Apply readonly + initializer normalization.
            List<PropertyNode> normalized = new ArrayList<>(properties.size());
            for (PropertyNode prop : properties) {
                boolean hadInitializer = prop.initializer() != null;
                Expression init = prop.initializer();
                boolean readonly = prop.readonly();
                if (ctorParamNames.contains(prop.name())) {
                    init = null;
                }
                if (parentClass == ParentClass.SMART_CONTRACT) {
                    readonly = true;
                } else if (!readonly && !hadInitializer && !mutated.contains(prop.name())) {
                    readonly = true;
                }
                normalized.add(new PropertyNode(
                    prop.name(),
                    prop.type(),
                    readonly,
                    init,
                    prop.sourceLocation(),
                    null
                ));
            }
            properties = normalized;

            // Rewrite bare method calls.
            Set<String> methodNames = new HashSet<>();
            for (MethodNode m : methods) methodNames.add(m.name());
            methodNames.addAll(Arrays.asList(
                "addOutput", "addRawOutput", "addDataOutput", "getStateScript"));

            List<MethodNode> rewrittenMethods = new ArrayList<>(methods.size());
            for (MethodNode m : methods) {
                Set<String> paramScope = new HashSet<>();
                for (ParamNode p : m.params()) paramScope.add(p.name());
                List<Statement> rewritten = rewriteStmts(m.body(), methodNames, paramScope);
                rewrittenMethods.add(new MethodNode(
                    m.name(), m.params(), rewritten, m.visibility(), m.sourceLocation()));
            }
            methods = rewrittenMethods;

            MethodNode ctor;
            if (constructor != null) {
                Set<String> paramScope = new HashSet<>();
                for (ParamNode p : constructor.params()) paramScope.add(p.name());
                List<Statement> rewritten = rewriteStmts(
                    constructor.body(), methodNames, paramScope);
                ctor = new MethodNode(
                    constructor.name(), constructor.params(), rewritten,
                    constructor.visibility(), constructor.sourceLocation());
            } else {
                ctor = createFallbackConstructor();
            }

            return new ContractNode(
                contractName, parentClass, properties, ctor, methods, file);
        }

        void parseContractMarker() {
            expect(Kind.PUB, "pub");
            expect(Kind.CONST, "const");
            expect(Kind.IDENT, "Contract");
            expect(Kind.ASSIGN, "=");
            if (current().kind == Kind.IDENT && "runar".equals(current().value)) {
                advance();
                expect(Kind.DOT, ".");
                String parent = expect(Kind.IDENT, "identifier").value;
                if ("StatefulSmartContract".equals(parent)) {
                    parentClass = ParentClass.STATEFUL_SMART_CONTRACT;
                } else {
                    parentClass = ParentClass.SMART_CONTRACT;
                }
            }
            match(Kind.SEMICOLON);
        }

        PropertyNode parseField() {
            SourceLocation l = loc();
            String name = expect(Kind.IDENT, "field name").value;
            expect(Kind.COLON, ":");
            ParsedType pt = parseType();

            Expression initializer = null;
            if (current().kind == Kind.ASSIGN) {
                advance();
                initializer = parseExpression();
            }
            match(Kind.COMMA);

            return new PropertyNode(name, pt.type, pt.readonly, initializer, l, null);
        }

        MethodNode parseMethod(boolean isPublic) {
            SourceLocation l = loc();
            if (isPublic) expect(Kind.PUB, "pub");
            expect(Kind.FN, "fn");
            String name = expect(Kind.IDENT, "method name").value;

            ParamListResult plr = parseParamList();

            // Parse and discard the return type if present.
            if (current().kind != Kind.LBRACE) {
                parseType();
            }

            Set<String> prevSelf = selfNames;
            Set<String> prevCtx = statefulContextNames;
            selfNames = plr.receiverName != null ? new HashSet<>(Set.of(plr.receiverName)) : new HashSet<>();
            statefulContextNames = plr.statefulCtx;

            try {
                if ("init".equals(name)) {
                    constructor = parseConstructor(l, plr.params);
                    return null;
                }
                List<Statement> body = parseBlockStatements();
                return new MethodNode(
                    name, plr.params, body,
                    isPublic ? Visibility.PUBLIC : Visibility.PRIVATE,
                    l);
            } finally {
                selfNames = prevSelf;
                statefulContextNames = prevCtx;
            }
        }

        static final class ParamListResult {
            final List<ParamNode> params;
            final String receiverName;
            final Set<String> statefulCtx;

            ParamListResult(List<ParamNode> params, String receiverName, Set<String> statefulCtx) {
                this.params = params;
                this.receiverName = receiverName;
                this.statefulCtx = statefulCtx;
            }
        }

        ParamListResult parseParamList() {
            expect(Kind.LPAREN, "(");
            List<ParamNode> params = new ArrayList<>();
            String receiverName = null;
            Set<String> statefulCtx = new HashSet<>();
            int index = 0;

            while (current().kind != Kind.RPAREN && current().kind != Kind.EOF) {
                String paramName = expect(Kind.IDENT, "parameter name").value;
                expect(Kind.COLON, ":");
                ParsedType pt = parseParamType();
                boolean isReceiver = (index == 0 && contractName.equals(pt.rawName));
                if (isReceiver) {
                    receiverName = paramName;
                } else if ("StatefulContext".equals(pt.rawName)) {
                    // Zig stateful contracts thread an explicit StatefulContext
                    // parameter through every state-mutating method body
                    // (e.g. `ctx.txPreimage`, `ctx.addOutput(...)`). The compiler
                    // re-injects this context when lowering, so the parameter is
                    // dropped from the canonical IR -- matching the Zig compiler's
                    // own parse_zig.zig behavior. Recording the binding name lets
                    // later passes rewrite `ctx.txPreimage` -> `this.txPreimage`
                    // and `ctx.addOutput(...)` -> `this.addOutput(...)`.
                    statefulCtx.add(paramName);
                } else {
                    params.add(new ParamNode(paramName, pt.type));
                }
                index++;
                match(Kind.COMMA);
            }
            expect(Kind.RPAREN, ")");
            return new ParamListResult(params, receiverName, statefulCtx);
        }

        ParsedType parseParamType() {
            // Skip pointer qualifiers / const.
            while (current().kind == Kind.STAR || current().kind == Kind.AMP) {
                advance();
            }
            if (current().kind == Kind.CONST) {
                advance();
            }
            return parseType();
        }

        static final class ParsedType {
            final TypeNode type;
            final String rawName;
            final boolean readonly;

            ParsedType(TypeNode type, String rawName, boolean readonly) {
                this.type = type;
                this.rawName = rawName;
                this.readonly = readonly;
            }
        }

        ParsedType parseType() {
            // [N]Element
            if (current().kind == Kind.LBRACKET) {
                advance();
                Token len = expect(Kind.NUMBER, "array length");
                int length = parseLongLiteral(len.value).intValueExact();
                expect(Kind.RBRACKET, "]");
                ParsedType elem = parseType();
                return new ParsedType(new FixedArrayType(elem.type, length), elem.rawName, false);
            }

            // runar.TypeName or runar.Readonly(Type)
            if (current().kind == Kind.IDENT
                    && "runar".equals(current().value)
                    && peekAhead(1).kind == Kind.DOT) {
                advance(); // 'runar'
                expect(Kind.DOT, ".");
                String name = expect(Kind.IDENT, "type name").value;

                if ("Readonly".equals(name) && current().kind == Kind.LPAREN) {
                    expect(Kind.LPAREN, "(");
                    ParsedType inner = parseType();
                    expect(Kind.RPAREN, ")");
                    return new ParsedType(inner.type, inner.rawName, true);
                }
                String mapped = mapZigType(name);
                return new ParsedType(makeTypeNode(mapped), name, false);
            }

            // void keyword
            if (current().kind == Kind.VOID) {
                advance();
                return new ParsedType(makeTypeNode("void"), "void", false);
            }

            // Bare ident
            if (current().kind == Kind.IDENT) {
                String n = advance().value;
                String mapped = mapZigType(n);
                return new ParsedType(makeTypeNode(mapped), n, false);
            }

            Token fallback = advance();
            return new ParsedType(new CustomType("unknown"),
                fallback.value == null || fallback.value.isEmpty() ? "unknown" : fallback.value,
                false);
        }

        MethodNode parseConstructor(SourceLocation l, List<ParamNode> params) {
            List<Statement> body = new ArrayList<>();
            body.add(createSuperCall(params));
            boolean foundReturnStruct = false;

            expect(Kind.LBRACE, "{");

            while (current().kind != Kind.RBRACE && current().kind != Kind.EOF) {
                // return .{ .field = value, ... };
                if (current().kind == Kind.RETURN
                        && peekAhead(1).kind == Kind.DOT
                        && peekAhead(2).kind == Kind.LBRACE) {
                    advance(); // 'return'
                    body.addAll(parseStructReturnAssignments());
                    foundReturnStruct = true;
                    match(Kind.SEMICOLON);
                    continue;
                }
                Statement stmt = parseStatement();
                if (stmt != null) body.add(stmt);
            }
            expect(Kind.RBRACE, "}");

            if (!foundReturnStruct) {
                for (PropertyNode prop : properties) {
                    boolean hasParam = false;
                    for (ParamNode p : params) {
                        if (p.name().equals(prop.name())) {
                            hasParam = true;
                            break;
                        }
                    }
                    if (hasParam) {
                        body.add(createPropertyAssignment(prop.name(), new Identifier(prop.name())));
                    }
                }
            }

            return new MethodNode("constructor", params, body, Visibility.PUBLIC, l);
        }

        List<Statement> parseStructReturnAssignments() {
            List<Statement> out = new ArrayList<>();
            expect(Kind.DOT, ".");
            expect(Kind.LBRACE, "{");
            while (current().kind != Kind.RBRACE && current().kind != Kind.EOF) {
                if (current().kind == Kind.DOT) advance();
                String field = expect(Kind.IDENT, "field name").value;
                expect(Kind.ASSIGN, "=");
                Expression value = parseExpression();
                out.add(createPropertyAssignment(field, value));
                match(Kind.COMMA);
            }
            expect(Kind.RBRACE, "}");
            return out;
        }

        // ------------------ Statements ------------------

        List<Statement> parseBlockStatements() {
            expect(Kind.LBRACE, "{");
            List<Statement> body = new ArrayList<>();
            while (current().kind != Kind.RBRACE && current().kind != Kind.EOF) {
                Statement s = parseStatement();
                if (s != null) {
                    // Merge `var i = 0; while(...)` patterns into a ForStmt's init slot.
                    if (s instanceof ForStatement fs
                            && fs.init() != null
                            && "__while_no_init".equals(fs.init().name())
                            && !body.isEmpty()) {
                        Statement last = body.get(body.size() - 1);
                        String updateName = getLoopUpdateTargetName(fs);
                        if (last instanceof VariableDeclStatement vds
                                && updateName != null
                                && updateName.equals(vds.name())) {
                            body.remove(body.size() - 1);
                            s = new ForStatement(vds, fs.condition(), fs.update(), fs.body(), fs.sourceLocation());
                        }
                    }
                    body.add(s);
                }
            }
            expect(Kind.RBRACE, "}");
            return body;
        }

        String getLoopUpdateTargetName(ForStatement fs) {
            if (fs.update() instanceof AssignmentStatement as
                    && as.target() instanceof Identifier id) {
                return id.name();
            }
            if (fs.update() instanceof ExpressionStatement es
                    && es.expression() instanceof Identifier id) {
                return id.name();
            }
            return null;
        }

        Statement parseStatement() {
            SourceLocation l = loc();

            if (current().kind == Kind.RETURN) {
                advance();
                Expression value = null;
                if (current().kind != Kind.SEMICOLON) {
                    value = parseExpression();
                }
                match(Kind.SEMICOLON);
                return new ReturnStatement(value, l);
            }
            if (current().kind == Kind.IF) {
                return parseIfStatement();
            }
            if (current().kind == Kind.CONST || current().kind == Kind.VAR) {
                return parseVariableDecl();
            }
            // _ = expr;
            if (current().kind == Kind.IDENT && "_".equals(current().value)
                    && peekAhead(1).kind == Kind.ASSIGN) {
                advance(); // _
                advance(); // =
                parseExpression();
                match(Kind.SEMICOLON);
                return null;
            }
            if (current().kind == Kind.WHILE) {
                return parseWhileStatement();
            }
            if (current().kind == Kind.FOR) {
                errors.add(file + ":" + l.line() + ":" + l.column()
                    + ": Unsupported Zig 'for' syntax -- use 'while' loops instead");
                skipUnsupportedBlock();
                return null;
            }

            // Expression-based statement.
            Expression target = parseExpression();
            if (current().kind == Kind.ASSIGN) {
                advance();
                Expression value = parseExpression();
                match(Kind.SEMICOLON);
                return new AssignmentStatement(target, value, l);
            }
            Expression.BinaryOp compound = parseCompoundAssignmentOperator();
            if (compound != null) {
                Expression rhs = parseExpression();
                match(Kind.SEMICOLON);
                return new AssignmentStatement(
                    target,
                    new BinaryExpr(compound, target, rhs),
                    l);
            }
            match(Kind.SEMICOLON);
            return new ExpressionStatement(target, l);
        }

        Statement parseVariableDecl() {
            SourceLocation l = loc();
            // 'const' or 'var' — mutability is not modelled in the Java AST,
            // but we still consume the keyword.
            advance();
            String name = expect(Kind.IDENT, "variable name").value;

            TypeNode typeNode = null;
            if (current().kind == Kind.COLON) {
                advance();
                typeNode = parseType().type;
            }

            expect(Kind.ASSIGN, "=");
            Expression init = parseExpression();
            match(Kind.SEMICOLON);

            return new VariableDeclStatement(name, typeNode, init, l);
        }

        Statement parseIfStatement() {
            SourceLocation l = loc();
            expect(Kind.IF, "if");
            if (current().kind == Kind.LPAREN) advance();
            Expression condition = parseExpression();
            if (current().kind == Kind.RPAREN) advance();

            List<Statement> thenBranch = parseBlockStatements();
            List<Statement> elseBranch = null;
            if (current().kind == Kind.ELSE) {
                advance();
                if (current().kind == Kind.IF) {
                    elseBranch = new ArrayList<>();
                    elseBranch.add(parseIfStatement());
                } else {
                    elseBranch = parseBlockStatements();
                }
            }
            return new IfStatement(condition, thenBranch, elseBranch == null ? List.of() : elseBranch, l);
        }

        Statement parseWhileStatement() {
            SourceLocation l = loc();
            expect(Kind.WHILE, "while");

            if (current().kind == Kind.LPAREN) advance();
            Expression condition = parseExpression();
            if (current().kind == Kind.RPAREN) advance();

            Statement update;
            if (current().kind == Kind.COLON) {
                advance();
                if (current().kind == Kind.LPAREN) advance();
                Expression updateTarget = parseExpression();
                Expression.BinaryOp compound = parseCompoundAssignmentOperator();
                if (compound != null) {
                    Expression rhs = parseExpression();
                    update = new AssignmentStatement(
                        updateTarget,
                        new BinaryExpr(compound, updateTarget, rhs),
                        l);
                } else {
                    update = new ExpressionStatement(updateTarget, l);
                }
                if (current().kind == Kind.RPAREN) advance();
            } else {
                update = new ExpressionStatement(new BigIntLiteral(BigInteger.ZERO), l);
            }

            List<Statement> body = parseBlockStatements();

            // Placeholder init that may be patched up by parseBlockStatements.
            VariableDeclStatement init = new VariableDeclStatement(
                "__while_no_init", null, new BigIntLiteral(BigInteger.ZERO), l);
            return new ForStatement(init, condition, update, body, l);
        }

        Expression.BinaryOp parseCompoundAssignmentOperator() {
            Expression.BinaryOp op = COMPOUND_OPS.get(current().kind);
            if (op != null) {
                advance();
                return op;
            }
            return null;
        }

        void skipUnsupportedBlock() {
            while (current().kind != Kind.LBRACE
                    && current().kind != Kind.SEMICOLON
                    && current().kind != Kind.EOF) {
                advance();
            }
            if (current().kind == Kind.SEMICOLON) {
                advance();
                return;
            }
            if (current().kind != Kind.LBRACE) return;

            int depth = 0;
            while (current().kind != Kind.EOF) {
                if (current().kind == Kind.LBRACE) {
                    depth++;
                }
                if (current().kind == Kind.RBRACE) {
                    depth--;
                    advance();
                    if (depth <= 0) break;
                    continue;
                }
                advance();
            }
        }

        // ------------------ Expressions (precedence climbing) ------------------

        Expression parseExpression() {
            return parseTernary();
        }

        Expression parseTernary() {
            // Zig has no ternary; replicate Python parser behaviour (no-op).
            return parseOr();
        }

        Expression parseOr() {
            Expression left = parseAnd();
            while (current().kind == Kind.PIPEPIPE) {
                advance();
                Expression right = parseAnd();
                left = new BinaryExpr(Expression.BinaryOp.OR, left, right);
            }
            return left;
        }

        Expression parseAnd() {
            Expression left = parseBitwiseOr();
            while (current().kind == Kind.AMPAMP) {
                advance();
                Expression right = parseBitwiseOr();
                left = new BinaryExpr(Expression.BinaryOp.AND, left, right);
            }
            return left;
        }

        Expression parseBitwiseOr() {
            Expression left = parseBitwiseXor();
            while (current().kind == Kind.PIPE) {
                advance();
                Expression right = parseBitwiseXor();
                left = new BinaryExpr(Expression.BinaryOp.BIT_OR, left, right);
            }
            return left;
        }

        Expression parseBitwiseXor() {
            Expression left = parseBitwiseAnd();
            while (current().kind == Kind.CARET) {
                advance();
                Expression right = parseBitwiseAnd();
                left = new BinaryExpr(Expression.BinaryOp.BIT_XOR, left, right);
            }
            return left;
        }

        Expression parseBitwiseAnd() {
            Expression left = parseEquality();
            while (current().kind == Kind.AMP) {
                advance();
                Expression right = parseEquality();
                left = new BinaryExpr(Expression.BinaryOp.BIT_AND, left, right);
            }
            return left;
        }

        Expression parseEquality() {
            Expression left = parseComparison();
            while (true) {
                Kind k = current().kind;
                if (k == Kind.EQEQ) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.EQ, left, parseComparison());
                } else if (k == Kind.NOTEQ) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.NEQ, left, parseComparison());
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseComparison() {
            Expression left = parseShift();
            while (true) {
                Kind k = current().kind;
                if (k == Kind.LT) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.LT, left, parseShift());
                } else if (k == Kind.LTEQ) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.LE, left, parseShift());
                } else if (k == Kind.GT) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.GT, left, parseShift());
                } else if (k == Kind.GTEQ) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.GE, left, parseShift());
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseShift() {
            Expression left = parseAddSub();
            while (true) {
                Kind k = current().kind;
                if (k == Kind.LSHIFT) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.SHL, left, parseAddSub());
                } else if (k == Kind.RSHIFT) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.SHR, left, parseAddSub());
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseAddSub() {
            Expression left = parseMulDiv();
            while (true) {
                Kind k = current().kind;
                if (k == Kind.PLUS) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.ADD, left, parseMulDiv());
                } else if (k == Kind.MINUS) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.SUB, left, parseMulDiv());
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseMulDiv() {
            Expression left = parseUnary();
            while (true) {
                Kind k = current().kind;
                if (k == Kind.STAR) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.MUL, left, parseUnary());
                } else if (k == Kind.SLASH) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.DIV, left, parseUnary());
                } else if (k == Kind.PERCENT) {
                    advance();
                    left = new BinaryExpr(Expression.BinaryOp.MOD, left, parseUnary());
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseUnary() {
            Kind k = current().kind;
            if (k == Kind.BANG) {
                advance();
                return new UnaryExpr(Expression.UnaryOp.NOT, parseUnary());
            }
            if (k == Kind.MINUS) {
                advance();
                return new UnaryExpr(Expression.UnaryOp.NEG, parseUnary());
            }
            if (k == Kind.TILDE) {
                advance();
                return new UnaryExpr(Expression.UnaryOp.BIT_NOT, parseUnary());
            }
            Expression expr = parsePrimary();
            return parsePostfixChain(expr);
        }

        Expression parsePrimary() {
            Token tok = current();

            // Anonymous struct literal: .{ elem, ... }
            if (tok.kind == Kind.DOT && peekAhead(1).kind == Kind.LBRACE) {
                advance(); // '.'
                advance(); // '{'
                List<Expression> elements = new ArrayList<>();
                while (current().kind != Kind.RBRACE && current().kind != Kind.EOF) {
                    elements.add(parseExpression());
                    match(Kind.COMMA);
                }
                expect(Kind.RBRACE, "}");
                return new ArrayLiteralExpr(elements);
            }

            if (tok.kind == Kind.NUMBER) {
                advance();
                return new BigIntLiteral(parseLongLiteral(tok.value));
            }
            if (tok.kind == Kind.STRING) {
                advance();
                return new ByteStringLiteral(tok.value);
            }
            if (tok.kind == Kind.TRUE) {
                advance();
                return new BoolLiteral(true);
            }
            if (tok.kind == Kind.FALSE) {
                advance();
                return new BoolLiteral(false);
            }
            if (tok.kind == Kind.LPAREN) {
                advance();
                Expression e = parseExpression();
                expect(Kind.RPAREN, ")");
                return e;
            }
            if (tok.kind == Kind.LBRACKET) {
                advance();
                List<Expression> elements = new ArrayList<>();
                while (current().kind != Kind.RBRACKET && current().kind != Kind.EOF) {
                    elements.add(parseExpression());
                    match(Kind.COMMA);
                }
                expect(Kind.RBRACKET, "]");
                return new ArrayLiteralExpr(elements);
            }
            // Zig @builtins
            if (tok.kind == Kind.AT) {
                advance();
                String builtinName = expect(Kind.IDENT, "builtin name").value;

                if ("divTrunc".equals(builtinName) || "mod".equals(builtinName)
                        || "shlExact".equals(builtinName) || "shrExact".equals(builtinName)) {
                    expect(Kind.LPAREN, "(");
                    Expression left = parseExpression();
                    expect(Kind.COMMA, ",");
                    Expression right = parseExpression();
                    expect(Kind.RPAREN, ")");
                    Expression.BinaryOp op = switch (builtinName) {
                        case "divTrunc" -> Expression.BinaryOp.DIV;
                        case "mod" -> Expression.BinaryOp.MOD;
                        case "shlExact" -> Expression.BinaryOp.SHL;
                        case "shrExact" -> Expression.BinaryOp.SHR;
                        default -> throw new IllegalStateException();
                    };
                    return new BinaryExpr(op, left, right);
                }
                if ("intCast".equals(builtinName) || "truncate".equals(builtinName)
                        || "as".equals(builtinName)) {
                    expect(Kind.LPAREN, "(");
                    if ("as".equals(builtinName)) {
                        parseType();
                        expect(Kind.COMMA, ",");
                    }
                    Expression inner = parseExpression();
                    expect(Kind.RPAREN, ")");
                    return inner;
                }
                if ("import".equals(builtinName)) {
                    expect(Kind.LPAREN, "(");
                    parseExpression();
                    expect(Kind.RPAREN, ")");
                    return new Identifier("__import");
                }
                if ("embedFile".equals(builtinName)) {
                    expect(Kind.LPAREN, "(");
                    Expression arg = parseExpression();
                    expect(Kind.RPAREN, ")");
                    return arg;
                }
                // Unknown builtin — try parsing args.
                if (current().kind == Kind.LPAREN) {
                    advance();
                    List<Expression> args = new ArrayList<>();
                    args.add(parseExpression());
                    while (current().kind == Kind.COMMA) {
                        advance();
                        args.add(parseExpression());
                    }
                    expect(Kind.RPAREN, ")");
                    errors.add(file + ":" + tok.line + ":" + tok.col
                        + ": Unsupported Zig builtin '@" + builtinName + "'");
                    return new CallExpr(new Identifier(builtinName), args);
                }
                errors.add(file + ":" + tok.line + ":" + tok.col
                    + ": Unsupported Zig builtin '@" + builtinName + "'");
                return new Identifier(builtinName);
            }
            // Identifier (with `runar.` stripping)
            if (tok.kind == Kind.IDENT) {
                advance();
                if ("runar".equals(tok.value) && current().kind == Kind.DOT) {
                    advance(); // '.'
                    String builtin = expect(Kind.IDENT, "builtin name").value;
                    if ("bytesEq".equals(builtin) && current().kind == Kind.LPAREN) {
                        advance();
                        Expression left = parseExpression();
                        expect(Kind.COMMA, ",");
                        Expression right = parseExpression();
                        expect(Kind.RPAREN, ")");
                        return new BinaryExpr(Expression.BinaryOp.EQ, left, right);
                    }
                    return new Identifier(builtin);
                }
                return new Identifier(tok.value);
            }
            // Fallback: emit an Identifier placeholder.
            advance();
            return new Identifier(tok.value == null || tok.value.isEmpty() ? "unknown" : tok.value);
        }

        Expression parsePostfixChain(Expression expr) {
            while (true) {
                if (current().kind == Kind.LPAREN) {
                    advance();
                    List<Expression> args = new ArrayList<>();
                    while (current().kind != Kind.RPAREN && current().kind != Kind.EOF) {
                        args.add(parseExpression());
                        match(Kind.COMMA);
                    }
                    expect(Kind.RPAREN, ")");
                    expr = new CallExpr(expr, args);
                    continue;
                }
                if (current().kind == Kind.DOT) {
                    advance();
                    String prop = current().value;
                    advance();
                    if (expr instanceof Identifier id && selfNames.contains(id.name())) {
                        expr = new PropertyAccessExpr(prop);
                    } else if (expr instanceof Identifier id2
                            && statefulContextNames.contains(id2.name())
                            && (prop.equals("txPreimage") || prop.equals("getStateScript")
                                || prop.equals("addOutput") || prop.equals("addRawOutput")
                                || prop.equals("addDataOutput"))) {
                        expr = new PropertyAccessExpr(prop);
                    } else {
                        expr = new MemberExpr(expr, prop);
                    }
                    continue;
                }
                if (current().kind == Kind.LBRACKET) {
                    advance();
                    Expression index = parseExpression();
                    expect(Kind.RBRACKET, "]");
                    expr = new IndexAccessExpr(expr, index);
                    continue;
                }
                break;
            }
            return expr;
        }

        // ------------------ Helpers ------------------

        Statement createSuperCall(List<ParamNode> params) {
            SourceLocation l = new SourceLocation(file, 1, 1);
            List<Expression> args = new ArrayList<>(params.size());
            for (ParamNode p : params) {
                args.add(new Identifier(p.name()));
            }
            return new ExpressionStatement(
                new CallExpr(new Identifier("super"), args), l);
        }

        Statement createPropertyAssignment(String name, Expression value) {
            SourceLocation l = new SourceLocation(file, 1, 1);
            return new AssignmentStatement(new PropertyAccessExpr(name), value, l);
        }

        MethodNode createFallbackConstructor() {
            List<PropertyNode> required = new ArrayList<>();
            for (PropertyNode p : properties) {
                if (p.initializer() == null) required.add(p);
            }
            List<ParamNode> params = new ArrayList<>(required.size());
            for (PropertyNode p : required) {
                params.add(new ParamNode(p.name(), p.type()));
            }
            SourceLocation l = new SourceLocation(file, 1, 1);
            List<Statement> body = new ArrayList<>();
            body.add(createSuperCall(params));
            for (PropertyNode p : required) {
                body.add(createPropertyAssignment(p.name(), new Identifier(p.name())));
            }
            return new MethodNode("constructor", params, body, Visibility.PUBLIC, l);
        }
    }

    // ===================================================================
    // Bare-method-call rewriting
    //
    // Mirrors Python's _rewrite_bare_method_calls. Returns rebuilt statement
    // lists/expressions (the Java AST is record-immutable).
    // ===================================================================

    private static List<Statement> rewriteStmts(
        List<Statement> stmts, Set<String> methodNames, Set<String> scope
    ) {
        if (stmts == null) return List.of();
        Set<String> currentScope = new HashSet<>(scope);
        List<Statement> out = new ArrayList<>(stmts.size());
        for (Statement s : stmts) {
            Statement rewritten = rewriteStmt(s, methodNames, currentScope);
            out.add(rewritten);
            if (rewritten instanceof VariableDeclStatement vds) {
                currentScope.add(vds.name());
            }
        }
        return out;
    }

    private static Statement rewriteStmt(Statement s, Set<String> methodNames, Set<String> scope) {
        if (s instanceof ExpressionStatement es) {
            Expression e = es.expression() == null ? null : rewriteExpr(es.expression(), methodNames, scope);
            return new ExpressionStatement(e, es.sourceLocation());
        }
        if (s instanceof VariableDeclStatement vds) {
            Expression e = vds.init() == null ? null : rewriteExpr(vds.init(), methodNames, scope);
            return new VariableDeclStatement(vds.name(), vds.type(), e, vds.sourceLocation());
        }
        if (s instanceof AssignmentStatement as) {
            Expression target = as.target() == null ? null : rewriteExpr(as.target(), methodNames, scope);
            Expression value = as.value() == null ? null : rewriteExpr(as.value(), methodNames, scope);
            return new AssignmentStatement(target, value, as.sourceLocation());
        }
        if (s instanceof ReturnStatement rs) {
            Expression v = rs.value() == null ? null : rewriteExpr(rs.value(), methodNames, scope);
            return new ReturnStatement(v, rs.sourceLocation());
        }
        if (s instanceof IfStatement ifs) {
            Expression cond = ifs.condition() == null ? null : rewriteExpr(ifs.condition(), methodNames, scope);
            List<Statement> thenBody = rewriteStmts(ifs.thenBody(), methodNames, new HashSet<>(scope));
            List<Statement> elseBody = ifs.elseBody() == null
                ? null
                : rewriteStmts(ifs.elseBody(), methodNames, new HashSet<>(scope));
            return new IfStatement(cond, thenBody, elseBody, ifs.sourceLocation());
        }
        if (s instanceof ForStatement fs) {
            Set<String> loopScope = new HashSet<>(scope);
            VariableDeclStatement init = fs.init();
            if (init != null) {
                Expression initExpr = init.init() == null ? null : rewriteExpr(init.init(), methodNames, loopScope);
                init = new VariableDeclStatement(init.name(), init.type(), initExpr, init.sourceLocation());
                loopScope.add(init.name());
            }
            Expression cond = fs.condition() == null ? null : rewriteExpr(fs.condition(), methodNames, loopScope);
            Statement update = fs.update() == null ? null : rewriteStmt(fs.update(), methodNames, loopScope);
            List<Statement> body = rewriteStmts(fs.body(), methodNames, loopScope);
            return new ForStatement(init, cond, update, body, fs.sourceLocation());
        }
        return s;
    }

    private static Expression rewriteExpr(Expression e, Set<String> methodNames, Set<String> scope) {
        if (e instanceof CallExpr call) {
            List<Expression> newArgs = new ArrayList<>(call.args().size());
            for (Expression a : call.args()) newArgs.add(rewriteExpr(a, methodNames, scope));
            Expression callee = call.callee();
            if (callee instanceof Identifier id
                    && methodNames.contains(id.name())
                    && !scope.contains(id.name())) {
                callee = new PropertyAccessExpr(id.name());
            } else {
                callee = rewriteExpr(callee, methodNames, scope);
            }
            return new CallExpr(callee, newArgs);
        }
        if (e instanceof BinaryExpr be) {
            return new BinaryExpr(be.op(),
                rewriteExpr(be.left(), methodNames, scope),
                rewriteExpr(be.right(), methodNames, scope));
        }
        if (e instanceof UnaryExpr ue) {
            return new UnaryExpr(ue.op(), rewriteExpr(ue.operand(), methodNames, scope));
        }
        if (e instanceof TernaryExpr te) {
            return new TernaryExpr(
                rewriteExpr(te.condition(), methodNames, scope),
                rewriteExpr(te.consequent(), methodNames, scope),
                rewriteExpr(te.alternate(), methodNames, scope));
        }
        if (e instanceof MemberExpr me) {
            return new MemberExpr(rewriteExpr(me.object(), methodNames, scope), me.property());
        }
        if (e instanceof IndexAccessExpr ia) {
            return new IndexAccessExpr(
                rewriteExpr(ia.object(), methodNames, scope),
                rewriteExpr(ia.index(), methodNames, scope));
        }
        if (e instanceof IncrementExpr ie) {
            return new IncrementExpr(rewriteExpr(ie.operand(), methodNames, scope), ie.prefix());
        }
        if (e instanceof DecrementExpr de) {
            return new DecrementExpr(rewriteExpr(de.operand(), methodNames, scope), de.prefix());
        }
        if (e instanceof ArrayLiteralExpr ale) {
            List<Expression> ne = new ArrayList<>(ale.elements().size());
            for (Expression el : ale.elements()) ne.add(rewriteExpr(el, methodNames, scope));
            return new ArrayLiteralExpr(ne);
        }
        return e;
    }

    // ===================================================================
    // Mutation detection
    // ===================================================================

    private static void collectMutatedProperties(List<Statement> body, Set<String> out) {
        if (body == null) return;
        for (Statement s : body) collectMutatedInStmt(s, out);
    }

    private static void collectMutatedInStmt(Statement s, Set<String> out) {
        if (s instanceof AssignmentStatement as) {
            if (as.target() instanceof PropertyAccessExpr pa) out.add(pa.property());
            collectMutatedInExpr(as.target(), out);
            collectMutatedInExpr(as.value(), out);
        } else if (s instanceof VariableDeclStatement vds) {
            collectMutatedInExpr(vds.init(), out);
        } else if (s instanceof ExpressionStatement es) {
            collectMutatedInExpr(es.expression(), out);
        } else if (s instanceof ReturnStatement rs) {
            collectMutatedInExpr(rs.value(), out);
        } else if (s instanceof IfStatement ifs) {
            collectMutatedInExpr(ifs.condition(), out);
            collectMutatedProperties(ifs.thenBody(), out);
            collectMutatedProperties(ifs.elseBody(), out);
        } else if (s instanceof ForStatement fs) {
            if (fs.init() != null) collectMutatedInExpr(fs.init().init(), out);
            collectMutatedInExpr(fs.condition(), out);
            if (fs.update() != null) collectMutatedInStmt(fs.update(), out);
            collectMutatedProperties(fs.body(), out);
        }
    }

    private static void collectMutatedInExpr(Expression e, Set<String> out) {
        if (e == null) return;
        if (e instanceof BinaryExpr be) {
            collectMutatedInExpr(be.left(), out);
            collectMutatedInExpr(be.right(), out);
        } else if (e instanceof UnaryExpr ue) {
            collectMutatedInExpr(ue.operand(), out);
        } else if (e instanceof CallExpr ce) {
            collectMutatedInExpr(ce.callee(), out);
            for (Expression a : ce.args()) collectMutatedInExpr(a, out);
        } else if (e instanceof MemberExpr me) {
            collectMutatedInExpr(me.object(), out);
        } else if (e instanceof TernaryExpr te) {
            collectMutatedInExpr(te.condition(), out);
            collectMutatedInExpr(te.consequent(), out);
            collectMutatedInExpr(te.alternate(), out);
        } else if (e instanceof IndexAccessExpr ia) {
            collectMutatedInExpr(ia.object(), out);
            collectMutatedInExpr(ia.index(), out);
        } else if (e instanceof IncrementExpr ie) {
            if (ie.operand() instanceof PropertyAccessExpr pa) out.add(pa.property());
            collectMutatedInExpr(ie.operand(), out);
        } else if (e instanceof DecrementExpr de) {
            if (de.operand() instanceof PropertyAccessExpr pa) out.add(pa.property());
            collectMutatedInExpr(de.operand(), out);
        } else if (e instanceof ArrayLiteralExpr ale) {
            for (Expression el : ale.elements()) collectMutatedInExpr(el, out);
        }
    }

    // ===================================================================
    // Number-literal helper (handles `0x...` hex prefix + decimal)
    // ===================================================================

    private static BigInteger parseLongLiteral(String value) {
        if (value == null || value.isEmpty()) return BigInteger.ZERO;
        if (value.startsWith("0x") || value.startsWith("0X")) {
            return new BigInteger(value.substring(2), 16);
        }
        return new BigInteger(value);
    }
}
