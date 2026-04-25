package runar.compiler.frontend;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
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
 * Parses {@code .runar.go} source into a Rúnar {@link ContractNode}.
 *
 * <p>Hand-written tokenizer + recursive-descent parser that mirrors the
 * Python reference parser at {@code compilers/python/runar_compiler/frontend/parser_go.py},
 * the Go reference parser at {@code compilers/go/frontend/parser_gocontract.go},
 * and the Ruby port at {@code compilers/ruby/lib/runar_compiler/frontend/parser_go.rb}.
 * All produce byte-identical Rúnar AST for the same {@code .runar.go} source.
 *
 * <p>Recognises the Rúnar subset of Go:
 * <ul>
 *   <li>{@code package <name>} declaration (skipped)</li>
 *   <li>{@code import} declarations (skipped)</li>
 *   <li>{@code type Name struct { ... }} carrying optional struct tags
 *       (e.g. {@code `runar:"readonly"`})</li>
 *   <li>{@code func (c *Name) Method(...)} method declarations</li>
 *   <li>{@code func (c *Name) init()} as the property-initializer source —
 *       its assignments to {@code c.Field} are folded into the matching
 *       {@link PropertyNode#initializer()}</li>
 *   <li>statements: {@code if}/{@code else}, {@code for}, {@code return},
 *       {@code var}, {@code const}, {@code :=} short declarations,
 *       {@code =} and compound assignments, {@code ++}/{@code --}</li>
 *   <li>full Go expression operator set (arithmetic, comparison,
 *       logical, bitwise, shift) lowered into the canonical Rúnar binary
 *       operators</li>
 * </ul>
 */
public final class GoParser {

    private GoParser() {}

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /** Parse Go contract source into a Rúnar contract AST. */
    public static ContractNode parse(String source, String filename) throws ParseException {
        List<Token> tokens = tokenize(source);
        ParserState state = new ParserState(filename, tokens);
        ContractNode contract = state.parseFile();
        if (contract == null) {
            if (state.errors.isEmpty()) {
                throw new ParseException("no Rúnar contract struct found in Go source: " + filename);
            }
            throw new ParseException(String.join("; ", state.errors));
        }
        if (!state.errors.isEmpty()) {
            throw new ParseException(String.join("; ", state.errors));
        }
        return contract;
    }

    /** Checked exception for parse-time problems. */
    public static class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
    }

    // ------------------------------------------------------------------
    // Token kinds
    // ------------------------------------------------------------------

    private enum Tok {
        EOF, IDENT, NUMBER, STRING, BACKTICK_STRING,
        LBRACE, RBRACE, LPAREN, RPAREN, LBRACKET, RBRACKET,
        SEMICOLON, COMMA, DOT, COLON,
        ASSIGN, EQEQ, NOTEQ,
        LT, LTEQ, GT, GTEQ,
        PLUS, MINUS, STAR, SLASH, PERCENT,
        BANG, TILDE,
        AMP, PIPE, CARET,
        AMPAMP, PIPEPIPE,
        PLUSEQ, MINUSEQ, STAREQ, SLASHEQ, PERCENTEQ,
        PLUSPLUS, MINUSMINUS,
        COLONEQ,
        LSHIFT, RSHIFT
    }

    private static final class Token {
        final Tok kind;
        final String value;
        final int line;
        final int col;

        Token(Tok kind, String value, int line, int col) {
            this.kind = kind;
            this.value = value;
            this.line = line;
            this.col = col;
        }
    }

    // ------------------------------------------------------------------
    // Type / builtin maps (mirrors Python parser)
    // ------------------------------------------------------------------

    private static final Map<String, String> GO_TYPE_MAP = new HashMap<>();
    private static final Map<String, String> GO_NATIVE_TYPE_MAP = new HashMap<>();
    private static final Map<String, String> GO_BUILTIN_MAP = new HashMap<>();

    static {
        GO_TYPE_MAP.put("Int", "bigint");
        GO_TYPE_MAP.put("Bigint", "bigint");
        GO_TYPE_MAP.put("BigintBig", "bigint");
        GO_TYPE_MAP.put("Bool", "boolean");
        GO_TYPE_MAP.put("ByteString", "ByteString");
        GO_TYPE_MAP.put("PubKey", "PubKey");
        GO_TYPE_MAP.put("Sig", "Sig");
        GO_TYPE_MAP.put("Sha256", "Sha256");
        GO_TYPE_MAP.put("Sha256Digest", "Sha256");
        GO_TYPE_MAP.put("Ripemd160", "Ripemd160");
        GO_TYPE_MAP.put("Addr", "Addr");
        GO_TYPE_MAP.put("SigHashPreimage", "SigHashPreimage");
        GO_TYPE_MAP.put("RabinSig", "RabinSig");
        GO_TYPE_MAP.put("RabinPubKey", "RabinPubKey");
        GO_TYPE_MAP.put("Point", "Point");
        GO_TYPE_MAP.put("P256Point", "P256Point");
        GO_TYPE_MAP.put("P384Point", "P384Point");

        GO_NATIVE_TYPE_MAP.put("int64", "bigint");
        GO_NATIVE_TYPE_MAP.put("int", "bigint");
        GO_NATIVE_TYPE_MAP.put("bool", "boolean");

        GO_BUILTIN_MAP.put("Assert", "assert");
        GO_BUILTIN_MAP.put("Hash160", "hash160");
        GO_BUILTIN_MAP.put("Hash256", "hash256");
        GO_BUILTIN_MAP.put("Sha256", "sha256");
        GO_BUILTIN_MAP.put("Sha256Hash", "sha256");
        GO_BUILTIN_MAP.put("Ripemd160", "ripemd160");
        GO_BUILTIN_MAP.put("CheckSig", "checkSig");
        GO_BUILTIN_MAP.put("CheckMultiSig", "checkMultiSig");
        GO_BUILTIN_MAP.put("CheckPreimage", "checkPreimage");
        GO_BUILTIN_MAP.put("VerifyRabinSig", "verifyRabinSig");
        GO_BUILTIN_MAP.put("VerifyWOTS", "verifyWOTS");
        GO_BUILTIN_MAP.put("VerifySLHDSA_SHA2_128s", "verifySLHDSA_SHA2_128s");
        GO_BUILTIN_MAP.put("VerifySLHDSA_SHA2_128f", "verifySLHDSA_SHA2_128f");
        GO_BUILTIN_MAP.put("VerifySLHDSA_SHA2_192s", "verifySLHDSA_SHA2_192s");
        GO_BUILTIN_MAP.put("VerifySLHDSA_SHA2_192f", "verifySLHDSA_SHA2_192f");
        GO_BUILTIN_MAP.put("VerifySLHDSA_SHA2_256s", "verifySLHDSA_SHA2_256s");
        GO_BUILTIN_MAP.put("VerifySLHDSA_SHA2_256f", "verifySLHDSA_SHA2_256f");
        GO_BUILTIN_MAP.put("Num2Bin", "num2bin");
        GO_BUILTIN_MAP.put("Bin2Num", "bin2num");
        GO_BUILTIN_MAP.put("ExtractLocktime", "extractLocktime");
        GO_BUILTIN_MAP.put("ExtractOutputHash", "extractOutputHash");
        GO_BUILTIN_MAP.put("ExtractSequence", "extractSequence");
        GO_BUILTIN_MAP.put("ExtractVersion", "extractVersion");
        GO_BUILTIN_MAP.put("ExtractAmount", "extractAmount");
        GO_BUILTIN_MAP.put("ExtractHashPrevouts", "extractHashPrevouts");
        GO_BUILTIN_MAP.put("ExtractHashSequence", "extractHashSequence");
        GO_BUILTIN_MAP.put("ExtractOutpoint", "extractOutpoint");
        GO_BUILTIN_MAP.put("ExtractScriptCode", "extractScriptCode");
        GO_BUILTIN_MAP.put("ExtractInputIndex", "extractInputIndex");
        GO_BUILTIN_MAP.put("ExtractSigHashType", "extractSigHashType");
        GO_BUILTIN_MAP.put("ExtractOutputs", "extractOutputs");
        GO_BUILTIN_MAP.put("AddOutput", "addOutput");
        GO_BUILTIN_MAP.put("AddRawOutput", "addRawOutput");
        GO_BUILTIN_MAP.put("AddDataOutput", "addDataOutput");
        GO_BUILTIN_MAP.put("GetStateScript", "getStateScript");
        GO_BUILTIN_MAP.put("Safediv", "safediv");
        GO_BUILTIN_MAP.put("Safemod", "safemod");
        GO_BUILTIN_MAP.put("Clamp", "clamp");
        GO_BUILTIN_MAP.put("Sign", "sign");
        GO_BUILTIN_MAP.put("Pow", "pow");
        GO_BUILTIN_MAP.put("MulDiv", "mulDiv");
        GO_BUILTIN_MAP.put("PercentOf", "percentOf");
        GO_BUILTIN_MAP.put("Sqrt", "sqrt");
        GO_BUILTIN_MAP.put("Gcd", "gcd");
        GO_BUILTIN_MAP.put("Divmod", "divmod");
        GO_BUILTIN_MAP.put("Log2", "log2");
        GO_BUILTIN_MAP.put("ToBool", "bool");
        GO_BUILTIN_MAP.put("ReverseBytes", "reverseBytes");
        GO_BUILTIN_MAP.put("EcAdd", "ecAdd");
        GO_BUILTIN_MAP.put("EcMul", "ecMul");
        GO_BUILTIN_MAP.put("EcMulGen", "ecMulGen");
        GO_BUILTIN_MAP.put("EcNegate", "ecNegate");
        GO_BUILTIN_MAP.put("EcOnCurve", "ecOnCurve");
        GO_BUILTIN_MAP.put("EcModReduce", "ecModReduce");
        GO_BUILTIN_MAP.put("EcEncodeCompressed", "ecEncodeCompressed");
        GO_BUILTIN_MAP.put("EcMakePoint", "ecMakePoint");
        GO_BUILTIN_MAP.put("EcPointX", "ecPointX");
        GO_BUILTIN_MAP.put("EcPointY", "ecPointY");
        GO_BUILTIN_MAP.put("EC_P", "EC_P");
        GO_BUILTIN_MAP.put("EC_N", "EC_N");
        GO_BUILTIN_MAP.put("EC_G", "EC_G");
        GO_BUILTIN_MAP.put("VerifyECDSAP256", "verifyECDSA_P256");
        GO_BUILTIN_MAP.put("P256Add", "p256Add");
        GO_BUILTIN_MAP.put("P256Mul", "p256Mul");
        GO_BUILTIN_MAP.put("P256MulGen", "p256MulGen");
        GO_BUILTIN_MAP.put("P256Negate", "p256Negate");
        GO_BUILTIN_MAP.put("P256OnCurve", "p256OnCurve");
        GO_BUILTIN_MAP.put("P256EncodeCompressed", "p256EncodeCompressed");
        GO_BUILTIN_MAP.put("VerifyECDSAP384", "verifyECDSA_P384");
        GO_BUILTIN_MAP.put("P384Add", "p384Add");
        GO_BUILTIN_MAP.put("P384Mul", "p384Mul");
        GO_BUILTIN_MAP.put("P384MulGen", "p384MulGen");
        GO_BUILTIN_MAP.put("P384Negate", "p384Negate");
        GO_BUILTIN_MAP.put("P384OnCurve", "p384OnCurve");
        GO_BUILTIN_MAP.put("P384EncodeCompressed", "p384EncodeCompressed");
    }

    private static TypeNode mapGoType(String name) {
        String mapped = GO_TYPE_MAP.get(name);
        if (mapped != null) {
            return primitiveOrCustom(mapped);
        }
        mapped = GO_NATIVE_TYPE_MAP.get(name);
        if (mapped != null) {
            return primitiveOrCustom(mapped);
        }
        try {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(name));
        } catch (IllegalArgumentException ignored) {
            return new CustomType(name);
        }
    }

    private static TypeNode primitiveOrCustom(String canonical) {
        try {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(canonical));
        } catch (IllegalArgumentException ignored) {
            return new CustomType(canonical);
        }
    }

    private static String mapGoBuiltin(String name) {
        String mapped = GO_BUILTIN_MAP.get(name);
        if (mapped != null) return mapped;
        return goFieldToCamel(name);
    }

    private static String goFieldToCamel(String name) {
        if (name == null || name.isEmpty()) return name;
        char first = name.charAt(0);
        if (Character.isLowerCase(first)) return name;
        return Character.toLowerCase(first) + name.substring(1);
    }

    // ------------------------------------------------------------------
    // Tokenizer
    // ------------------------------------------------------------------

    private static List<Token> tokenize(String source) {
        List<Token> tokens = new ArrayList<>();
        int line = 1;
        int col = 0;
        int i = 0;
        int n = source.length();

        while (i < n) {
            char ch = source.charAt(i);

            // Newlines — Go automatic semicolon insertion.
            if (ch == '\n' || ch == '\r') {
                int curLine = line;
                int curCol = col;
                if (ch == '\r') {
                    i++;
                    if (i < n && source.charAt(i) == '\n') i++;
                } else {
                    i++;
                }
                line++;
                col = 0;
                Tok last = lastSignificantKind(tokens);
                if (last == Tok.IDENT || last == Tok.NUMBER || last == Tok.STRING
                    || last == Tok.BACKTICK_STRING || last == Tok.RPAREN
                    || last == Tok.RBRACKET || last == Tok.RBRACE
                    || last == Tok.PLUSPLUS || last == Tok.MINUSMINUS) {
                    tokens.add(new Token(Tok.SEMICOLON, ";", curLine, curCol));
                }
                continue;
            }

            if (ch == ' ' || ch == '\t') {
                i++;
                col++;
                continue;
            }

            // Line comment
            if (ch == '/' && i + 1 < n && source.charAt(i + 1) == '/') {
                while (i < n && source.charAt(i) != '\n' && source.charAt(i) != '\r') i++;
                continue;
            }

            // Block comment
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

            // Backtick raw string (struct tags)
            if (ch == '`') {
                i++;
                col++;
                int start = i;
                while (i < n && source.charAt(i) != '`') {
                    if (source.charAt(i) == '\n') {
                        line++;
                        col = 0;
                    } else {
                        col++;
                    }
                    i++;
                }
                String val = source.substring(start, i);
                if (i < n) {
                    i++;
                    col++;
                }
                tokens.add(new Token(Tok.BACKTICK_STRING, val, line, startCol));
                continue;
            }

            // Double-quoted string
            if (ch == '"') {
                i++;
                col++;
                int start = i;
                while (i < n && source.charAt(i) != '"') {
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
                tokens.add(new Token(Tok.STRING, processGoStringEscapes(val), line, startCol));
                continue;
            }

            // Number
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
                tokens.add(new Token(Tok.NUMBER, numStr, line, startCol));
                continue;
            }

            // Identifier
            if (isIdentStart(ch)) {
                int start = i;
                while (i < n && isIdentPart(source.charAt(i))) {
                    i++;
                    col++;
                }
                tokens.add(new Token(Tok.IDENT, source.substring(start, i), line, startCol));
                continue;
            }

            // Two-character operators
            if (i + 1 < n) {
                String two = source.substring(i, i + 2);
                Tok twoKind = twoCharOp(two);
                if (twoKind != null) {
                    tokens.add(new Token(twoKind, two, line, startCol));
                    i += 2;
                    col += 2;
                    continue;
                }
            }

            // Single-character operators
            Tok oneKind = oneCharOp(ch);
            if (oneKind != null) {
                tokens.add(new Token(oneKind, String.valueOf(ch), line, startCol));
                i++;
                col++;
                continue;
            }

            // Unknown — skip to keep parsing robust.
            i++;
            col++;
        }

        tokens.add(new Token(Tok.EOF, "", line, col));
        return tokens;
    }

    private static Tok lastSignificantKind(List<Token> tokens) {
        for (int j = tokens.size() - 1; j >= 0; j--) {
            return tokens.get(j).kind;
        }
        return Tok.EOF;
    }

    private static boolean isIdentStart(char c) {
        return Character.isLetter(c) || c == '_';
    }

    private static boolean isIdentPart(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static Tok twoCharOp(String s) {
        switch (s) {
            case "==": return Tok.EQEQ;
            case "!=": return Tok.NOTEQ;
            case "<=": return Tok.LTEQ;
            case ">=": return Tok.GTEQ;
            case "+=": return Tok.PLUSEQ;
            case "-=": return Tok.MINUSEQ;
            case "*=": return Tok.STAREQ;
            case "/=": return Tok.SLASHEQ;
            case "%=": return Tok.PERCENTEQ;
            case "&&": return Tok.AMPAMP;
            case "||": return Tok.PIPEPIPE;
            case "++": return Tok.PLUSPLUS;
            case "--": return Tok.MINUSMINUS;
            case ":=": return Tok.COLONEQ;
            case "<<": return Tok.LSHIFT;
            case ">>": return Tok.RSHIFT;
            default: return null;
        }
    }

    private static Tok oneCharOp(char c) {
        switch (c) {
            case '(': return Tok.LPAREN;
            case ')': return Tok.RPAREN;
            case '[': return Tok.LBRACKET;
            case ']': return Tok.RBRACKET;
            case '{': return Tok.LBRACE;
            case '}': return Tok.RBRACE;
            case ',': return Tok.COMMA;
            case '.': return Tok.DOT;
            case ':': return Tok.COLON;
            case ';': return Tok.SEMICOLON;
            case '=': return Tok.ASSIGN;
            case '<': return Tok.LT;
            case '>': return Tok.GT;
            case '+': return Tok.PLUS;
            case '-': return Tok.MINUS;
            case '*': return Tok.STAR;
            case '/': return Tok.SLASH;
            case '%': return Tok.PERCENT;
            case '!': return Tok.BANG;
            case '~': return Tok.TILDE;
            case '&': return Tok.AMP;
            case '|': return Tok.PIPE;
            case '^': return Tok.CARET;
            default: return null;
        }
    }

    private static String processGoStringEscapes(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(i + 1);
                switch (n) {
                    case 'n': out.append('\n'); i += 2; break;
                    case 't': out.append('\t'); i += 2; break;
                    case 'r': out.append('\r'); i += 2; break;
                    case '\\': out.append('\\'); i += 2; break;
                    case '"': out.append('"'); i += 2; break;
                    case 'x':
                        if (i + 3 < s.length()) {
                            String hex = s.substring(i + 2, i + 4);
                            try {
                                out.append((char) Integer.parseInt(hex, 16));
                            } catch (NumberFormatException ex) {
                                out.append(s, i, i + 4);
                            }
                            i += 4;
                        } else {
                            out.append(c);
                            i++;
                        }
                        break;
                    default:
                        out.append(c);
                        i++;
                }
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    // ------------------------------------------------------------------
    // Parser state
    // ------------------------------------------------------------------

    private static final class ParserState {
        final String fileName;
        final List<Token> tokens;
        int pos = 0;
        final List<String> errors = new ArrayList<>();
        String receiverName = "";

        ParserState(String fileName, List<Token> tokens) {
            this.fileName = fileName;
            this.tokens = tokens;
        }

        // -- Token helpers ------------------------------------------------

        Token peek() {
            if (pos < tokens.size()) return tokens.get(pos);
            return new Token(Tok.EOF, "", 0, 0);
        }

        Token peekAt(int offset) {
            int idx = pos + offset;
            if (idx >= 0 && idx < tokens.size()) return tokens.get(idx);
            return new Token(Tok.EOF, "", 0, 0);
        }

        Token advance() {
            Token t = peek();
            if (pos < tokens.size()) pos++;
            return t;
        }

        boolean check(Tok kind) {
            return peek().kind == kind;
        }

        boolean checkIdent(String value) {
            Token t = peek();
            return t.kind == Tok.IDENT && t.value.equals(value);
        }

        boolean match(Tok kind) {
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

        Token expect(Tok kind) {
            Token t = advance();
            if (t.kind != kind) {
                addError("line " + t.line + ": expected " + kind + ", got " + t.kind + " (" + t.value + ")");
            }
            return t;
        }

        Token expectIdent(String value) {
            Token t = advance();
            if (t.kind != Tok.IDENT || !t.value.equals(value)) {
                addError("line " + t.line + ": expected '" + value + "', got " + t.value);
            }
            return t;
        }

        void addError(String msg) {
            errors.add(msg);
        }

        SourceLocation loc() {
            Token t = peek();
            return new SourceLocation(fileName, t.line, t.col);
        }

        void skipSemicolons() {
            while (check(Tok.SEMICOLON)) advance();
        }

        // -- Top-level ----------------------------------------------------

        ContractNode parseFile() {
            skipSemicolons();
            if (matchIdent("package")) {
                expect(Tok.IDENT);
                skipSemicolons();
            }
            while (checkIdent("import")) {
                skipImport();
                skipSemicolons();
            }

            String contractName = "";
            String parentClass = "";
            List<PropertyNode> properties = new ArrayList<>();
            List<MethodNode> methods = new ArrayList<>();
            boolean structFound = false;

            while (!check(Tok.EOF)) {
                skipSemicolons();
                if (check(Tok.EOF)) break;

                if (checkIdent("type")) {
                    TypeDeclResult result = parseTypeDecl();
                    if (result != null) {
                        contractName = result.name;
                        parentClass = result.parent;
                        properties = result.properties;
                        structFound = true;
                    }
                } else if (checkIdent("func")) {
                    MethodNode m = parseFuncDecl(contractName);
                    if (m != null) methods.add(m);
                } else {
                    advance();
                }
            }

            if (!structFound) return null;

            // Fold init() into property initializers.
            List<MethodNode> finalMethods = new ArrayList<>();
            for (MethodNode m : methods) {
                if (m.name().equals("init") && m.params().isEmpty()) {
                    for (Statement stmt : m.body()) {
                        if (stmt instanceof AssignmentStatement as
                            && as.target() instanceof PropertyAccessExpr pae) {
                            for (int i = 0; i < properties.size(); i++) {
                                PropertyNode prop = properties.get(i);
                                if (prop.name().equals(pae.property())) {
                                    properties.set(i, new PropertyNode(
                                        prop.name(),
                                        prop.type(),
                                        prop.readonly(),
                                        as.value(),
                                        prop.sourceLocation(),
                                        prop.syntheticArrayChain()
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    finalMethods.add(m);
                }
            }
            methods = finalMethods;

            // Auto-generated constructor (only non-initialised properties).
            List<ParamNode> constructorParams = new ArrayList<>();
            List<Expression> superArgs = new ArrayList<>();
            for (PropertyNode p : properties) {
                if (p.initializer() != null) continue;
                constructorParams.add(new ParamNode(p.name(), p.type()));
                superArgs.add(new Identifier(p.name()));
            }
            SourceLocation synthLoc = new SourceLocation(fileName, 1, 1);
            List<Statement> constructorBody = new ArrayList<>();
            constructorBody.add(new ExpressionStatement(
                new CallExpr(new Identifier("super"), superArgs),
                synthLoc
            ));
            for (PropertyNode p : properties) {
                if (p.initializer() != null) continue;
                constructorBody.add(new AssignmentStatement(
                    new PropertyAccessExpr(p.name()),
                    new Identifier(p.name()),
                    synthLoc
                ));
            }

            ParentClass parent = ParentClass.fromCanonical(parentClass);
            MethodNode constructor = new MethodNode(
                "constructor",
                constructorParams,
                constructorBody,
                Visibility.PUBLIC,
                synthLoc
            );
            return new ContractNode(contractName, parent, properties, constructor, methods, fileName);
        }

        void skipImport() {
            expectIdent("import");
            if (check(Tok.LPAREN)) {
                advance();
                int depth = 1;
                while (depth > 0 && !check(Tok.EOF)) {
                    if (check(Tok.LPAREN)) {
                        depth++;
                    } else if (check(Tok.RPAREN)) {
                        depth--;
                        if (depth == 0) {
                            advance();
                            break;
                        }
                    }
                    advance();
                }
            } else {
                if (check(Tok.IDENT)) advance();
                if (check(Tok.STRING)) advance();
            }
        }

        // -- Type declaration --------------------------------------------

        static final class TypeDeclResult {
            final String name;
            final String parent;
            final List<PropertyNode> properties;

            TypeDeclResult(String name, String parent, List<PropertyNode> properties) {
                this.name = name;
                this.parent = parent;
                this.properties = properties;
            }
        }

        TypeDeclResult parseTypeDecl() {
            expectIdent("type");
            Token nameTok = expect(Tok.IDENT);
            String typeName = nameTok.value;

            if (!matchIdent("struct")) {
                skipToSemicolonOrBrace();
                return null;
            }

            expect(Tok.LBRACE);

            String parentClass = "";
            List<PropertyNode> properties = new ArrayList<>();

            while (!check(Tok.RBRACE) && !check(Tok.EOF)) {
                skipSemicolons();
                if (check(Tok.RBRACE)) break;

                SourceLocation fieldLoc = loc();

                if (check(Tok.IDENT) && isEmbedField()) {
                    String embedName = parseEmbeddedType();
                    if ("SmartContract".equals(embedName)) {
                        parentClass = "SmartContract";
                    } else if ("StatefulSmartContract".equals(embedName)) {
                        parentClass = "StatefulSmartContract";
                    }
                    skipSemicolons();
                    continue;
                }

                if (check(Tok.IDENT)) {
                    List<String> fieldNames = new ArrayList<>();
                    fieldNames.add(advance().value);
                    while (match(Tok.COMMA)) {
                        Token nt = expect(Tok.IDENT);
                        fieldNames.add(nt.value);
                    }
                    TypeNode fieldType = parseType();

                    boolean readonly = false;
                    if (check(Tok.BACKTICK_STRING)) {
                        Token tagTok = advance();
                        if (tagTok.value.contains("runar:\"readonly\"")) {
                            readonly = true;
                        }
                    }

                    for (String fname : fieldNames) {
                        String propName = goFieldToCamel(fname);
                        properties.add(new PropertyNode(
                            propName,
                            fieldType,
                            readonly,
                            null,
                            fieldLoc,
                            null
                        ));
                    }

                    skipSemicolons();
                    continue;
                }

                advance();
                skipSemicolons();
            }

            expect(Tok.RBRACE);

            if (parentClass.isEmpty()) return null;
            return new TypeDeclResult(typeName, parentClass, properties);
        }

        boolean isEmbedField() {
            Token tok1 = peekAt(0);
            Token tok2 = peekAt(1);
            Token tok3 = peekAt(2);
            Token tok4 = peekAt(3);

            if (tok1.kind == Tok.IDENT && tok2.kind == Tok.DOT
                && tok3.kind == Tok.IDENT
                && (tok4.kind == Tok.SEMICOLON || tok4.kind == Tok.RBRACE
                    || tok4.kind == Tok.EOF || tok4.kind == Tok.BACKTICK_STRING)) {
                if (!tok1.value.isEmpty() && Character.isLowerCase(tok1.value.charAt(0))) {
                    return true;
                }
            }
            return false;
        }

        String parseEmbeddedType() {
            Token pkgTok = advance();
            expect(Tok.DOT);
            Token selTok = expect(Tok.IDENT);
            if (check(Tok.BACKTICK_STRING)) advance();
            if ("runar".equals(pkgTok.value)) return selTok.value;
            return pkgTok.value + "." + selTok.value;
        }

        // -- Type parsing -------------------------------------------------

        TypeNode parseType() {
            if (check(Tok.LBRACKET)) {
                advance();
                if (check(Tok.NUMBER)) {
                    Token sizeTok = advance();
                    int size;
                    try {
                        size = Integer.parseInt(sizeTok.value);
                    } catch (NumberFormatException ex) {
                        size = 0;
                        addError("line " + sizeTok.line + ": array size must be integer");
                    }
                    expect(Tok.RBRACKET);
                    TypeNode elem = parseType();
                    return new FixedArrayType(elem, size);
                }
                expect(Tok.RBRACKET);
                return parseType();
            }

            if (check(Tok.STAR)) {
                advance();
                return parseType();
            }

            Token tok = peek();
            if (tok.kind != Tok.IDENT) {
                addError("line " + tok.line + ": expected type name, got " + tok.value);
                advance();
                return new CustomType("unknown");
            }

            String name = tok.value;
            advance();

            if (check(Tok.DOT)) {
                advance();
                Token selTok = expect(Tok.IDENT);
                if ("runar".equals(name)) return mapGoType(selTok.value);
                return new CustomType(name + "." + selTok.value);
            }

            return mapGoType(name);
        }

        // -- Func declaration --------------------------------------------

        MethodNode parseFuncDecl(String contractName) {
            SourceLocation location = loc();
            expectIdent("func");

            boolean hasReceiver = false;
            boolean isContractMethod = false;
            String localReceiverName = "";

            if (check(Tok.LPAREN)) {
                int saved = pos;
                if (looksLikeReceiver()) {
                    hasReceiver = true;
                    pos = saved;
                    expect(Tok.LPAREN);
                    Token recvTok = expect(Tok.IDENT);
                    localReceiverName = recvTok.value;
                    match(Tok.STAR);
                    Token typeTok = expect(Tok.IDENT);
                    expect(Tok.RPAREN);
                    if (typeTok.value.equals(contractName)) {
                        isContractMethod = true;
                    }
                } else {
                    pos = saved;
                }
            }

            Token nameTok = expect(Tok.IDENT);
            String funcName = nameTok.value;

            this.receiverName = hasReceiver ? localReceiverName : "";

            Visibility visibility;
            if (hasReceiver && isContractMethod) {
                visibility = Character.isUpperCase(funcName.charAt(0)) ? Visibility.PUBLIC : Visibility.PRIVATE;
            } else if (!hasReceiver) {
                if ("init".equals(funcName) || "main".equals(funcName)) {
                    skipFuncBody();
                    return null;
                }
                if (Character.isUpperCase(funcName.charAt(0))) {
                    skipFuncBody();
                    return null;
                }
                visibility = Visibility.PRIVATE;
            } else {
                skipFuncBody();
                return null;
            }

            String methodName = goFieldToCamel(funcName);
            List<ParamNode> params = parseFuncParams();

            if (!check(Tok.LBRACE)) {
                skipReturnType();
            }
            List<Statement> body = parseBlock();

            return new MethodNode(methodName, params, body, visibility, location);
        }

        boolean looksLikeReceiver() {
            int saved = pos;
            advance();
            if (!check(Tok.IDENT)) {
                pos = saved;
                return false;
            }
            advance();
            if (check(Tok.STAR)) {
                advance();
                if (check(Tok.IDENT)) {
                    advance();
                    if (check(Tok.RPAREN)) {
                        advance();
                        boolean result = check(Tok.IDENT);
                        pos = saved;
                        return result;
                    }
                }
            } else if (check(Tok.IDENT)) {
                advance();
                if (check(Tok.RPAREN)) {
                    advance();
                    boolean result = check(Tok.IDENT);
                    pos = saved;
                    return result;
                }
            }
            pos = saved;
            return false;
        }

        List<ParamNode> parseFuncParams() {
            expect(Tok.LPAREN);
            List<ParamNode> params = new ArrayList<>();

            while (!check(Tok.RPAREN) && !check(Tok.EOF)) {
                List<String> names = new ArrayList<>();
                Token nameTok = expect(Tok.IDENT);
                names.add(nameTok.value);

                while (match(Tok.COMMA)) {
                    if (isParamNameBeforeType()) {
                        Token nt = expect(Tok.IDENT);
                        names.add(nt.value);
                    } else {
                        break;
                    }
                }

                TypeNode paramType = parseType();
                for (String pname : names) {
                    params.add(new ParamNode(goFieldToCamel(pname), paramType));
                }

                if (!match(Tok.COMMA)) break;
            }

            expect(Tok.RPAREN);
            return params;
        }

        boolean isParamNameBeforeType() {
            if (!check(Tok.IDENT)) return false;
            Token tok = peekAt(0);
            Token tok2 = peekAt(1);

            if ("runar".equals(tok.value)
                || GO_TYPE_MAP.containsKey(tok.value)
                || GO_NATIVE_TYPE_MAP.containsKey(tok.value)) {
                return false;
            }
            if (tok2.kind == Tok.DOT) return false;
            if (Character.isUpperCase(tok.value.charAt(0)) && tok2.kind != Tok.COMMA) {
                return false;
            }
            if (tok2.kind == Tok.COMMA || tok2.kind == Tok.RPAREN) {
                return Character.isLowerCase(tok.value.charAt(0));
            }
            return Character.isLowerCase(tok.value.charAt(0));
        }

        void skipReturnType() {
            if (check(Tok.LPAREN)) {
                advance();
                int depth = 1;
                while (depth > 0 && !check(Tok.EOF)) {
                    if (check(Tok.LPAREN)) depth++;
                    else if (check(Tok.RPAREN)) depth--;
                    advance();
                }
            } else {
                while (!check(Tok.LBRACE) && !check(Tok.EOF)) advance();
            }
        }

        void skipFuncBody() {
            if (check(Tok.LPAREN)) {
                advance();
                int depth = 1;
                while (depth > 0 && !check(Tok.EOF)) {
                    if (check(Tok.LPAREN)) depth++;
                    else if (check(Tok.RPAREN)) depth--;
                    advance();
                }
            }
            if (!check(Tok.LBRACE)) skipReturnType();
            if (check(Tok.LBRACE)) {
                advance();
                int depth = 1;
                while (depth > 0 && !check(Tok.EOF)) {
                    if (check(Tok.LBRACE)) depth++;
                    else if (check(Tok.RBRACE)) depth--;
                    advance();
                }
            }
            skipSemicolons();
        }

        void skipToSemicolonOrBrace() {
            while (!check(Tok.SEMICOLON) && !check(Tok.LBRACE) && !check(Tok.EOF)) advance();
            skipSemicolons();
        }

        // -- Block / statements ------------------------------------------

        List<Statement> parseBlock() {
            expect(Tok.LBRACE);
            List<Statement> stmts = new ArrayList<>();
            while (!check(Tok.RBRACE) && !check(Tok.EOF)) {
                skipSemicolons();
                if (check(Tok.RBRACE) || check(Tok.EOF)) break;
                Statement s = parseStatement();
                if (s != null) stmts.add(s);
            }
            expect(Tok.RBRACE);
            skipSemicolons();
            return stmts;
        }

        Statement parseStatement() {
            SourceLocation location = loc();
            if (checkIdent("if")) return parseIf(location);
            if (checkIdent("for")) return parseFor(location);
            if (checkIdent("return")) return parseReturn(location);
            if (checkIdent("var")) return parseVarDecl(location);
            if (checkIdent("const")) return parseConstDecl(location);
            return parseExprStatement(location, true);
        }

        Statement parseIf(SourceLocation loc) {
            expectIdent("if");
            Expression condition = parseExpression();
            List<Statement> thenBlock = parseBlock();
            List<Statement> elseBlock = null;
            if (matchIdent("else")) {
                if (checkIdent("if")) {
                    SourceLocation elifLoc = loc();
                    Statement elif = parseIf(elifLoc);
                    elseBlock = new ArrayList<>();
                    elseBlock.add(elif);
                } else {
                    elseBlock = parseBlock();
                }
            }
            return new IfStatement(condition, thenBlock, elseBlock, loc);
        }

        Statement parseFor(SourceLocation loc) {
            expectIdent("for");
            if (check(Tok.LBRACE)) {
                List<Statement> body = parseBlock();
                return new ForStatement(null, null, null, body, loc);
            }

            if (hasSemicolonBeforeBrace()) {
                Statement initStmt = parseSimpleStatement(loc);
                VariableDeclStatement initDecl = (initStmt instanceof VariableDeclStatement v) ? v : null;
                expect(Tok.SEMICOLON);

                Expression cond = parseExpression();
                expect(Tok.SEMICOLON);

                Statement update = parseSimpleStatement(loc);
                List<Statement> body = parseBlock();
                return new ForStatement(initDecl, cond, update, body, loc);
            } else {
                Expression cond = parseExpression();
                List<Statement> body = parseBlock();
                return new ForStatement(null, cond, null, body, loc);
            }
        }

        boolean hasSemicolonBeforeBrace() {
            int saved = pos;
            int depth = 0;
            while (saved < tokens.size()) {
                Token tok = tokens.get(saved);
                if (tok.kind == Tok.LPAREN) depth++;
                else if (tok.kind == Tok.RPAREN) depth--;
                else if (tok.kind == Tok.SEMICOLON && depth == 0) return true;
                else if (tok.kind == Tok.LBRACE && depth == 0) return false;
                else if (tok.kind == Tok.EOF) return false;
                saved++;
            }
            return false;
        }

        Statement parseSimpleStatement(SourceLocation loc) {
            return parseExprStatement(loc, false);
        }

        Statement parseReturn(SourceLocation loc) {
            expectIdent("return");
            Expression value = null;
            if (!check(Tok.SEMICOLON) && !check(Tok.RBRACE) && !check(Tok.EOF)) {
                value = parseExpression();
            }
            skipSemicolons();
            return new ReturnStatement(value, loc);
        }

        Statement parseVarDecl(SourceLocation loc) {
            expectIdent("var");
            Token nameTok = expect(Tok.IDENT);
            String varName = goFieldToCamel(nameTok.value);

            TypeNode typeNode = null;
            if (!check(Tok.ASSIGN)) typeNode = parseType();

            Expression init = null;
            if (match(Tok.ASSIGN)) init = parseExpression();
            if (init == null) init = new BigIntLiteral(BigInteger.ZERO);

            skipSemicolons();
            return new VariableDeclStatement(varName, typeNode, init, loc);
        }

        Statement parseConstDecl(SourceLocation loc) {
            expectIdent("const");
            Token nameTok = expect(Tok.IDENT);
            String varName = goFieldToCamel(nameTok.value);

            TypeNode typeNode = null;
            if (!check(Tok.ASSIGN)) typeNode = parseType();

            expect(Tok.ASSIGN);
            Expression init = parseExpression();

            skipSemicolons();
            return new VariableDeclStatement(varName, typeNode, init, loc);
        }

        Statement parseExprStatement(SourceLocation loc, boolean consumeSemis) {
            Expression expr = parseExpression();
            if (expr == null) {
                advance();
                if (consumeSemis) skipSemicolons();
                return null;
            }

            // Short variable declaration: name := expr
            if (match(Tok.COLONEQ)) {
                Expression init = parseExpression();
                String name = "";
                if (expr instanceof Identifier id) name = id.name();
                if (consumeSemis) skipSemicolons();
                return new VariableDeclStatement(name, null, init, loc);
            }

            // Plain assignment
            if (match(Tok.ASSIGN)) {
                Expression value = parseExpression();
                if (consumeSemis) skipSemicolons();
                return new AssignmentStatement(expr, value, loc);
            }

            // Compound assignments
            Tok[] compoundTokens = {Tok.PLUSEQ, Tok.MINUSEQ, Tok.STAREQ, Tok.SLASHEQ, Tok.PERCENTEQ};
            Expression.BinaryOp[] compoundOps = {
                Expression.BinaryOp.ADD, Expression.BinaryOp.SUB,
                Expression.BinaryOp.MUL, Expression.BinaryOp.DIV, Expression.BinaryOp.MOD
            };
            for (int i = 0; i < compoundTokens.length; i++) {
                if (match(compoundTokens[i])) {
                    Expression right = parseExpression();
                    if (consumeSemis) skipSemicolons();
                    Expression value = new BinaryExpr(compoundOps[i], expr, right);
                    return new AssignmentStatement(expr, value, loc);
                }
            }

            // Postfix increment/decrement
            if (match(Tok.PLUSPLUS)) {
                if (consumeSemis) skipSemicolons();
                return new ExpressionStatement(new IncrementExpr(expr, false), loc);
            }
            if (match(Tok.MINUSMINUS)) {
                if (consumeSemis) skipSemicolons();
                return new ExpressionStatement(new DecrementExpr(expr, false), loc);
            }

            if (consumeSemis) skipSemicolons();
            return new ExpressionStatement(expr, loc);
        }

        // -- Expressions --------------------------------------------------

        Expression parseExpression() {
            return parseOr();
        }

        Expression parseOr() {
            Expression left = parseAnd();
            while (match(Tok.PIPEPIPE)) {
                Expression right = parseAnd();
                left = new BinaryExpr(Expression.BinaryOp.OR, left, right);
            }
            return left;
        }

        Expression parseAnd() {
            Expression left = parseBitwiseOr();
            while (match(Tok.AMPAMP)) {
                Expression right = parseBitwiseOr();
                left = new BinaryExpr(Expression.BinaryOp.AND, left, right);
            }
            return left;
        }

        Expression parseBitwiseOr() {
            Expression left = parseBitwiseXor();
            while (match(Tok.PIPE)) {
                Expression right = parseBitwiseXor();
                left = new BinaryExpr(Expression.BinaryOp.BIT_OR, left, right);
            }
            return left;
        }

        Expression parseBitwiseXor() {
            Expression left = parseBitwiseAnd();
            while (match(Tok.CARET)) {
                Expression right = parseBitwiseAnd();
                left = new BinaryExpr(Expression.BinaryOp.BIT_XOR, left, right);
            }
            return left;
        }

        Expression parseBitwiseAnd() {
            Expression left = parseEquality();
            while (match(Tok.AMP)) {
                Expression right = parseEquality();
                left = new BinaryExpr(Expression.BinaryOp.BIT_AND, left, right);
            }
            return left;
        }

        Expression parseEquality() {
            Expression left = parseComparison();
            while (true) {
                if (match(Tok.EQEQ)) {
                    Expression right = parseComparison();
                    left = new BinaryExpr(Expression.BinaryOp.EQ, left, right);
                } else if (match(Tok.NOTEQ)) {
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
                if (match(Tok.LT)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.LT, left, right);
                } else if (match(Tok.LTEQ)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.LE, left, right);
                } else if (match(Tok.GT)) {
                    Expression right = parseShift();
                    left = new BinaryExpr(Expression.BinaryOp.GT, left, right);
                } else if (match(Tok.GTEQ)) {
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
                if (match(Tok.LSHIFT)) {
                    Expression right = parseAdditive();
                    left = new BinaryExpr(Expression.BinaryOp.SHL, left, right);
                } else if (match(Tok.RSHIFT)) {
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
                if (match(Tok.PLUS)) {
                    Expression right = parseMultiplicative();
                    left = new BinaryExpr(Expression.BinaryOp.ADD, left, right);
                } else if (match(Tok.MINUS)) {
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
                if (match(Tok.STAR)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.MUL, left, right);
                } else if (match(Tok.SLASH)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.DIV, left, right);
                } else if (match(Tok.PERCENT)) {
                    Expression right = parseUnary();
                    left = new BinaryExpr(Expression.BinaryOp.MOD, left, right);
                } else {
                    break;
                }
            }
            return left;
        }

        Expression parseUnary() {
            if (match(Tok.MINUS)) {
                return new UnaryExpr(Expression.UnaryOp.NEG, parseUnary());
            }
            if (match(Tok.BANG)) {
                return new UnaryExpr(Expression.UnaryOp.NOT, parseUnary());
            }
            if (match(Tok.CARET)) {
                // Go uses ^ as unary bitwise NOT.
                return new UnaryExpr(Expression.UnaryOp.BIT_NOT, parseUnary());
            }
            return parsePostfix();
        }

        Expression parsePostfix() {
            Expression expr = parsePrimary();
            while (true) {
                if (match(Tok.DOT)) {
                    Token propTok = expect(Tok.IDENT);
                    String propName = goFieldToCamel(propTok.value);

                    if (check(Tok.LPAREN)) {
                        List<Expression> args = parseCallArgs();
                        if (expr instanceof Identifier id && isReceiver(id.name())) {
                            expr = new CallExpr(
                                new MemberExpr(new Identifier("this"), propName),
                                args
                            );
                        } else {
                            expr = new CallExpr(new MemberExpr(expr, propName), args);
                        }
                    } else {
                        if (expr instanceof Identifier id && isReceiver(id.name())) {
                            expr = new PropertyAccessExpr(propName);
                        } else {
                            expr = new MemberExpr(expr, propName);
                        }
                    }
                } else if (check(Tok.LBRACKET)) {
                    advance();
                    Expression index = parseExpression();
                    expect(Tok.RBRACKET);
                    expr = new IndexAccessExpr(expr, index);
                } else if (check(Tok.LPAREN)) {
                    List<Expression> args = parseCallArgs();
                    expr = new CallExpr(expr, args);
                } else {
                    break;
                }
            }
            return expr;
        }

        boolean isReceiver(String name) {
            if (!receiverName.isEmpty() && name.equals(receiverName)) return true;
            return "c".equals(name) || "self".equals(name);
        }

        Expression parsePrimary() {
            Token tok = peek();

            if (tok.kind == Tok.NUMBER) {
                advance();
                return parseNumberLiteral(tok.value);
            }
            if (tok.kind == Tok.STRING) {
                advance();
                return new ByteStringLiteral(tok.value);
            }
            if (tok.kind == Tok.IDENT) {
                advance();
                String name = tok.value;

                if ("true".equals(name)) return new BoolLiteral(true);
                if ("false".equals(name)) return new BoolLiteral(false);

                if ("runar".equals(name) && check(Tok.DOT)) {
                    advance();
                    Token selTok = expect(Tok.IDENT);
                    String selName = selTok.value;

                    if (("Int".equals(selName) || "Bigint".equals(selName)
                        || "BigintBig".equals(selName) || "Bool".equals(selName))
                        && check(Tok.LPAREN)) {
                        List<Expression> args = parseCallArgs();
                        if (args.size() == 1) return args.get(0);
                        return new BigIntLiteral(BigInteger.ZERO);
                    }

                    if ("ByteString".equals(selName) && check(Tok.LPAREN)) {
                        int savedPos = pos;
                        advance(); // consume '('
                        if (check(Tok.STRING)) {
                            Token strTok = advance();
                            if (check(Tok.RPAREN)) {
                                advance();
                                String hex = bytesToHex(strTok.value);
                                return new ByteStringLiteral(hex);
                            }
                        }
                        pos = savedPos;
                        List<Expression> args = parseCallArgs();
                        if (args.size() == 1) return args.get(0);
                        return new CallExpr(new Identifier("byteString"), args);
                    }

                    String builtinName = mapGoBuiltin(selName);

                    if (("EC_P".equals(selName) || "EC_N".equals(selName) || "EC_G".equals(selName))
                        && !check(Tok.LPAREN)) {
                        return new Identifier(builtinName);
                    }

                    if ("TxPreimage".equals(selName)) {
                        return new PropertyAccessExpr("txPreimage");
                    }

                    if (check(Tok.LPAREN)) {
                        List<Expression> args = parseCallArgs();
                        return new CallExpr(new Identifier(builtinName), args);
                    }
                    return new Identifier(builtinName);
                }

                if (isReceiver(name)) {
                    return new Identifier(name);
                }

                String converted = goFieldToCamel(name);

                if (check(Tok.LPAREN)) {
                    List<Expression> args = parseCallArgs();
                    return new CallExpr(new Identifier(converted), args);
                }
                return new Identifier(converted);
            }

            if (tok.kind == Tok.LPAREN) {
                advance();
                Expression e = parseExpression();
                expect(Tok.RPAREN);
                return e;
            }

            addError("line " + tok.line + ": unexpected token " + tok.value);
            advance();
            return new BigIntLiteral(BigInteger.ZERO);
        }

        List<Expression> parseCallArgs() {
            expect(Tok.LPAREN);
            List<Expression> args = new ArrayList<>();
            while (!check(Tok.RPAREN) && !check(Tok.EOF)) {
                args.add(parseExpression());
                if (!match(Tok.COMMA)) break;
            }
            expect(Tok.RPAREN);
            return args;
        }
    }

    private static Expression parseNumberLiteral(String s) {
        try {
            BigInteger v;
            if (s.startsWith("0x") || s.startsWith("0X")) {
                v = new BigInteger(s.substring(2), 16);
            } else {
                v = new BigInteger(s);
            }
            return new BigIntLiteral(v);
        } catch (NumberFormatException ex) {
            return new BigIntLiteral(BigInteger.ZERO);
        }
    }

    /** Hex-encode a string's raw bytes as latin-1 (mirrors Python's {@code .encode("latin-1")}). */
    private static String bytesToHex(String s) {
        StringBuilder out = new StringBuilder(s.length() * 2);
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i) & 0xff;
            out.append(Character.forDigit((c >> 4) & 0xf, 16));
            out.append(Character.forDigit(c & 0xf, 16));
        }
        return out.toString();
    }
}
