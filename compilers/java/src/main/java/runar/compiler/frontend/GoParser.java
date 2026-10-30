package runar.compiler.frontend;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.IdentityHashMap;
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
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;
import runar.compiler.passes.SighashDirective;

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
        // DoS-bound size guard, enforced at every exported parser entry, not
        // just ParserDispatch.parse. N-136.
        try {
            InputLimits.assertSourceBytesUnderLimit(source);
        } catch (ParserDispatch.ParseException e) {
            throw new ParseException(e.getMessage());
        }
        List<String> lex = new ArrayList<>();
        List<GoDirective> directives = new ArrayList<>();
        List<Token> tokens = tokenize(source, filename, lex, directives);
        // F-011: refuse an unterminated literal before parsing what follows it.
        if (!lex.isEmpty()) throw new ParseException(String.join("; ", lex));
        ParserState state = new ParserState(filename, tokens);
        state.directives.addAll(directives);
        // F-213: measures (A) and (B).
        ContractNode contract = SourceNesting.guard(state::parseFile, ParseException::new);
        String collision = state.idents.message();
        if (contract != null && collision != null) state.errors.add(collision);
        if (contract == null) {
            if (state.errors.isEmpty()) {
                throw new ParseException(GO_NO_CONTRACT_MESSAGE);
            }
            throw new ParseException(String.join("; ", state.errors));
        }
        if (!state.errors.isEmpty()) {
            throw new ParseException(String.join("; ", state.errors));
        }
        return contract;
    }

    // F-010 diagnostics -- emitted verbatim by every tier's .runar.go parser
    // (TS reference: goNoContractMessage / goMultipleContractsMessage /
    // goForeignReceiverMessage in packages/runar-compiler/src/passes/01-parse-go.ts).
    static final String GO_NO_CONTRACT_MESSAGE = "no Rúnar contract struct found in Go source";

    static String goMultipleContractsMessage(String first, String second) {
        return "multiple Rúnar contract structs found in Go source: '" + first + "' and '" + second + "'; "
            + "exactly one struct may embed runar.SmartContract, runar.StatefulSmartContract or runar.UnsafeSmartContract";
    }

    static String goForeignReceiverMessage(String method, String receiverType, String contract) {
        return "method '" + method + "' has receiver type '" + receiverType + "', not the contract type '"
            + contract + "'; methods on other types are not allowed";
    }

    /** A parsed {@code func}: the method, its Go name, and its receiver type or null. */
    private record FuncDecl(MethodNode method, String goName, String receiverType) {}

    /**
     * N-093: a Go DSL directive comment {@code //runar:<name> <args>} (Go's own
     * {@code //go:} convention: no space after {@code //}). {@code tokenIndex}
     * is the index of the first token after the comment, so a directive
     * attaches to the declaration that follows it, with only comments and
     * blank lines in between. Mirrors GoDirective in the TS reference
     * (01-parse-go.ts).
     */
    private record GoDirective(String name, String args, int tokenIndex) {}

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
        /** Tok.STRING only (N-435): the Go string's bytes, one per char (latin-1 style). */
        String raw;

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

    /**
     * The Rúnar binary operator each {@code BigintBig} helper stands for.
     *
     * <p>{@code runar.BigintBig} is {@code *big.Int} in packages/runar-go and Go has no
     * operator overloading, so a {@code .runar.go} contract carrying arbitrary-precision
     * values spells {@code a === b} as {@code runar.BigintBigEqual(a, b)} -- and it has to
     * emit the script the operator emits. Mirrors {@code bigintBigOpFor} in
     * compilers/go/frontend/parser_gocontract.go and its peers in the TS, Rust, Python, Zig
     * and Ruby tiers, plus the eleven helpers in packages/runar-go/runar.go. The rewrite
     * lived only in compilers/go until R-Bigint, although all seven tiers parse
     * {@code .runar.go} -- a frontend-parity break no fixture exercised.
     */
    private static final Map<String, Expression.BinaryOp> GO_BIGINTBIG_OPS = new HashMap<>();

    static {
        GO_BIGINTBIG_OPS.put("BigintBigLess", Expression.BinaryOp.LT);
        GO_BIGINTBIG_OPS.put("BigintBigLessEq", Expression.BinaryOp.LE);
        GO_BIGINTBIG_OPS.put("BigintBigGreater", Expression.BinaryOp.GT);
        GO_BIGINTBIG_OPS.put("BigintBigGreaterEq", Expression.BinaryOp.GE);
        GO_BIGINTBIG_OPS.put("BigintBigEqual", Expression.BinaryOp.EQ);
        GO_BIGINTBIG_OPS.put("BigintBigNotEqual", Expression.BinaryOp.NEQ);
        GO_BIGINTBIG_OPS.put("BigintBigAdd", Expression.BinaryOp.ADD);
        GO_BIGINTBIG_OPS.put("BigintBigSub", Expression.BinaryOp.SUB);
        GO_BIGINTBIG_OPS.put("BigintBigMul", Expression.BinaryOp.MUL);
        GO_BIGINTBIG_OPS.put("BigintBigMod", Expression.BinaryOp.MOD);
        GO_BIGINTBIG_OPS.put("BigintBigDiv", Expression.BinaryOp.DIV);
    }

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
        GO_TYPE_MAP.put("Ripemd160Hash", "Ripemd160");
        GO_TYPE_MAP.put("Addr", "Addr");
        GO_TYPE_MAP.put("SigHashPreimage", "SigHashPreimage");
        GO_TYPE_MAP.put("RabinSig", "RabinSig");
        GO_TYPE_MAP.put("RabinPubKey", "RabinPubKey");
        GO_TYPE_MAP.put("Point", "Point");
        GO_TYPE_MAP.put("P256Point", "P256Point");
        GO_TYPE_MAP.put("P384Point", "P384Point");

        GO_NATIVE_TYPE_MAP.put("int64", "bigint");
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
        // the *Big peers of num2bin / bin2num. They lower to the SAME builtins as
        // Num2Bin / Bin2Num, exactly as compilers/go has always done: the suffix names
        // a different Go RUNTIME type (*big.Int, so the Go-side mock does not truncate),
        // not a different Script operation. Six tiers fell through to the default rule
        // and produced `num2BinBig` / `bin2NumBig`, names no builtin registry has
        // (R-Bigint).
        GO_BUILTIN_MAP.put("Num2BinBig", "num2bin");
        GO_BUILTIN_MAP.put("Bin2NumBig", "bin2num");

        // the *Big peers of abs / gcd. Same rule as Num2BinBig / Bin2NumBig above: the
        // suffix names a different Go RUNTIME type (*big.Int, so the Go-side mock does
        // not narrow at MinInt64), not a different Script operation -- OP_ABS and the
        // gcd builtin are arbitrary-width after Genesis. These were mapped in ZERO
        // tiers while `Abs(math.MinInt64)` and `Gcd(math.MinInt64, 0)` in
        // packages/runar-go panic telling the author to use them, naming the .runar.go
        // parser as the thing that lowers them.
        GO_BUILTIN_MAP.put("AbsBig", "abs");
        GO_BUILTIN_MAP.put("GcdBig", "gcd");
        // `Int2Str` is the spelling docs/formats/go.md documents. Without it the
        // default rule camel-cases the leading character to `int2Str`, which is
        // registered nowhere — the call is rejected as an unknown function.
        GO_BUILTIN_MAP.put("Int2Str", "int2str");
        GO_BUILTIN_MAP.put("ExtractLocktime", "extractLocktime");
        GO_BUILTIN_MAP.put("ExtractOutputHash", "extractOutputHash");
        // Intent sub-covenant intrinsics (BSVM Phase 13).
        GO_BUILTIN_MAP.put("ExtractPrevOutputScript", "extractPrevOutputScript");
        GO_BUILTIN_MAP.put("RequireOutputP2PKH", "requireOutputP2PKH");
        GO_BUILTIN_MAP.put("CurrentBlockHeight", "currentBlockHeight");
        GO_BUILTIN_MAP.put("ContinuationAmount", "continuationAmount");
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

    private static List<Token> tokenize(
        String source, String filename, List<String> lex, List<GoDirective> directives
    ) {
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
                int start = i;
                while (i < n && source.charAt(i) != '\n' && source.charAt(i) != '\r') i++;
                // N-093: `//runar:<name> <args>` is a directive, not prose.
                String text = source.substring(start, i);
                if (text.startsWith("//runar:")) {
                    String body = text.substring("//runar:".length());
                    int nameEnd = 0;
                    while (nameEnd < body.length() && body.charAt(nameEnd) != ' ' && body.charAt(nameEnd) != '\t') {
                        nameEnd++;
                    }
                    directives.add(new GoDirective(body.substring(0, nameEnd), body.substring(nameEnd), tokens.size()));
                }
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
                int tickLine = line;
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
                // F-011: this literal may span lines; only end of file leaves
                // it unterminated.
                if (i < n) {
                    i++;
                    col++;
                } else {
                    lex.add(LexDiag.at(filename, tickLine, startCol, LexDiag.UNTERMINATED_STRING_LITERAL));
                }
                tokens.add(new Token(Tok.BACKTICK_STRING, val, line, startCol));
                continue;
            }

            // Double-quoted string
            if (ch == '"') {
                i++;
                col++;
                int start = i;
                // F-011: a literal that reaches a line break (escaped or not) or end
                // of file is unterminated; it must never run on into the next lines.
                while (i < n && source.charAt(i) != '"' && source.charAt(i) != '\n' && source.charAt(i) != '\r') {
                    if (source.charAt(i) == '\\') {
                        if (i + 1 >= n || source.charAt(i + 1) == '\n' || source.charAt(i + 1) == '\r') break;
                        i++;
                        col++;
                    }
                    i++;
                    col++;
                }
                String val = source.substring(start, Math.min(i, n));
                if (i < n && source.charAt(i) == '"') {
                    i++;
                    col++;
                } else {
                    lex.add(LexDiag.at(filename, line, startCol, LexDiag.UNTERMINATED_STRING_LITERAL));
                }
                // N-437: decode with Go's string-literal rules; an escape Go
                // refuses is refused here too.
                GoString dec = decodeGoString(val);
                if (dec.error() != null) {
                    lex.add(LexDiag.at(filename, line, startCol, dec.error()));
                }
                Token stringTok = new Token(Tok.STRING, dec.val(), line, startCol);
                stringTok.raw = dec.raw();
                tokens.add(stringTok);
                continue;
            }

            // Numbers (F-026): the whole glued [0-9A-Za-z_] run is one literal.
            if (ch >= '0' && ch <= '9') {
                IntLiteral.Scan sc = IntLiteral.lex("go", source, i, lex, filename, line, startCol);
                col += sc.end() - i;
                i = sc.end();
                tokens.add(new Token(Tok.NUMBER, sc.value(), line, startCol));
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

            // N-214: an unrecognised character is refused, as the TS reference
            // does, rather than skipped: skipping compiled `a + § b` as `a + b`.
            lex.add(LexDiag.at(filename, line, startCol, "Unexpected character '" + ch + "'"));
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
        // N-407: ASCII only, as the TS reference; a non-ASCII letter is
        // refused as an unexpected character.
        return LexDiag.isAsciiLetter(c) || c == '_';
    }

    private static boolean isIdentPart(char c) {
        return LexDiag.isAsciiLetter(c) || (c >= '0' && c <= '9') || c == '_';
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

    /**
     * N-437: the decoded body of a Go interpreted string literal, per
     * https://go.dev/ref/spec#String_literals. {@code raw} is the Go string's
     * BYTES, one latin-1 char per byte: literal text and {@code \}u / {@code \}U
     * escapes are UTF-8 encoded, {@code \}xNN and octal {@code \}NNN (at most
     * 255) are the single byte (what {@code []byte(s)} yields in Go).
     * {@code val} keeps one char per escape for the bare-literal (hex) path.
     * {@code error} is the shared invalid-escape diagnostic for an escape Go
     * refuses, or null.
     */
    private record GoString(String val, String raw, String error) {}

    private static void appendUtf8(StringBuilder raw, int cp) {
        for (byte bt : new String(Character.toChars(cp)).getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            raw.append((char) (bt & 0xff));
        }
    }

    private static GoString decodeGoString(String s) {
        StringBuilder val = new StringBuilder(s.length());
        StringBuilder raw = new StringBuilder(s.length());
        int i = 0;
        int len = s.length();
        while (i < len) {
            char c = s.charAt(i);
            if (c != '\\') {
                int cp = s.codePointAt(i);
                val.appendCodePoint(cp);
                appendUtf8(raw, cp);
                i += Character.charCount(cp);
                continue;
            }
            char e = i + 1 < len ? s.charAt(i + 1) : 0;
            int simple = switch (e) {
                case 'a' -> 0x07;
                case 'b' -> 0x08;
                case 'f' -> 0x0c;
                case 'n' -> 0x0a;
                case 'r' -> 0x0d;
                case 't' -> 0x09;
                case 'v' -> 0x0b;
                case '\\' -> '\\';
                case '"' -> '"';
                default -> -1;
            };
            if (simple >= 0) {
                val.append((char) simple);
                raw.append((char) simple);
                i += 2;
            } else if (e == 'x') {
                if (i + 4 > len || !isHexDigit(s.charAt(i + 2)) || !isHexDigit(s.charAt(i + 3))) {
                    return new GoString(val.toString(), raw.toString(), LexDiag.invalidEscapeSequence("\\x"));
                }
                int b = Integer.parseInt(s.substring(i + 2, i + 4), 16);
                val.append((char) b);
                raw.append((char) b);
                i += 4;
            } else if (e == 'u' || e == 'U') {
                int width = e == 'u' ? 4 : 8;
                boolean ok = i + 2 + width <= len;
                for (int k = 0; ok && k < width; k++) ok = isHexDigit(s.charAt(i + 2 + k));
                long cp = ok ? Long.parseLong(s.substring(i + 2, i + 2 + width), 16) : -1;
                if (cp < 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
                    return new GoString(val.toString(), raw.toString(), LexDiag.invalidEscapeSequence("\\" + e));
                }
                val.appendCodePoint((int) cp);
                appendUtf8(raw, (int) cp);
                i += 2 + width;
            } else if (e >= '0' && e <= '7') {
                int j = i + 1;
                while (j < len && j < i + 4 && s.charAt(j) >= '0' && s.charAt(j) <= '7') j++;
                String run = s.substring(i + 1, j);
                if (run.length() < 3 || Integer.parseInt(run, 8) > 0xff) {
                    return new GoString(val.toString(), raw.toString(), LexDiag.invalidEscapeSequence("\\" + run));
                }
                int b = Integer.parseInt(run, 8);
                val.append((char) b);
                raw.append((char) b);
                i += 4;
            } else {
                String esc = e == 0 ? "\\" : "\\" + new String(Character.toChars(s.codePointAt(i + 1)));
                return new GoString(val.toString(), raw.toString(), LexDiag.invalidEscapeSequence(esc));
            }
        }
        return new GoString(val.toString(), raw.toString(), null);
    }

    // ------------------------------------------------------------------
    // Parser state
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // N-056 -- ambiguous operator precedence (mirrors 01-parse-go.ts)
    // ------------------------------------------------------------------
    //
    // Go: `* / % << >> & &^` > `+ - | ^` > comparisons > `&&` > `||`. C
    // ladder (this parser): MulDiv > AddSub > Shift > Comparison > Equality >
    // BitAnd > BitXor > BitOr > And > Or. For `x OP1 y OP2 z` a scheme groups
    // left iff prec(OP1) >= prec(OP2). The ordered (OP1 class, OP2 class)
    // pairs on which the schemes disagree: 23 class pairs, 72 operator pairs.
    // `&^` lexes as `&` over a prefix `^`, i.e. `&`.

    static final Set<String> GO_AMBIGUOUS_PRECEDENCE_PAIRS = Set.of(
        "shift mul", "shift add",
        "and mul", "and shift", "and add", "and rel", "and eq",
        "add shift", "add and",
        "or add", "or xor", "or rel", "or eq",
        "xor add", "xor rel", "xor eq",
        "rel and", "rel or", "rel xor",
        "eq and", "eq or", "eq xor", "eq rel"
    );

    private static String goPrecedenceClass(Expression.BinaryOp op) {
        return switch (op) {
            case MUL, DIV, MOD -> "mul";
            case SHL, SHR -> "shift";
            case BIT_AND -> "and";
            case ADD, SUB -> "add";
            case BIT_OR -> "or";
            case BIT_XOR -> "xor";
            case LT, LE, GT, GE -> "rel";
            case EQ, NEQ -> "eq";
            case AND -> "land";
            case OR -> "lor";
        };
    }

    static boolean isGoAmbiguousPrecedence(Expression.BinaryOp first, Expression.BinaryOp second) {
        return GO_AMBIGUOUS_PRECEDENCE_PAIRS.contains(goPrecedenceClass(first) + " " + goPrecedenceClass(second));
    }

    static String goAmbiguousPrecedenceMessage(Expression.BinaryOp first, Expression.BinaryOp second) {
        return "ambiguous operator precedence in .runar.go: `a " + goSpelling(first) + " b "
            + goSpelling(second) + " c` groups differently under Go precedence than in "
            + "Rúnar's other surfaces; add parentheses";
    }

    private static String goSpelling(Expression.BinaryOp op) {
        return switch (op) {
            case EQ -> "==";
            case NEQ -> "!=";
            default -> op.canonical();
        };
    }

    /** N-093: the {@code runar} key of a struct tag. */
    private static final java.util.regex.Pattern RUNAR_TAG =
        java.util.regex.Pattern.compile("(?:^|\\s)runar:\"([^\"]*)\"");

    /**
     * N-093: the segment rule of extractSighashDirective: the flag text
     * starts with a space/tab and holds only flag-name characters, {@code |},
     * spaces and tabs.
     */
    private static final java.util.regex.Pattern GO_SIGHASH_ARGS =
        java.util.regex.Pattern.compile("[ \t][A-Za-z0-9_| \t]*");

    private static final class ParserState {
        final String fileName;
        final List<Token> tokens;
        int pos = 0;
        final List<String> errors = new ArrayList<>();
        /** N-448: token indexes of string literals whose bare use is legal (a runar.Asm body). */
        final Set<Integer> bareLiteralOk = new java.util.HashSet<>();
        /** F-213 measure (A): parse nesting. */
        final SourceNesting.Counter nest = new SourceNesting.Counter();
        /** N-056: expression operands (primaries, calls, parenthesised groups). */
        final Set<Expression> goAtoms = Collections.newSetFromMap(new IdentityHashMap<>());
        String receiverName = "";
        /** F-017: declared (spelling, Rúnar name) pairs. */
        final IdentifierCollision.Declared idents = new IdentifierCollision.Declared();
        /** N-093: every {@code //runar:} directive in the file, in source order. */
        final List<GoDirective> directives = new ArrayList<>();
        final Set<GoDirective> consumedDirectives = Collections.newSetFromMap(new IdentityHashMap<>());

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
            List<FuncDecl> funcs = new ArrayList<>();
            boolean structFound = false;

            while (!check(Tok.EOF)) {
                skipSemicolons();
                if (check(Tok.EOF)) break;

                if (checkIdent("type")) {
                    TypeDeclResult result = parseTypeDecl();
                    if (result != null) {
                        if (structFound) {
                            // F-010: exactly one contract struct; never merged.
                            addError(goMultipleContractsMessage(contractName, result.name));
                            continue;
                        }
                        contractName = result.name;
                        parentClass = result.parent;
                        properties = result.properties;
                        structFound = true;
                    }
                } else if (checkIdent("func")) {
                    FuncDecl f = parseFuncDecl();
                    if (f != null) funcs.add(f);
                } else {
                    advance();
                }
            }
            reportStrayDirectives();

            if (!structFound) return null;

            // F-010: a method whose receiver (value or pointer) is not the
            // contract type is refused -- checked once the whole file is read,
            // so a method declared before the contract struct is judged the same way.
            List<MethodNode> methods = new ArrayList<>();
            for (FuncDecl f : funcs) {
                if (f.receiverType() != null && !f.receiverType().equals(contractName)) {
                    addError(goForeignReceiverMessage(f.goName(), f.receiverType(), contractName));
                    continue;
                }
                methods.add(f.method());
            }

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
                                        prop.syntheticArrayChain(),
                                        prop.embedAlways()
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
                    } else if ("UnsafeSmartContract".equals(embedName)) {
                        parentClass = "UnsafeSmartContract";
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

                    // Struct tag. The `runar` key holds comma-separated options
                    // (N-093): `readonly`, and `embedAlways` — the native
                    // spelling of the `@embedAlways` directive — in any order.
                    boolean readonly = false;
                    boolean embedAlways = false;
                    if (check(Tok.BACKTICK_STRING)) {
                        Token tagTok = advance();
                        java.util.regex.Matcher runarTag = RUNAR_TAG.matcher(tagTok.value);
                        if (runarTag.find()) {
                            for (String o : runarTag.group(1).split(",", -1)) {
                                String option = o.trim();
                                if (option.equals("readonly")) readonly = true;
                                if (option.equals("embedAlways")) embedAlways = true;
                            }
                        }
                    }

                    for (String fname : fieldNames) {
                        String propName = idents.declare(fname, goFieldToCamel(fname));
                        properties.add(new PropertyNode(
                            propName,
                            fieldType,
                            readonly,
                            null,
                            fieldLoc,
                            null,
                            embedAlways
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
                    TypeNode elem = nest.nested(this::parseType);
                    return new FixedArrayType(elem, size);
                }
                expect(Tok.RBRACKET);
                return nest.nested(this::parseType);
            }

            if (check(Tok.STAR)) {
                advance();
                return nest.nested(this::parseType);
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

        /**
         * Parse one {@code func}. The receiver type ({@code *} stripped, or null
         * for a free function) is checked against the contract in parseFile (F-010).
         */
        FuncDecl parseFuncDecl() {
            SourceLocation location = loc();
            // N-093: the `//runar:sighash` directives directly above this func.
            int funcTokenIndex = pos;
            expectIdent("func");

            boolean hasReceiver = false;
            String receiverType = null;
            String localReceiverName = "";

            if (check(Tok.LPAREN)) {
                int saved = pos;
                if (looksLikeReceiver()) {
                    hasReceiver = true;
                    pos = saved;
                    expect(Tok.LPAREN);
                    Token recvTok = expect(Tok.IDENT);
                    if (check(Tok.RPAREN)) {
                        // N-018: unnamed receiver `(Type)` -- the only
                        // identifier is the type. Real Go forbids
                        // referencing it in the method body at all, so no
                        // name is bound.
                        localReceiverName = "";
                        receiverType = recvTok.value;
                    } else {
                        localReceiverName = recvTok.value;
                        match(Tok.STAR);
                        Token typeTok = expect(Tok.IDENT);
                        receiverType = typeTok.value;
                    }
                    expect(Tok.RPAREN);
                } else {
                    pos = saved;
                }
            }

            Token nameTok = expect(Tok.IDENT);
            String funcName = nameTok.value;

            this.receiverName = hasReceiver ? localReceiverName : "";

            Visibility visibility;
            if (hasReceiver) {
                visibility = Character.isUpperCase(funcName.charAt(0)) ? Visibility.PUBLIC : Visibility.PRIVATE;
            } else {
                // Standalone functions: skip init and main. F-010: an exported
                // standalone function is a private helper, as in the TS reference.
                if ("init".equals(funcName) || "main".equals(funcName)) {
                    // N-093: refused as on a private func, as the TS
                    // reference (which parses these as private helpers) does.
                    SighashDirective.Result skipped = SighashDirective.resolveNativeSighash(
                        goFieldToCamel(funcName), false, takeSighashDirectives(funcTokenIndex));
                    if (skipped != null && skipped.isError()) addError(skipped.error());
                    skipFuncBody();
                    return null;
                }
                visibility = Visibility.PRIVATE;
            }

            String methodName = idents.declare(funcName, goFieldToCamel(funcName));
            List<ParamNode> params = parseFuncParams();

            if (!check(Tok.LBRACE)) {
                checkReturnType(methodName, visibility == Visibility.PUBLIC);
                skipReturnType();
            }
            List<Statement> body = parseBlock();

            SighashDirective.Result sighash = SighashDirective.resolveNativeSighash(
                methodName, visibility == Visibility.PUBLIC, takeSighashDirectives(funcTokenIndex));
            if (sighash != null && sighash.isError()) addError(sighash.error());

            return new FuncDecl(new MethodNode(methodName, params, body, visibility, location,
                sighash == null || sighash.isError() ? null : sighash.value()), funcName, receiverType);
        }

        /**
         * N-093: the flag specs of the {@code //runar:sighash} directives
         * attached to the declaration starting at token {@code tokenIndex}
         * ({@code null} for a malformed one).
         */
        List<String> takeSighashDirectives(int tokenIndex) {
            List<String> specs = new ArrayList<>();
            for (GoDirective d : directives) {
                if (d.tokenIndex() != tokenIndex || !d.name().equals("sighash")) continue;
                consumedDirectives.add(d);
                specs.add(d.args().isEmpty() || GO_SIGHASH_ARGS.matcher(d.args()).matches() ? d.args() : null);
            }
            return specs;
        }

        /** N-093: refuse every directive that is unknown or attached to no func. */
        void reportStrayDirectives() {
            for (GoDirective d : directives) {
                if (consumedDirectives.contains(d)) continue;
                addError(d.name().equals("sighash")
                    ? SighashDirective.lostDirectiveMessage("@sighash")
                    : SighashDirective.unknownGoDirectiveMessage(d.name() + d.args()));
            }
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
            } else if (check(Tok.RPAREN)) {
                // N-018: unnamed receiver `(Type)` -- only the type, no
                // receiver name.
                advance();
                boolean result = check(Tok.IDENT);
                pos = saved;
                return result;
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
                    params.add(new ParamNode(idents.declare(pname, goFieldToCamel(pname)), paramType));
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

        /**
         * N-331: the AST keeps no return type, so a result type that is not a
         * Rúnar type is refused where it is spelled: a single type, or each
         * entry of a parenthesised result list (named or not). The rest is
         * left to {@link #skipReturnType()}.
         */
        void checkReturnType(String methodName, boolean isPublic) {
            if (check(Tok.LPAREN)) {
                advance();
                while (!check(Tok.RPAREN) && !check(Tok.LBRACE) && !check(Tok.EOF)) {
                    Token next = peekAt(1);
                    if (check(Tok.IDENT) && next.kind != Tok.DOT && next.kind != Tok.COMMA && next.kind != Tok.RPAREN) {
                        advance(); // result name
                    }
                    String unknownReturn = LexDiag.unknownReturnType(parseType(), methodName, isPublic);
                    if (unknownReturn != null) addError(unknownReturn);
                    if (!match(Tok.COMMA)) break;
                }
                match(Tok.RPAREN);
            } else {
                String unknownReturn = LexDiag.unknownReturnType(parseType(), methodName, isPublic);
                if (unknownReturn != null) addError(unknownReturn);
            }
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
                skipStatementSeparators();
                if (check(Tok.RBRACE) || check(Tok.EOF)) break;
                // N-153: a `{` cannot start a statement (no block statement,
                // and not a brace composite literal). Refuse it, as the TS
                // reference does, and skip the balanced braces.
                if (check(Tok.LBRACE)) {
                    addError("Unexpected token in expression: '{'");
                    int depth = 0;
                    do {
                        Tok kind = advance().kind;
                        if (kind == Tok.LBRACE) depth++;
                        else if (kind == Tok.RBRACE) depth--;
                    } while (depth > 0 && !check(Tok.EOF));
                    continue;
                }
                Statement s = parseStatement();
                if (s != null) stmts.add(s);
            }
            expect(Tok.RBRACE);
            skipStatementSeparators();
            return stmts;
        }

        /**
         * N-153: a {@code ;} that ends a statement on the same line separates
         * it from the next one (what go/parser accepts; an inserted newline
         * {@code ;} always does). Any other {@code ;} -- at the start of a
         * block, after another {@code ;}, or on a later line than the token
         * before it -- is an EMPTY statement, which the TS reference and the
         * Go tier refuse.
         */
        void skipStatementSeparators() {
            while (check(Tok.SEMICOLON)) {
                Token prev = pos > 0 ? tokens.get(pos - 1) : null;
                boolean separates = prev != null
                    && prev.kind != Tok.LBRACE && prev.kind != Tok.SEMICOLON
                    && prev.line == peek().line;
                if (!separates) addError("Unexpected token in expression: ';'");
                advance();
            }
        }

        Statement parseStatement() {
            return nest.nested(this::parseStatementInner);
        }

        Statement parseStatementInner() {
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
                    // F-213 A1: an else-if is a statement of the else branch.
                    Statement elif = nest.nested(() -> parseIf(elifLoc));
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
            match(Tok.SEMICOLON);
            return new ReturnStatement(value, loc);
        }

        Statement parseVarDecl(SourceLocation loc) {
            expectIdent("var");
            Token nameTok = expect(Tok.IDENT);
            String varName = idents.declare(nameTok.value, goFieldToCamel(nameTok.value));

            TypeNode typeNode = null;
            if (!check(Tok.ASSIGN)) typeNode = parseType();

            Expression init = null;
            if (match(Tok.ASSIGN)) init = parseExpression();
            if (init == null) init = new BigIntLiteral(BigInteger.ZERO);

            match(Tok.SEMICOLON);
            return new VariableDeclStatement(varName, typeNode, init, loc);
        }

        Statement parseConstDecl(SourceLocation loc) {
            expectIdent("const");
            Token nameTok = expect(Tok.IDENT);
            String varName = idents.declare(nameTok.value, goFieldToCamel(nameTok.value));

            TypeNode typeNode = null;
            if (!check(Tok.ASSIGN)) typeNode = parseType();

            expect(Tok.ASSIGN);
            Expression init = parseExpression();

            match(Tok.SEMICOLON);
            return new VariableDeclStatement(varName, typeNode, init, loc);
        }

        Statement parseExprStatement(SourceLocation loc, boolean consumeSemis) {
            Token targetTok = peek();
            Expression expr = parseExpression();
            if (expr == null) {
                advance();
                if (consumeSemis) match(Tok.SEMICOLON);
                return null;
            }

            // Short variable declaration: name := expr
            if (match(Tok.COLONEQ)) {
                Expression init = parseExpression();
                String name = "";
                if (expr instanceof Identifier id) {
                    name = id.name();
                    if (targetTok.kind == Tok.IDENT) idents.declare(targetTok.value, name);
                }
                if (consumeSemis) match(Tok.SEMICOLON);
                return new VariableDeclStatement(name, null, init, loc);
            }

            // Plain assignment
            if (match(Tok.ASSIGN)) {
                Expression value = parseExpression();
                if (consumeSemis) match(Tok.SEMICOLON);
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
                    if (consumeSemis) match(Tok.SEMICOLON);
                    Expression value = new BinaryExpr(compoundOps[i], expr, right);
                    return new AssignmentStatement(expr, value, loc);
                }
            }

            // Postfix increment/decrement
            if (match(Tok.PLUSPLUS)) {
                if (consumeSemis) match(Tok.SEMICOLON);
                return new ExpressionStatement(new IncrementExpr(expr, false), loc);
            }
            if (match(Tok.MINUSMINUS)) {
                if (consumeSemis) match(Tok.SEMICOLON);
                return new ExpressionStatement(new DecrementExpr(expr, false), loc);
            }

            if (consumeSemis) match(Tok.SEMICOLON);
            return new ExpressionStatement(expr, loc);
        }

        // -- Expressions --------------------------------------------------

        Expression parseExpression() {
            return nest.nested(this::parseExpressionInner);
        }

        Expression parseExpressionInner() {
            Expression expr = parseOr();
            // N-056: refuse an unparenthesised operand edge that groups
            // differently under Go precedence; nested ( ... ) groups were
            // checked by their own parseExpression call and are atoms here.
            Deque<Expression> work = new ArrayDeque<>();
            work.push(expr);
            while (!work.isEmpty()) {
                if (!(work.pop() instanceof BinaryExpr e) || goAtoms.contains(e)) continue;
                if (e.left() instanceof BinaryExpr l && !goAtoms.contains(l)) {
                    if (isGoAmbiguousPrecedence(l.op(), e.op())) {
                        addError(goAmbiguousPrecedenceMessage(l.op(), e.op()));
                        return expr;
                    }
                    work.push(l);
                }
                if (e.right() instanceof BinaryExpr r && !goAtoms.contains(r)) {
                    if (isGoAmbiguousPrecedence(e.op(), r.op())) {
                        addError(goAmbiguousPrecedenceMessage(e.op(), r.op()));
                        return expr;
                    }
                    work.push(r);
                }
            }
            return expr;
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
                return new UnaryExpr(Expression.UnaryOp.NEG, nest.nested(this::parseUnary));
            }
            if (match(Tok.BANG)) {
                return new UnaryExpr(Expression.UnaryOp.NOT, nest.nested(this::parseUnary));
            }
            if (match(Tok.CARET)) {
                // Go uses ^ as unary bitwise NOT.
                return new UnaryExpr(Expression.UnaryOp.BIT_NOT, nest.nested(this::parseUnary));
            }
            Expression expr = parsePostfix();
            goAtoms.add(expr); // N-056: an operand is an atom
            return expr;
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
            // N-018: this must be an exact match on the actual declared
            // receiver name, never a hardcoded "c"/"self" -- that wrongly
            // turned ANY same-spelled parameter or local into a
            // self-reference even when the receiver was named something
            // else, or unnamed (receiverName == "", which real Go forbids
            // referencing at all).
            return !receiverName.isEmpty() && name.equals(receiverName);
        }

        Expression parsePrimary() {
            Token tok = peek();

            if (tok.kind == Tok.NUMBER) {
                advance();
                return parseNumberLiteral(tok.value);
            }
            // N-448: a bare non-empty literal is refused (natively ASCII text, to
            // the compiler hex). Exempt: "" and a runar.Asm body.
            // N-439: a raw (backtick) literal is its text verbatim with carriage
            // returns discarded (Go spec), then goes through the hex check.
            if (tok.kind == Tok.STRING || tok.kind == Tok.BACKTICK_STRING) {
                int idx = pos;
                advance();
                String value = tok.kind == Tok.STRING ? tok.value : tok.value.replace("\r", "");
                if (!value.isEmpty() && !bareLiteralOk.contains(idx)) {
                    addError(LexDiag.at(fileName, tok.line, tok.col, LexDiag.goBareStringLiteral(value)));
                }
                return new ByteStringLiteral(value, new SourceLocation(fileName, tok.line, tok.col));
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

                    Expression.BinaryOp bigOp = GO_BIGINTBIG_OPS.get(selName);
                    if (bigOp != null && check(Tok.LPAREN)) {
                        List<Expression> args = parseCallArgs();
                        if (args.size() == 2) {
                            return new BinaryExpr(bigOp, args.get(0), args.get(1));
                        }
                    }

                    // N-448: runar.HexToBytes("deadbeef") is the explicit hex spelling.
                    if ("HexToBytes".equals(selName) && check(Tok.LPAREN)) {
                        Token argTok = pos + 1 < tokens.size() ? tokens.get(pos + 1) : null;
                        Token closeTok = pos + 2 < tokens.size() ? tokens.get(pos + 2) : null;
                        if (argTok != null && (argTok.kind == Tok.STRING || argTok.kind == Tok.BACKTICK_STRING)
                            && closeTok != null && closeTok.kind == Tok.RPAREN) {
                            advance(); // '('
                            advance(); // literal
                            advance(); // ')'
                            return new ByteStringLiteral(argTok.kind == Tok.STRING
                                ? argTok.value : argTok.value.replace("\r", ""),
                                new SourceLocation(fileName, argTok.line, argTok.col));
                        }
                        addError(LexDiag.at(fileName, tok.line, tok.col,
                            "runar.HexToBytes expects a single string literal argument"));
                    }

                    // N-448: the first argument of runar.Asm(...) is an opcode body.
                    if ("Asm".equals(selName) && check(Tok.LPAREN) && pos + 1 < tokens.size()
                        && (tokens.get(pos + 1).kind == Tok.STRING || tokens.get(pos + 1).kind == Tok.BACKTICK_STRING)) {
                        bareLiteralOk.add(pos + 1);
                    }

                    if ("ByteString".equals(selName) && check(Tok.LPAREN)) {
                        int savedPos = pos;
                        advance(); // consume '('
                        if (check(Tok.STRING) || check(Tok.BACKTICK_STRING)) {
                            Token strTok = advance();
                            if (check(Tok.RPAREN)) {
                                advance();
                                // N-437: a raw string is its text verbatim as UTF-8,
                                // carriage returns discarded (Go spec).
                                String bytes = strTok.kind == Tok.BACKTICK_STRING
                                    ? new String(strTok.value.replace("\r", "").getBytes(java.nio.charset.StandardCharsets.UTF_8),
                                        java.nio.charset.StandardCharsets.ISO_8859_1)
                                    : (strTok.raw != null ? strTok.raw : strTok.value);
                                String hex = bytesToHex(bytes);
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

            if (tok.kind == Tok.LBRACKET) {
                return parseArrayOrCompositeLiteral();
            }

            if (tok.kind == Tok.LBRACE) {
                // Nested composite-literal body for multi-dim arrays.
                return parseBraceLiteral();
            }

            addError("line " + tok.line + ": unexpected token " + tok.value);
            advance();
            return new BigIntLiteral(BigInteger.ZERO);
        }

        // Parse either a bare `[a, b, …]` array literal or a Go composite
        // literal `[N]T{a, b, …}` (also `[]T{...}` and multi-dim variants).
        // Both surfaces emit an ArrayLiteralExpr so all 7 tiers lower to
        // the same `array_literal` ANF node.
        Expression parseArrayOrCompositeLiteral() {
            int saved = pos;
            expect(Tok.LBRACKET);
            boolean composite = false;
            if (check(Tok.NUMBER) || check(Tok.RBRACKET)) {
                if (check(Tok.NUMBER)) advance();
                if (check(Tok.RBRACKET)) {
                    advance(); // consume ']'
                    // Multi-dim arrays: consume additional `[N]` dims.
                    while (check(Tok.LBRACKET)) {
                        int dimSaved = pos;
                        advance();
                        if (check(Tok.NUMBER)) advance();
                        if (!check(Tok.RBRACKET)) { pos = dimSaved; break; }
                        advance();
                    }
                    // Consume element type: `*T`, `T`, or `runar.T`.
                    if (check(Tok.STAR)) advance();
                    if (check(Tok.IDENT)) {
                        advance();
                        while (check(Tok.DOT)) {
                            advance();
                            if (check(Tok.IDENT)) advance();
                            else break;
                        }
                    }
                    if (check(Tok.LBRACE)) {
                        composite = true;
                        return parseBraceLiteral();
                    }
                }
            }
            if (!composite) {
                pos = saved;
                expect(Tok.LBRACKET);
            }
            List<Expression> elements = new ArrayList<>();
            while (!check(Tok.RBRACKET) && !check(Tok.EOF)) {
                elements.add(parseExpression());
                if (!match(Tok.COMMA)) {
                    break;
                }
            }
            expect(Tok.RBRACKET);
            return new ArrayLiteralExpr(elements);
        }

        // Parse `{e, e, …}` — the body of a Go composite literal. Nested
        // braces recurse for multi-dim arrays.
        Expression parseBraceLiteral() {
            expect(Tok.LBRACE);
            List<Expression> elements = new ArrayList<>();
            while (!check(Tok.RBRACE) && !check(Tok.EOF)) {
                if (check(Tok.LBRACE)) {
                    // F-213 A2: a nested brace element is an array element.
                    elements.add(nest.nested(this::parseBraceLiteral));
                } else {
                    elements.add(parseExpression());
                }
                if (!match(Tok.COMMA)) break;
            }
            expect(Tok.RBRACE);
            return new ArrayLiteralExpr(elements);
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
