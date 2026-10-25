package runar.compiler.frontend;

/**
 * F-011 — the tokenizer diagnostics every hand-written surface shares with the
 * TS reference ({@code packages/runar-compiler/src/errors.ts}).
 */
final class LexDiag {

    private LexDiag() {}

    /**
     * A quoted literal that reaches a line break or end of file before its
     * closing quote (only end of file on .runar.rs, for Python triple-quoted
     * strings, .runar.go backtick raw strings and .runar.ts template literals).
     */
    static final String UNTERMINATED_STRING_LITERAL = "unterminated string literal";

    /**
     * N-121 (user decision R85; the TS reference's OPTIONAL_CHAINING): a
     * .runar.ts {@code ?.}, located at the {@code ?}. Only the first
     * {@code ?.} in a file is reported.
     */
    static final String OPTIONAL_CHAINING = "optional chaining '?.' is not supported";

    /**
     * F-203: a .runar.py string or bytes literal escape CPython does not define
     * for that literal kind, a {@code \x} not followed by two hex digits, an
     * octal escape above 0o377, or (in a plain string) a {@code \N} /
     * backslash-u / backslash-U escape the surface does not support (the TS
     * reference's invalidEscapeSequenceMessage). {@code escape} is the
     * backslash plus the escape letter, or the whole octal escape.
     */
    static String invalidEscapeSequence(String escape) {
        return "invalid escape sequence '" + escape + "'";
    }

    /** F-203: CPython's refusal of a non-ASCII character inside b'..' / b"..". */
    static final String PY_BYTES_NON_ASCII = "bytes can only contain ASCII literal characters";

    /**
     * F-026: a .runar.zig call argument list or array literal whose elements are
     * not separated by commas (the TS reference's ZIG_LIST_COMMA).
     */
    static final String ZIG_LIST_COMMA = "expected ',' between list elements";

    /**
     * N-410: a .runar.zig struct-body token that is not a {@code pub const
     * Contract} marker, a method or a {@code name:} field (the TS reference's
     * unexpectedStructBodyTokenMessage). It used to be skipped.
     */
    static String unexpectedStructBodyToken(String token) {
        return "Unexpected token in struct body: '" + token + "'";
    }

    /**
     * N-410: a .runar.zig struct-init field without its leading {@code .}
     * (the TS reference's ZIG_STRUCT_INIT_DOT).
     */
    static final String ZIG_STRUCT_INIT_DOT = "expected '.' before struct-init field name";

    /**
     * F-026: a second .runar.py statement on the same line (the TS reference's
     * PY_STATEMENT_LINE_BREAK).
     */
    static final String PY_STATEMENT_LINE_BREAK = "expected a line break between statements";

    /** A Java char literal, which Rúnar does not support. */
    static final String JAVA_CHAR_LITERAL = "char literals are unsupported in Rúnar Java contracts";

    /**
     * N-053: a .runar.rb / .runar.py statement whose first token can begin
     * neither a statement nor an expression (the TS reference's
     * unsupportedStatementMessage). {@code token} is the token's source text.
     */
    static String unsupportedStatement(String token) {
        return "Unsupported statement starting with '" + token + "'";
    }

    /**
     * N-004: a .runar.rb class-body token that is not {@code prop},
     * {@code runar_public}, {@code params}, {@code def} or a bare
     * {@code private} / {@code public} marker (the TS reference's
     * unexpectedClassBodyTokenMessage). It used to be skipped, so an indented
     * {@code =begin} (lexed as {@code =}, {@code begin}) let a
     * "commented-out" method become the only spend path.
     */
    static String unexpectedClassBodyToken(String token) {
        return "Unexpected token in class body: '" + token + "'";
    }

    /**
     * N-004: the first token after a .runar.rb class's {@code end} (the TS
     * reference's unexpectedTokenAfterClassMessage).
     */
    static String unexpectedTokenAfterClass(String token) {
        return "Unexpected token after class end: '" + token + "'";
    }

    /**
     * N-050: a static or class-level method (the TS reference's
     * staticMethodMessage): {@code static} on .runar.ts / .runar.java,
     * {@code @staticmethod} / {@code @classmethod} on .runar.py,
     * {@code def self.m} on .runar.rb, and a {@code pub fn} without a self
     * receiver on .runar.rs / .runar.zig. {@code name} is the method name as
     * written in the source.
     */
    static String staticMethod(String name) {
        return "static methods are not allowed in Rúnar contracts; method '" + name + "' is declared static";
    }

    /**
     * N-331: a method whose RETURN-type annotation names a type that is not a
     * Rúnar type (the TS reference's checkReturnType). The AST keeps no return
     * type, so every surface parser calls this where the annotation is
     * spelled. Returns the diagnostic, or {@code null} for any other type;
     * {@code unknown} is the missing-annotation placeholder, diagnosed
     * elsewhere.
     */
    static String unknownReturnType(runar.compiler.ir.ast.TypeNode t, String methodName) {
        return unknownReturnType(t, methodName, false);
    }

    /**
     * As {@link #unknownReturnType(runar.compiler.ir.ast.TypeNode, String)},
     * and N-332: when {@code isPublic}, any non-void return type is also
     * refused, because public methods are spending entry points and return
     * void (spec/grammar.md:161).
     */
    static String unknownReturnType(runar.compiler.ir.ast.TypeNode t, String methodName, boolean isPublic) {
        // This tier's PrimitiveTypeName has no VOID member, so the .runar.ts /
        // .runar.zig parsers carry `void` as a CustomType; it is "returns nothing".
        if (t instanceof runar.compiler.ir.ast.CustomType ct) {
            if (ct.name().equals("unknown") || ct.name().equals("void")) return null;
            return "Type '" + ct.name() + "' of the return value of method '" + methodName
                + "' is not a Rúnar type";
        }
        return isPublic ? publicReturnType(methodName) : null;
    }

    /**
     * N-332: a PUBLIC method that declares a non-void return type (the TS
     * reference's publicReturnTypeMessage).
     */
    static String publicReturnType(String methodName) {
        return "Public method '" + methodName + "' must not declare a return type: "
            + "public methods are spending entry points and return void (spec/grammar.md:161)";
    }

    /**
     * N-023 (R49): an assignment ({@code =}, op=, {@code ++}, {@code --}) on
     * the .runar.java surface to a bare property name that no local or
     * parameter shadows (the TS reference's
     * bareJavaPropertyAssignmentMessage). In Java that bare name IS the field.
     */
    static String bareJavaPropertyAssignment(String name) {
        return "bare assignment to property '" + name + "' is not allowed; write `this." + name + " = ...`";
    }

    /** {@code file:line:col: message}. */
    static String at(String file, int line, int col, String message) {
        return file + ":" + line + ":" + col + ": " + message;
    }
}
