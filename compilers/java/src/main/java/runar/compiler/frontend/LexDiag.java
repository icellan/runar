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
