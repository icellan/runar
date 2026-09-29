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

    /** {@code file:line:col: message}. */
    static String at(String file, int line, int col, String message) {
        return file + ":" + line + ":" + col + ": " + message;
    }
}
