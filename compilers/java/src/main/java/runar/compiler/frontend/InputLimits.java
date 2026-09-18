package runar.compiler.frontend;

/**
 * DoS-bound input limits + typed errors for the Java compiler frontend.
 * Mirrors {@code InputLimits} from {@code
 * packages/runar-ir-schema/src/input-limits.ts}. See {@code
 * compilers/go/frontend/input_limits.go} for the reference shape.
 *
 * <p>BUG-008 follow-up.
 */
public final class InputLimits {
    private InputLimits() {}

    /**
     * Mirrors {@code InputLimits.MAX_SOURCE_BYTES} (4 MiB) from the TS schema
     * package. Rúnar source files larger than this are rejected at the parser
     * entry point ({@link ParserDispatch#parse}) BEFORE any tokenizer touches
     * the input.
     */
    public static final int MAX_SOURCE_BYTES = 4 * 1024 * 1024;

    /**
     * Thrown when a source payload exceeds {@link #MAX_SOURCE_BYTES} at a
     * public parser entry point. Distinct typed exception so callers can
     * distinguish DoS-bound rejection from generic syntax errors.
     */
    public static final class SourceSizeExceededException
            extends ParserDispatch.ParseException {
        private final int limit;
        private final int actual;

        public SourceSizeExceededException(int limit, int actual) {
            super("source exceeds MAX_SOURCE_BYTES (limit=" + limit
                    + ", actual=" + actual + ")");
            this.limit = limit;
            this.actual = actual;
        }

        public int limit() { return limit; }
        public int actual() { return actual; }
    }

    /**
     * Thrown when a null source reaches a parser entry point (R-182). A
     * ParseException subclass, like every other rejection from this guard, so
     * callers that already catch ParseException are unaffected.
     */
    public static final class NullSourceException extends ParserDispatch.ParseException {
        public NullSourceException() {
            super("source is null (nothing to parse)");
        }
    }

    /**
     * Throws {@link SourceSizeExceededException} if the UTF-8 encoded length
     * of {@code source} exceeds {@link #MAX_SOURCE_BYTES}, and
     * {@link NullSourceException} if it is null.
     *
     * <p>R-182: null used to return early here. This guard is the first thing
     * {@link ParserDispatch#parse} runs, and its job is to stop bad input
     * BEFORE a format parser touches it — so letting null through defeated the
     * purpose of running it first. The null reached the tokenizer and came back
     * as {@code Cannot invoke "String.length()" because "source" is null}: a
     * caller mistake reported as an internal error.
     */
    public static void assertSourceBytesUnderLimit(String source)
            throws SourceSizeExceededException, NullSourceException {
        if (source == null) {
            throw new NullSourceException();
        }
        int n = source.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        if (n > MAX_SOURCE_BYTES) {
            throw new SourceSizeExceededException(MAX_SOURCE_BYTES, n);
        }
    }
}
