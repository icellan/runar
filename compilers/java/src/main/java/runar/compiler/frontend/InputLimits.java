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
     * Throws {@link SourceSizeExceededException} if the UTF-8 encoded length
     * of {@code source} exceeds {@link #MAX_SOURCE_BYTES}.
     */
    public static void assertSourceBytesUnderLimit(String source)
            throws SourceSizeExceededException {
        if (source == null) {
            return;
        }
        int n = source.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        if (n > MAX_SOURCE_BYTES) {
            throw new SourceSizeExceededException(MAX_SOURCE_BYTES, n);
        }
    }
}
