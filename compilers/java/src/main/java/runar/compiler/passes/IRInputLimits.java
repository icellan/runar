package runar.compiler.passes;

/**
 * DoS-bound input limits + typed errors for the Java ANF IR loader.
 * Mirrors {@code InputLimits} from {@code
 * packages/runar-ir-schema/src/input-limits.ts} and the Go reference at
 * {@code compilers/go/ir/input_limits.go}.
 *
 * <p>BUG-008 follow-up.
 */
public final class IRInputLimits {
    private IRInputLimits() {}

    /**
     * Mirrors {@code InputLimits.MAX_IR_BYTES} (16 MiB) from the TS schema
     * package. Any ANF IR JSON larger than this is rejected at the loader
     * entry point ({@link AnfLoader#parse}) BEFORE the hand-rolled JSON
     * parser runs.
     */
    public static final int MAX_IR_BYTES = 16 * 1024 * 1024;

    /**
     * Mirrors {@code InputLimits.MAX_NESTING} (512) from the TS schema
     * package. ANF IR JSON whose structural nesting (objects + arrays)
     * exceeds this is rejected.
     */
    public static final int MAX_IR_NESTING = 512;

    /**
     * Thrown when an IR JSON payload exceeds {@link #MAX_IR_BYTES} at a
     * public loader entry point. Distinct typed exception so callers can
     * distinguish DoS-bound rejection from generic deserialisation
     * failures.
     */
    public static final class IRSizeExceededException extends RuntimeException {
        private final int limit;
        private final int actual;

        public IRSizeExceededException(int limit, int actual) {
            super("IR JSON exceeds MAX_IR_BYTES (limit=" + limit
                    + ", actual=" + actual + ")");
            this.limit = limit;
            this.actual = actual;
        }

        public int limit() { return limit; }
        public int actual() { return actual; }
    }

    /**
     * Thrown when an IR JSON payload's structural nesting (objects +
     * arrays) exceeds {@link #MAX_IR_NESTING}.
     */
    public static final class IRNestingExceededException extends RuntimeException {
        private final int limit;

        public IRNestingExceededException(int limit) {
            super("IR JSON nesting exceeds MAX_NESTING (limit=" + limit + ")");
            this.limit = limit;
        }

        public int limit() { return limit; }
    }

    /**
     * Throws {@link IRSizeExceededException} if the UTF-8 encoded length
     * of {@code json} exceeds {@link #MAX_IR_BYTES}.
     */
    public static void assertIRBytesUnderLimit(String json) {
        if (json == null) return;
        int n = json.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        if (n > MAX_IR_BYTES) {
            throw new IRSizeExceededException(MAX_IR_BYTES, n);
        }
    }

    /**
     * Walks the raw JSON bytes and throws {@link IRNestingExceededException}
     * the first time the structural nesting (objects + arrays) exceeds
     * {@link #MAX_IR_NESTING}. Runs BEFORE the hand-rolled JSON parser so
     * a deeply-nested payload cannot exhaust the JVM thread stack.
     *
     * <p>Skips strings (respecting backslash-escapes).
     */
    public static void assertIRNestingUnderLimit(String json) {
        if (json == null) return;
        byte[] data = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (byte raw : data) {
            int b = raw & 0xFF;
            if (inString) {
                if (escaped) { escaped = false; continue; }
                if (b == 0x5C) { escaped = true; continue; }
                if (b == 0x22) { inString = false; }
                continue;
            }
            if (b == 0x22) {
                inString = true;
            } else if (b == 0x7B || b == 0x5B) {
                depth++;
                if (depth > MAX_IR_NESTING) {
                    throw new IRNestingExceededException(MAX_IR_NESTING);
                }
            } else if (b == 0x7D || b == 0x5D) {
                if (depth > 0) depth--;
            }
        }
    }
}
