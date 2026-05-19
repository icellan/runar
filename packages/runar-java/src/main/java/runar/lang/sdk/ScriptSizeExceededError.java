package runar.lang.sdk;

/**
 * Thrown when a script exceeds {@link InputLimits#MAX_SCRIPT_BYTES} at a
 * public SDK entry point (deploy / call / Provider#getUtxos /
 * Provider#getContractUtxo).
 *
 * <p>Distinct typed exception so callers can distinguish DoS-bound
 * rejection from generic {@link ProviderException} / decode errors. Guards
 * fire BEFORE any signing or broadcast work runs.
 */
public final class ScriptSizeExceededError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final int limit;
    private final int actual;
    private final String context;

    public ScriptSizeExceededError(int limit, int actual, String context) {
        super("script exceeds MAX_SCRIPT_BYTES (limit=" + limit
            + ", actual=" + actual + ", context=" + context + ")");
        this.limit = limit;
        this.actual = actual;
        this.context = context;
    }

    public int limit() { return limit; }
    public int actual() { return actual; }
    public String context() { return context; }

    /**
     * Assert that a hex-encoded script is at or under {@code limit} bytes.
     * Hex string is 2 chars per byte; tolerate odd-length defensively.
     *
     * @throws ScriptSizeExceededError when the script exceeds {@code limit}.
     */
    public static void assertScriptHexUnderLimit(String scriptHex, int limit, String context) {
        if (scriptHex == null || scriptHex.isEmpty()) return;
        int actualBytes = (scriptHex.length() + 1) / 2;
        if (actualBytes > limit) {
            throw new ScriptSizeExceededError(limit, actualBytes, context);
        }
    }
}
