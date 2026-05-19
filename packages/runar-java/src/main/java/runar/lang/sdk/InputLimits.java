package runar.lang.sdk;

/**
 * DoS-bound input limits used by the Java SDK. Mirrors
 * {@code InputLimits.MAX_SCRIPT_BYTES} (4 MiB) from the TS schema package.
 * Largest legitimate script measured is {@code p384-wallet} at ~1.87 MB;
 * 4 MiB gives ~2× headroom.
 */
public final class InputLimits {
    private InputLimits() {}

    /** 4 MiB cap on a single Bitcoin Script. */
    public static final int MAX_SCRIPT_BYTES = 4 * 1024 * 1024;
}
