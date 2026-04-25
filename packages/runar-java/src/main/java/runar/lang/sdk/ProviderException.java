package runar.lang.sdk;

/**
 * Unchecked exception thrown by HTTP-backed {@link Provider} implementations
 * (such as {@link RPCProvider}, {@link WhatsOnChainProvider}, and
 * {@link GorillaPoolProvider}) when an upstream call fails.
 *
 * <p>Wraps both transport errors (IO, timeouts) and protocol errors
 * (non-2xx responses, JSON-RPC error envelopes, malformed payloads).
 */
public class ProviderException extends RuntimeException {

    private final int statusCode;

    public ProviderException(String message) {
        super(message);
        this.statusCode = 0;
    }

    public ProviderException(String message, Throwable cause) {
        super(message, cause);
        this.statusCode = 0;
    }

    public ProviderException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public ProviderException(String message, int statusCode, Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
    }

    /** HTTP status code, or {@code 0} if the failure was not protocol-level. */
    public int statusCode() {
        return statusCode;
    }
}
