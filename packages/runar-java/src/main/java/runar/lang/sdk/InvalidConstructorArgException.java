package runar.lang.sdk;

/**
 * Thrown by {@link RunarContract}'s constructor when a ByteString-family
 * constructor arg (ByteString, PubKey, Sig, Addr, Ripemd160, Sha256, Point,
 * P256Point, P384Point, SigHashPreimage) is a {@link String} that is not an
 * even-length hex string (N-329). The SDK treats such a string as hex when it
 * splices it into the locking script, so raw bytes would otherwise build a
 * corrupt script.
 */
public final class InvalidConstructorArgException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    public InvalidConstructorArgException(String message) {
        super(message);
    }
}
