package runar.lang.sdk;

/**
 * Marker interface for deferred-signing flows. The multi-signer API
 * (M9) will route sighash computation through the SDK and hand off the
 * digest to an {@link ExternalSigner} implementation for the actual
 * signature. For now it is just a nominal sub-type of {@link Signer}
 * so contract code can declare an {@code ExternalSigner} parameter
 * today without breaking when M9 lands.
 */
public interface ExternalSigner extends Signer {
}
