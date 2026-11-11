package runar.lang.sdk;

import java.util.List;

/**
 * Conformance-driver bridge to {@link ContractScript#extractConstructorArgs},
 * which is package-private in the SDK. This class lives in the driver's own
 * source tree under the SDK's package name (a split package on the plain
 * classpath, which the fat jar is) so the readback mode can call the exact
 * method {@code RunarContract.fromUtxo} uses, without widening the SDK's
 * public surface and without going through {@code fromUtxo}, which adds its
 * own state-section refusal on top.
 */
public final class DriverReadbackAccess {

    private DriverReadbackAccess() {}

    /** Positional by paramIndex; params with no constructor slot hold the SDK's 0 placeholder. */
    public static List<Object> extractConstructorArgs(RunarArtifact artifact, String scriptHex) {
        return ContractScript.extractConstructorArgs(artifact, scriptHex);
    }
}
