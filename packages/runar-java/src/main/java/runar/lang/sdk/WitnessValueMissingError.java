package runar.lang.sdk;

/**
 * Thrown when a method call requires a caller-supplied intent-intrinsic
 * witness value (auto-injected {@code _prevOutScript_<i>} or
 * {@code _serialisedOutputs}) that has not been set on the
 * {@link RunarContract}.
 *
 * <p>Auto-injected witness params come from the compiler when a contract
 * method uses {@code extractPrevOutputScript(i)} or
 * {@code requireOutputP2PKH(...)}. The caller must supply concrete bytes for
 * each before invoking {@link RunarContract#call} /
 * {@link RunarContract#prepareCall} via
 * {@link RunarContract#setPrevOutScript} and
 * {@link RunarContract#setSerialisedOutputs}.
 */
public final class WitnessValueMissingError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String paramName;
    private final String methodName;
    private final String contractName;

    public WitnessValueMissingError(String paramName, String methodName, String contractName) {
        super("witness value missing for auto-injected param '" + paramName + "' on "
            + contractName + "." + methodName
            + " — call setPrevOutScript(i, bytes) or setSerialisedOutputs(bytes)"
            + " before invoking the method");
        this.paramName = paramName;
        this.methodName = methodName;
        this.contractName = contractName;
    }

    public String paramName() { return paramName; }
    public String methodName() { return methodName; }
    public String contractName() { return contractName; }
}
