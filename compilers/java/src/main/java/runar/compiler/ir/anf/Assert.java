package runar.compiler.ir.anf;

/**
 * Assert ANF node.
 *
 * <p>{@code isAutoInjectedStateCheck} is {@code true} only on the
 * compiler-emitted
 * {@code hash256(continuationOutputs) === extractOutputHash(txPreimage)}
 * assert at the end of every stateful-contract public method. Off-chain
 * SDK interpreters use this marker to skip the equality check via a
 * direct lookup instead of structural / taint heuristics that misfire on
 * developer covenant asserts whose IR shape is identical.
 */
public record Assert(
    String value,
    // R-270: the omit-when-false rule lives on the declaration, not in a name
    // comparison inside Jcs. Rename this component and the rule follows it.
    @runar.compiler.canonical.JsonOmitWhenFalse boolean isAutoInjectedStateCheck
) implements AnfValue {
    public Assert(String value) {
        this(value, false);
    }

    @Override
    public String kind() {
        return "assert";
    }
}
