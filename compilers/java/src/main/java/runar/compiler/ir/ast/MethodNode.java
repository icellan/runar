package runar.compiler.ir.ast;

import java.util.List;

public record MethodNode(
    String name,
    List<ParamNode> params,
    List<Statement> body,
    Visibility visibility,
    SourceLocation sourceLocation,
    /**
     * Issue #123: the BIP-143 sighash type declared via a {@code /** @sighash
     * <FLAGS> *&#47;} directive on a public method (e.g. {@code 0x43} for
     * SINGLE|FORKID). {@code null} = the default {@code ALL|FORKID} (0x41),
     * byte-identical to the historically-pinned mode. The eight non-TS
     * surfaces set it from their native spelling (N-093), e.g. Java
     * {@code @Sighash("SINGLE|FORKID")}.
     */
    Integer sighashType,
    /**
     * Ports #170: the Any-S OP_PUSH_TX binding construction from a
     * {@code /** @bindingVariant <lowS|all> *&#47;} directive on a public
     * {@code .runar.ts} method. {@code null} = the default lowS; {@code "all"}
     * selects the compact non-low-S blob, spendable only when the spending tx
     * has nVersion > 1.
     */
    String bindingVariant
) {
    /** Convenience constructor for a method with no binding-variant directive. */
    public MethodNode(
        String name,
        List<ParamNode> params,
        List<Statement> body,
        Visibility visibility,
        SourceLocation sourceLocation,
        Integer sighashType
    ) {
        this(name, params, body, visibility, sourceLocation, sighashType, null);
    }

    /** Convenience constructor for a method with no sighash directive. */
    public MethodNode(
        String name,
        List<ParamNode> params,
        List<Statement> body,
        Visibility visibility,
        SourceLocation sourceLocation
    ) {
        this(name, params, body, visibility, sourceLocation, null, null);
    }

    public String kind() {
        return "method";
    }
}
