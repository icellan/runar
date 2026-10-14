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
    Integer sighashType
) {
    /** Convenience constructor for a method with no sighash directive. */
    public MethodNode(
        String name,
        List<ParamNode> params,
        List<Statement> body,
        Visibility visibility,
        SourceLocation sourceLocation
    ) {
        this(name, params, body, visibility, sourceLocation, null);
    }

    public String kind() {
        return "method";
    }
}
