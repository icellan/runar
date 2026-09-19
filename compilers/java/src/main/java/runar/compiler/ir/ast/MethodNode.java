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
     * byte-identical to the historically-pinned mode. Only honoured on the
     * {@code .runar.ts} surface (mirrors the TypeScript reference).
     */
    Integer sighashType,
    /**
     * The Any-S binding construction declared via a {@code /** @bindingVariant
     * <lowS|all> *&#47;} directive on a public method. {@code null} = no
     * directive = the default {@code "lowS"} (byte-identical to the pinned
     * binding blob). {@code "all"} selects the compact non-low-S blob (valid
     * only for nVersion != 1). Only honoured on the {@code .runar.ts} surface
     * (mirrors the TypeScript reference).
     */
    String bindingVariant
) {
    /** Backwards-compatible constructor for the 8 non-TS parsers (no directive). */
    public MethodNode(
        String name,
        List<ParamNode> params,
        List<Statement> body,
        Visibility visibility,
        SourceLocation sourceLocation
    ) {
        this(name, params, body, visibility, sourceLocation, null, null);
    }

    /** Backwards-compatible constructor: declared @sighash, no @bindingVariant. */
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

    public String kind() {
        return "method";
    }
}
