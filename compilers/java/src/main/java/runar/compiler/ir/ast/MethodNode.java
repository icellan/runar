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
    String bindingVariant,
    /**
     * D12 FE-F4: the return type the source declares, when its surface syntax
     * can spell one and it names a Rúnar type (Ruby cannot; TypeScript may
     * omit it; an unknown name is refused by the parser's N-331 check). The
     * type checker enforces it on every {@code return} and gives it to every
     * call. {@code null} = inferred from the body by the type checker, with
     * the full environment.
     */
    TypeNode returnType
) {
    /** Convenience constructor for a method with no declared return type. */
    public MethodNode(
        String name,
        List<ParamNode> params,
        List<Statement> body,
        Visibility visibility,
        SourceLocation sourceLocation,
        Integer sighashType,
        String bindingVariant
    ) {
        this(name, params, body, visibility, sourceLocation, sighashType, bindingVariant, null);
    }

    /** Convenience constructor for a method with no binding-variant directive. */
    public MethodNode(
        String name,
        List<ParamNode> params,
        List<Statement> body,
        Visibility visibility,
        SourceLocation sourceLocation,
        Integer sighashType
    ) {
        this(name, params, body, visibility, sourceLocation, sighashType, null, null);
    }

    /** Convenience constructor for a method with no sighash directive. */
    public MethodNode(
        String name,
        List<ParamNode> params,
        List<Statement> body,
        Visibility visibility,
        SourceLocation sourceLocation
    ) {
        this(name, params, body, visibility, sourceLocation, null, null, null);
    }

    /** This method with declared return type {@code t} (D12 FE-F4). */
    public MethodNode withReturnType(TypeNode t) {
        return new MethodNode(name, params, body, visibility, sourceLocation, sighashType, bindingVariant, t);
    }

    /**
     * D12 FE-F4: the declared return type a method node keeps, or null when
     * the declaration names no usable Rúnar type (an unknown name is refused
     * by the parser's N-331 check; the missing-annotation placeholder is a
     * custom name too). Mirrors the TS reference's {@code declaredReturnType}.
     * {@code void} is kept: this tier's PrimitiveTypeName has no VOID member,
     * so the parsers carry it as {@code CustomType("void")}, which TS stores as
     * the primitive {@code void} and enforces like any other declared type.
     */
    public static TypeNode declaredReturnType(TypeNode t) {
        if (t instanceof CustomType ct && ct.name().equals("void")) return t;
        return t == null || t instanceof CustomType ? null : t;
    }

    public String kind() {
        return "method";
    }
}
