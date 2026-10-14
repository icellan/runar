package runar.compiler.ir.ast;

import java.util.List;

/**
 * Contract property (field). {@code initializer} is nullable for
 * properties without a default value. {@code syntheticArrayChain} is
 * populated only by the expand-fixed-arrays pass (null otherwise).
 *
 * <p>Mirrors {@code PropertyNode} in
 * {@code packages/runar-ir-schema/src/runar-ast.ts}.
 */
public record PropertyNode(
    String name,
    TypeNode type,
    boolean readonly,
    Expression initializer,
    SourceLocation sourceLocation,
    List<SyntheticArrayChainEntry> syntheticArrayChain,
    /**
     * Issue #109: set by the parser when a {@code /** @embedAlways *&#47;} (or
     * {@code // @embedAlways}) comment directive immediately precedes a readonly
     * field. It opts the field OUT of dead-code elimination so its deploy-time
     * bytes survive into the on-chain locking script. Only meaningful on
     * readonly fields. The eight non-TS surfaces set it from their native
     * spelling (N-093), e.g. Java {@code @EmbedAlways}.
     */
    boolean embedAlways
) {
    /** Backwards-compatible constructor for callers that carry no {@code @embedAlways}. */
    public PropertyNode(
        String name,
        TypeNode type,
        boolean readonly,
        Expression initializer,
        SourceLocation sourceLocation,
        List<SyntheticArrayChainEntry> syntheticArrayChain
    ) {
        this(name, type, readonly, initializer, sourceLocation, syntheticArrayChain, false);
    }

    public String kind() {
        return "property";
    }

    /** Per-level entry recording a scalar's origin in a FixedArray expansion. */
    public record SyntheticArrayChainEntry(String base, int index, int length) {}
}
