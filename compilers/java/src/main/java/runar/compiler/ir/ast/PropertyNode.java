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
    List<SyntheticArrayChainEntry> syntheticArrayChain
) {
    public String kind() {
        return "property";
    }

    /** Per-level entry recording a scalar's origin in a FixedArray expansion. */
    public record SyntheticArrayChainEntry(String base, int index, int length) {}
}
