package runar.compiler.ir.anf;

import java.util.List;

/**
 * {@code initialValue} is nullable; non-null when the property carries a
 * compile-time default from the source.
 *
 * <p>{@code syntheticArrayChain} (N-095) is nullable and non-null only on a
 * scalar leaf minted by {@link runar.compiler.passes.ExpandFixedArrays}. One
 * entry per {@code FixedArray} nesting level, outermost first. Every other
 * tier's artifact assembler regroups the expanded siblings back into a single
 * {@code FixedArray} state/ABI entry by reading this chain off the ANF
 * PROGRAM, not off the AST — so it is load-bearing wire data even here, where
 * the regrouper itself is not yet ported: an ANF Java emits is fed to the other
 * six tiers' {@code --ir}, and without the chain none of them can recover the
 * grouping. The wire spelling is the Go reference's {@code syntheticArrayChain},
 * which {@code $defs.ANFProperty} declares; {@code Jcs} omits a null component,
 * so a FixedArray-free contract's ANF bytes are unchanged.
 */
public record AnfProperty(
    String name,
    String type,
    boolean readonly,
    ConstValue initialValue,
    List<SyntheticArrayLevel> syntheticArrayChain) {

    /** One {@code FixedArray} nesting level on a synthetic scalar leaf. */
    public record SyntheticArrayLevel(String base, int index, int length) {}

    /** A property with no synthetic-array chain — every non-expanded property. */
    public AnfProperty(String name, String type, boolean readonly, ConstValue initialValue) {
        this(name, type, readonly, initialValue, null);
    }
}
