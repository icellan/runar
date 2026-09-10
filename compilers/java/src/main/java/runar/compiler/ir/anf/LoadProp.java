package runar.compiler.ir.anf;

import runar.compiler.canonical.JsonSkip;

/**
 * Read a contract property onto the stack.
 *
 * @param name     the property name
 * @param preserve issue #109 ({@code @embedAlways}): when true, dead-binding DCE
 *                 must NOT remove this binding even though nothing references
 *                 it. Set only on the {@code load_prop} that ANF lowering
 *                 injects for an {@code @embedAlways} readonly field.
 *                 Compiler-internal — {@link JsonSkip} keeps it out of the
 *                 emitted ANF IR JSON so the cross-tier bytes stay identical
 *                 (matches {@code compilers/zig/src/ir/types.zig}).
 */
public record LoadProp(String name, @JsonSkip boolean preserve) implements AnfValue {
    /** An ordinary, freely eliminable property read. */
    public LoadProp(String name) {
        this(name, false);
    }

    @Override
    public String kind() {
        return "load_prop";
    }
}
