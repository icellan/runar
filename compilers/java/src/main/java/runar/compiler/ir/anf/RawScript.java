package runar.compiler.ir.anf;

import runar.compiler.canonical.JsonName;

/**
 * Opaque opcode-byte span with a declared stack arity. Emitted by the
 * {@code asm({...})} compiler intrinsic in {@code UnsafeSmartContract}
 * bodies. The bytes pass through the emit pass verbatim; the peephole
 * optimizer treats them as a hard barrier and the DCE pass never
 * eliminates them.
 *
 * <p>Mirrors the {@code raw_script} ANF value defined in
 * {@code packages/runar-compiler/src/ir/anf-ir.ts} and
 * {@code compilers/go/ir/types.go}.
 */
public record RawScript(
    String bytes,
    @JsonName("in_arity") int inArity,
    @JsonName("out_arity") int outArity
) implements AnfValue {
    @Override
    public String kind() {
        return "raw_script";
    }
}
