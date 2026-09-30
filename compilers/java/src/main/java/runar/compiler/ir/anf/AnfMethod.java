package runar.compiler.ir.anf;

import java.util.List;
import runar.compiler.canonical.JsonSkip;

/**
 * A single lowered contract method.
 *
 * @param sighashType F-079 / issue #123: the non-default BIP-143 sighash mode a
 *                    {@code @sighash} directive declared for this method (e.g.
 *                    {@code 0x43} for SINGLE|FORKID); {@code null} = default
 *                    ALL|FORKID. The artifact writer copies it to
 *                    {@code abi.methods[].sigHashType}. Compiler-internal —
 *                    {@link JsonSkip} keeps it out of the emitted ANF IR JSON
 *                    (Go: {@code json:"-"}), where the codegen-relevant flag
 *                    rides on each {@code check_preimage.sighashFlag} instead.
 */
public record AnfMethod(
    String name,
    List<AnfParam> params,
    List<AnfBinding> body,
    boolean isPublic,
    @JsonSkip Integer sighashType
) {
    /** A method with the default sighash mode (no directive). */
    public AnfMethod(String name, List<AnfParam> params, List<AnfBinding> body, boolean isPublic) {
        this(name, params, body, isPublic, null);
    }

    /**
     * This method with {@code body} replaced and every other component kept.
     * Passes that rewrite only the body use this so a component added later
     * cannot be silently dropped (the N-093 failure mode in Go's constant fold).
     */
    public AnfMethod withBody(List<AnfBinding> newBody) {
        return new AnfMethod(name, params, newBody, isPublic, sighashType);
    }
}
