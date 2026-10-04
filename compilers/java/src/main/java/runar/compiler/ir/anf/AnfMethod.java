package runar.compiler.ir.anf;

import java.util.List;
import runar.compiler.canonical.JsonName;

/**
 * A single lowered contract method.
 *
 * @param sighashType F-079 / issue #123: the non-default BIP-143 sighash mode a
 *                    {@code @sighash} directive declared for this method (e.g.
 *                    {@code 0x43} for SINGLE|FORKID); {@code null} = default
 *                    ALL|FORKID. The artifact writer copies it to
 *                    {@code abi.methods[].sigHashType}. F-065 / F-088: wire
 *                    data, emitted as {@code sigHashType} so an
 *                    {@code --emit-ir} -> {@code --ir} round trip keeps the
 *                    ABI's mode (the script bytes ride on each
 *                    {@code check_preimage.sighashFlag}). The default 0x41 is
 *                    normalised to {@code null} so it is never emitted —
 *                    explicit {@code @sighash ALL|FORKID} and no directive give
 *                    the same ANF, as in every other tier.
 */
public record AnfMethod(
    String name,
    List<AnfParam> params,
    List<AnfBinding> body,
    boolean isPublic,
    @JsonName("sigHashType") Integer sighashType
) {
    /** SIGHASH_ALL | SIGHASH_FORKID (SighashDirective.SIGHASH_DEFAULT). */
    private static final int SIGHASH_DEFAULT = 0x41;

    public AnfMethod {
        if (sighashType != null && sighashType == SIGHASH_DEFAULT) {
            sighashType = null;
        }
    }

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
