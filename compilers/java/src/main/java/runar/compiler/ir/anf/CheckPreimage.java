package runar.compiler.ir.anf;

/**
 * @param sighashFlag    issue #123: non-default BIP-143 sighash flag, or null.
 * @param bindingVariant ports #170: {@code "all"} for the compact non-low-S
 *                       Any-S blob (nVersion > 1 only); null = default lowS.
 *                       Emitted only when set, keeping golden ANF unchanged.
 */
public record CheckPreimage(String preimage, Integer sighashFlag, String bindingVariant) implements AnfValue {
    /** Backwards-compatible constructor: default sighash (ALL|FORKID, 0x41). */
    public CheckPreimage(String preimage) {
        this(preimage, null, null);
    }

    /** Backwards-compatible constructor: default binding variant (lowS). */
    public CheckPreimage(String preimage, Integer sighashFlag) {
        this(preimage, sighashFlag, null);
    }

    @Override
    public String kind() {
        return "check_preimage";
    }
}
