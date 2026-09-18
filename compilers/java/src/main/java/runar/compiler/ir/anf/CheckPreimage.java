package runar.compiler.ir.anf;

/**
 * check_preimage — the OP_PUSH_TX preimage binding.
 *
 * <p>{@code sighashFlag} is the declared {@code @sighash} mode ({@code null} =
 * default ALL|FORKID, 0x41). {@code bindingVariant} is the Any-S binding
 * construction declared via {@code @bindingVariant} ({@code null} / {@code
 * "lowS"} = the default low-S blob, byte-identical to the pinned cross-tier
 * binding; {@code "all"} = the compact non-low-S blob). Only set for a method
 * that declares {@code @bindingVariant all}, keeping golden ANF unchanged for
 * every existing (default) contract.
 */
public record CheckPreimage(String preimage, Integer sighashFlag, String bindingVariant)
        implements AnfValue {
    /** Backwards-compatible constructor: default sighash (ALL|FORKID, 0x41), default lowS binding. */
    public CheckPreimage(String preimage) {
        this(preimage, null, null);
    }

    /** Backwards-compatible constructor: declared sighash, default lowS binding. */
    public CheckPreimage(String preimage, Integer sighashFlag) {
        this(preimage, sighashFlag, null);
    }

    @Override
    public String kind() {
        return "check_preimage";
    }
}
