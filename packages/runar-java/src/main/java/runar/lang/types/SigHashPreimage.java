package runar.lang.types;

/**
 * Serialized BIP-143 sighash preimage, variable length. Fed to
 * {@code checkPreimage(...)} and to the {@code extract*} builtin family
 * for on-chain introspection of the spending transaction.
 *
 * <p>For the structured accessor API (version, outpoint, amount,
 * locktime, ...) that mirrors the on-chain {@code extract*} opcodes, see
 * {@link runar.lang.runtime.Preimage}. That class also knows how to
 * serialize / parse a preimage round-trip so tests can forge specific
 * preimage contents before calling into a contract method.
 *
 * <p>Instances wrap the raw bytes of the preimage. Equality is
 * value-based on the underlying bytes.
 */
public final class SigHashPreimage extends ByteString {
    public SigHashPreimage(byte[] bytes) {
        super(bytes);
    }

    public static SigHashPreimage fromHex(String hex) {
        return new SigHashPreimage(java.util.HexFormat.of().parseHex(hex));
    }

    /** Convenience alias for {@link #toByteArray()}. */
    public byte[] bytes() {
        return toByteArray();
    }
}
