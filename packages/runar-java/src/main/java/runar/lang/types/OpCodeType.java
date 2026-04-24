package runar.lang.types;

/**
 * Single-byte Bitcoin Script opcode encoded as a {@link ByteString}.
 * Produced by {@code OpCodeType(hex)} helpers and used by covenant
 * templates that embed raw opcode bytes into constructed outputs.
 */
public final class OpCodeType extends ByteString {
    public OpCodeType(byte[] bytes) {
        super(bytes);
    }

    public static OpCodeType fromHex(String hex) {
        return new OpCodeType(java.util.HexFormat.of().parseHex(hex));
    }
}
