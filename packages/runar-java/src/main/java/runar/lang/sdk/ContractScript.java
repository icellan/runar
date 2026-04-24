package runar.lang.sdk;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import runar.lang.sdk.RunarArtifact.ConstructorSlot;

/**
 * Helpers that turn a {@link RunarArtifact} + constructor args into a
 * deployable locking script, and split an on-chain script back into its
 * code part + state part. Parity target: Go {@code GetLockingScript}
 * and TS {@code SDK/contract.ts}.
 *
 * <p>The SDK replaces every OP_0 placeholder at the byte offset listed
 * in {@link RunarArtifact#constructorSlots()} with a push of the
 * corresponding constructor argument. Stateful contracts append an
 * OP_RETURN-prefixed state section, serialised via
 * {@link StateSerializer}.
 */
public final class ContractScript {

    private ContractScript() {}

    public static String renderLockingScript(
        RunarArtifact artifact,
        List<Object> constructorArgs,
        Map<String, Object> initialState
    ) {
        String tpl = artifact.scriptHex();
        List<ConstructorSlot> slots = new ArrayList<>(artifact.constructorSlots());
        slots.sort(Comparator.comparingInt(ConstructorSlot::byteOffset).reversed());

        byte[] bytes = ScriptUtils.hexToBytes(tpl);
        StringBuilder workingHex = new StringBuilder(ScriptUtils.bytesToHex(bytes));

        // Walk slots in *reverse* byte-offset order so replacements at the tail
        // don't shift earlier offsets.
        for (ConstructorSlot slot : slots) {
            if (slot.paramIndex() >= constructorArgs.size()) continue;
            Object arg = constructorArgs.get(slot.paramIndex());
            String push = encodeConstructorArg(arg, paramType(artifact, slot.paramIndex()));
            int hexOffset = slot.byteOffset() * 2;
            // Template has an OP_0 (0x00) placeholder, 1 byte wide, at this offset.
            workingHex.replace(hexOffset, hexOffset + 2, push);
        }

        String code = workingHex.toString();
        if (artifact.isStateful()) {
            String stateHex = initialState == null
                ? ""
                : StateSerializer.serialize(artifact.stateFields(), initialState);
            // Stateful template already includes trailing state handling in the code part.
            // M8 scope emits code + OP_RETURN + state to match Go's GetLockingScript layout.
            return code + "6a" + stateHex;
        }
        return code;
    }

    /** Extracts the code portion of a locking script (everything before the last OP_RETURN). */
    public static String extractCodePart(String fullScriptHex) {
        int opReturnPos = ScriptUtils.findLastOpReturn(fullScriptHex);
        if (opReturnPos < 0) return fullScriptHex;
        return fullScriptHex.substring(0, opReturnPos);
    }

    // ------------------------------------------------------------------
    // Constructor-arg encoding
    // ------------------------------------------------------------------

    /** Encodes a single constructor arg as the hex bytes that replace an OP_0 placeholder. */
    static String encodeConstructorArg(Object value, String type) {
        return switch (type) {
            case "int", "bigint" -> pushScriptNumber(StateSerializer.toBigInteger(value));
            case "bool" -> Boolean.TRUE.equals(value) ? "51" : "00"; // OP_1 / OP_0
            case "PubKey", "Addr", "Ripemd160", "Sha256", "Point", "Sig", "ByteString" -> {
                String hex = String.valueOf(value);
                yield ScriptUtils.encodePushData(hex);
            }
            default -> ScriptUtils.encodePushData(String.valueOf(value));
        };
    }

    /** Minimal Bitcoin Script number push (OP_0..OP_16 shortcuts, else minimal byte encoding). */
    static String pushScriptNumber(BigInteger n) {
        if (n.signum() == 0) return "00";
        if (n.signum() > 0 && n.compareTo(BigInteger.valueOf(16)) <= 0) {
            return String.format("%02x", 0x50 + n.intValue());
        }
        byte[] mag = n.abs().toByteArray();
        // Trim any leading sign byte from two's-complement encoding.
        int start = 0;
        while (start < mag.length - 1 && mag[start] == 0) start++;
        byte[] trimmed = new byte[mag.length - start];
        System.arraycopy(mag, start, trimmed, 0, trimmed.length);

        // Reverse to little-endian.
        byte[] le = new byte[trimmed.length];
        for (int i = 0; i < trimmed.length; i++) le[i] = trimmed[trimmed.length - 1 - i];

        // Sign-magnitude: if top bit of high byte is set, add an extra sign byte.
        if ((le[le.length - 1] & 0x80) != 0) {
            byte[] extended = new byte[le.length + 1];
            System.arraycopy(le, 0, extended, 0, le.length);
            extended[le.length] = (byte) (n.signum() < 0 ? 0x80 : 0x00);
            le = extended;
        } else if (n.signum() < 0) {
            le[le.length - 1] |= (byte) 0x80;
        }
        return ScriptUtils.encodePushData(ScriptUtils.bytesToHex(le));
    }

    private static String paramType(RunarArtifact artifact, int paramIndex) {
        var params = artifact.abi().constructor().params();
        if (paramIndex < 0 || paramIndex >= params.size()) return "bigint";
        return params.get(paramIndex).type();
    }
}
