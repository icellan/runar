package runar.lang.sdk;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import runar.lang.sdk.RunarArtifact.CodeSepIndexSlot;
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
        return renderLockingScript(artifact, constructorArgs, initialState, null);
    }

    public static String renderLockingScript(
        RunarArtifact artifact,
        List<Object> constructorArgs,
        Map<String, Object> initialState,
        Inscription inscription
    ) {
        String tpl = artifact.scriptHex();

        // Build the unified list of template slot substitutions (constructor args
        // + codeSepIndex slots), then apply them in descending template
        // byte-offset order so each splice preserves earlier offsets. Mirrors
        // the Go SDK's `buildCodeScript`.
        record Sub(int byteOffset, String encoded) {}
        List<Sub> subs = new ArrayList<>();
        for (ConstructorSlot slot : artifact.constructorSlots()) {
            if (slot.paramIndex() >= constructorArgs.size()) continue;
            Object arg = constructorArgs.get(slot.paramIndex());
            subs.add(new Sub(
                slot.byteOffset(),
                encodeConstructorArg(arg, paramType(artifact, slot.paramIndex()))
            ));
        }
        for (ResolvedCodeSep rs : resolvedCodeSepSlots(artifact, constructorArgs)) {
            subs.add(new Sub(rs.templateByteOffset, pushScriptNumber(BigInteger.valueOf(rs.adjustedValue))));
        }
        subs.sort(Comparator.comparingInt(Sub::byteOffset).reversed());

        byte[] bytes = ScriptUtils.hexToBytes(tpl);
        StringBuilder workingHex = new StringBuilder(ScriptUtils.bytesToHex(bytes));
        for (Sub sub : subs) {
            int hexOffset = sub.byteOffset() * 2;
            // Template has an OP_0 (0x00) placeholder, 1 byte wide, at this offset.
            workingHex.replace(hexOffset, hexOffset + 2, sub.encoded());
        }

        StringBuilder script = new StringBuilder(workingHex.toString());
        // Inject ordinals envelope between code and state (matches Go/Rust/Python/Zig/Ruby SDKs).
        if (inscription != null) {
            script.append(inscription.toEnvelopeHex());
        }
        if (artifact.isStateful()) {
            String stateHex = initialState == null
                ? ""
                : StateSerializer.serialize(artifact.stateFields(), initialState);
            // Stateful template already includes trailing state handling in the code part.
            // M8 scope emits code + OP_RETURN + state to match Go's GetLockingScript layout.
            script.append("6a").append(stateHex);
        }
        return script.toString();
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

    /**
     * Encodes a single constructor arg as the hex bytes that replace an
     * OP_0 placeholder. Dispatches on the <em>runtime value type</em>
     * (mirrors Go's {@code encodeArg} and Rust's {@code encode_arg}):
     * numbers become script-number pushes, booleans become OP_0/OP_1,
     * everything else (strings) is treated as hex push data. The ABI
     * parameter {@code type} is accepted but only consulted when the
     * runtime value is ambiguous (e.g. a {@link String} value that must
     * be decoded as a script number for an {@code int}/{@code bigint}
     * slot — a shape the other SDKs don't actually exercise but kept
     * for backwards compatibility).
     */
    static String encodeConstructorArg(Object value, String type) {
        if (value instanceof Boolean b) {
            return b ? "51" : "00";
        }
        if (value instanceof BigInteger bi) {
            return pushScriptNumber(bi);
        }
        if (value instanceof Long || value instanceof Integer || value instanceof Short || value instanceof Byte) {
            return pushScriptNumber(BigInteger.valueOf(((Number) value).longValue()));
        }
        if (value instanceof String s) {
            // Only fall back to numeric encoding when the ABI explicitly says
            // the slot is an integer AND the string looks like a decimal number.
            if (("int".equals(type) || "bigint".equals(type)) && s.matches("-?\\d+")) {
                return pushScriptNumber(new BigInteger(s));
            }
            return s.isEmpty() ? "00" : ScriptUtils.encodePushData(s);
        }
        return ScriptUtils.encodePushData(String.valueOf(value));
    }

    /** Minimal Bitcoin Script number push (OP_0..OP_16 shortcuts, else minimal byte encoding). */
    static String pushScriptNumber(BigInteger n) {
        if (n.signum() == 0) return "00";
        if (n.signum() > 0 && n.compareTo(BigInteger.valueOf(16)) <= 0) {
            return String.format("%02x", 0x50 + n.intValue());
        }
        if (n.equals(BigInteger.valueOf(-1))) return "4f"; // OP_1NEGATE
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

    // ------------------------------------------------------------------
    // CodeSepIndex slot resolution — parity with Go resolvedCodeSepSlotValues
    // ------------------------------------------------------------------

    /**
     * Resolved (template byte-offset, adjusted-value) pair for a single
     * code-separator-index slot. The adjusted value accounts for earlier
     * constructor-arg and code-sep-index slot expansions that shift the
     * OP_CODESEPARATOR position in the substituted script.
     */
    record ResolvedCodeSep(int templateByteOffset, int adjustedValue) {}

    static List<ResolvedCodeSep> resolvedCodeSepSlots(
        RunarArtifact artifact,
        List<Object> constructorArgs
    ) {
        List<CodeSepIndexSlot> slots = artifact.codeSepIndexSlots();
        if (slots.isEmpty()) return List.of();

        // Process slots in ascending template-byte-offset order so each
        // slot's adjusted value correctly accounts for earlier expansions.
        List<CodeSepIndexSlot> sorted = new ArrayList<>(slots);
        sorted.sort(Comparator.comparingInt(CodeSepIndexSlot::byteOffset));

        List<ResolvedCodeSep> result = new ArrayList<>();
        for (CodeSepIndexSlot slot : sorted) {
            int shift = 0;
            // Shift from constructor-arg expansions that land before this slot's
            // code-separator position in the template.
            for (ConstructorSlot cs : artifact.constructorSlots()) {
                if (cs.byteOffset() < slot.codeSepIndex() && cs.paramIndex() < constructorArgs.size()) {
                    String encoded = encodeConstructorArg(
                        constructorArgs.get(cs.paramIndex()),
                        paramType(artifact, cs.paramIndex())
                    );
                    shift += encoded.length() / 2 - 1;
                }
            }
            // Shift from earlier (already-resolved) code-sep-index slot expansions.
            for (ResolvedCodeSep prev : result) {
                if (prev.templateByteOffset() < slot.codeSepIndex()) {
                    String prevEncoded = pushScriptNumber(BigInteger.valueOf(prev.adjustedValue()));
                    shift += prevEncoded.length() / 2 - 1;
                }
            }
            result.add(new ResolvedCodeSep(slot.byteOffset(), slot.codeSepIndex() + shift));
        }
        return result;
    }
}
