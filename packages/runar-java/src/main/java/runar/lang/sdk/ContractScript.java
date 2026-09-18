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
        StringBuilder script = new StringBuilder(renderCodePart(artifact, constructorArgs, inscription));
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

    /**
     * Renders the CODE PART of the locking script: the template with every
     * constructor-arg / codeSepIndex placeholder spliced in, followed by the
     * ordinals envelope when one is attached, and nothing else.
     *
     * <p>The envelope belongs to the code part — a stateful contract's on-chain
     * output reconstruction treats it as part of the immutable code — which is
     * why it lands before the {@code OP_RETURN || state} section and why
     * attaching one changes {@code SIZE(_codePart)}. Parity target: Go
     * {@code getCodePartHex}, Rust {@code get_code_part_hex}.
     */
    public static String renderCodePart(
        RunarArtifact artifact,
        List<Object> constructorArgs,
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
        if (RunarContract.isEmptySig(value)) {
            // Issue #106: OP_0 — empty signature push for the failing OR-CHECKSIG branch.
            return "00";
        }
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
    // Constructor-arg recovery from a deployed script (issue #119)
    // ------------------------------------------------------------------

    /**
     * Recover the positional constructor argument list from a deployed locking
     * script (issue #119), so a restored contract ({@code fromUtxo} /
     * {@code fromTxId}) operates on the real baked-in values rather than
     * {@code 0} placeholders. Without this the ANF interpreter computes the
     * wrong state continuation (readonly ctor params feed the continuation
     * formula) for restored stateful spends.
     *
     * <p>Byte-walks the {@link RunarArtifact#scriptHex()} template and the
     * deployed script in parallel: everywhere the template carries a 1-byte
     * OP_0 placeholder at a {@link RunarArtifact#constructorSlots()} offset, the
     * deployed script carries the substituted push — decoded here into the
     * positional arg. Code-separator-index slots are skipped (they are not
     * constructor args). Params that carry no constructor slot (mutable state
     * fields) fall back to {@code 0} and are overwritten by state extraction.
     *
     * @return a list of length {@code abi.constructor.params.size()} ordered by
     *     paramIndex; missing slots hold {@link BigInteger#ZERO}.
     */
    static List<Object> extractConstructorArgs(RunarArtifact artifact, String deployedScriptHex) {
        int paramCount = artifact.abi().constructor().params().size();
        List<Object> args = new ArrayList<>(paramCount);
        for (int i = 0; i < paramCount; i++) args.add(BigInteger.ZERO);
        if (paramCount == 0 || artifact.constructorSlots().isEmpty()) return args;

        String template = artifact.scriptHex();
        String deployed = deployedScriptHex;

        // Template byte-offset -> paramIndex for constructor slots.
        Map<Integer, Integer> ctorSlotByOffset = new java.util.HashMap<>();
        for (ConstructorSlot slot : artifact.constructorSlots()) {
            if (slot.paramIndex() < paramCount) {
                ctorSlotByOffset.put(slot.byteOffset(), slot.paramIndex());
            }
        }
        // Code-sep-index slot template byte-offsets (substituted but not args).
        java.util.Set<Integer> codesepOffsets = new java.util.HashSet<>();
        for (CodeSepIndexSlot slot : artifact.codeSepIndexSlots()) {
            codesepOffsets.add(slot.byteOffset());
        }

        int templatePos = 0;      // hex-char offset into the template
        int deployedPos = 0;      // hex-char offset into the deployed script
        int templateLen = template.length();
        while (templatePos + 2 <= templateLen && deployedPos + 2 <= deployed.length()) {
            int templateByteOffset = templatePos / 2;
            if (ctorSlotByOffset.containsKey(templateByteOffset)) {
                int paramIndex = ctorSlotByOffset.get(templateByteOffset);
                int opcode = Integer.parseInt(deployed.substring(deployedPos, deployedPos + 2), 16);
                args.set(paramIndex, decodeSlotValue(deployed, deployedPos, opcode,
                    paramType(artifact, paramIndex)));
                templatePos += 2;  // OP_0 placeholder is 1 byte
                deployedPos += ScriptUtils.decodePushData(deployed, deployedPos).hexCharsConsumed();
            } else if (codesepOffsets.contains(templateByteOffset)) {
                templatePos += 2;
                deployedPos += ScriptUtils.decodePushData(deployed, deployedPos).hexCharsConsumed();
            } else {
                // Non-slot item: template and deployed are byte-identical here.
                int consumed = ScriptUtils.decodePushData(template, templatePos).hexCharsConsumed();
                templatePos += consumed;
                deployedPos += consumed;
            }
        }
        return args;
    }

    /**
     * ABI type name -> how the constructor-slot value is encoded in the script.
     *
     * <p>TABLE, not a chain of {@code equals} predicates: the spellings missing
     * from the old predicates — the {@code bigint} aliases {@code RabinSig} /
     * {@code RabinPubKey} — silently turned a modulus into a hex string on the
     * way back off chain. Mirrors
     * {@code packages/runar-ir-schema/src/abi-type-encoding.ts}, the same table
     * the compiler stamps {@code ConstructorSlot.valueEncoding} from.
     */
    private static final Map<String, String> ABI_VALUE_ENCODINGS = Map.of(
        "bigint", "scriptnum",
        "int", "scriptnum",
        // RabinSig / RabinPubKey are bigint aliases; verifyRabinSig lowers to
        // OP_MOD, which reads its operand as a little-endian sign-magnitude
        // Script number — exactly what bigint gets.
        "RabinSig", "scriptnum",
        "RabinPubKey", "scriptnum",
        // "boolean" is canonical; "bool" is the alias several frontends spell.
        "boolean", "bool",
        "bool", "bool");

    /** Classify an ABI type name: {@code scriptnum}, {@code bool}, or
     *  {@code data} (ByteString and every fixed-width byte type). */
    private static String abiValueEncoding(String type) {
        return ABI_VALUE_ENCODINGS.getOrDefault(type, "data");
    }

    /**
     * Decode the value pushed at {@code offset} in the deployed script into the
     * positional constructor argument, using the ABI {@code type} to pick the
     * representation (script number for {@code int}/{@code bigint}, boolean for
     * {@code bool}, hex string for byte types) — the inverse of
     * {@link #encodeConstructorArg}.
     */
    private static Object decodeSlotValue(String deployed, int offset, int opcode, String type) {
        String encoding = abiValueEncoding(type);
        boolean isBool = "bool".equals(encoding);
        boolean isInt = "scriptnum".equals(encoding);
        if (opcode == 0x00) {                       // OP_0
            return isBool ? Boolean.FALSE : (isInt ? BigInteger.ZERO : "");
        }
        // S1: OP_1..OP_16 / OP_1NEGATE carry no separate data bytes — the
        // opcode itself IS the value. For int/bool slots that value is the
        // script number; for a ByteString (or other byte-typed) slot it is the
        // 1-byte payload the MINIMALDATA encoder short-circuited, so it must be
        // reconstructed as hex rather than degraded to a number. OP_0 above
        // still yields "" for byte types — OP_0 genuinely pushes [].
        if (opcode == 0x4f) {                       // OP_1NEGATE
            if (isInt) return BigInteger.valueOf(-1);
            if (isBool) return Boolean.TRUE;
            return "81";
        }
        if (opcode >= 0x51 && opcode <= 0x60) {     // OP_1..OP_16
            int v = opcode - 0x50;
            if (isBool) return Boolean.TRUE;
            if (isInt) return BigInteger.valueOf(v);
            return String.format("%02x", v);
        }
        String dataHex = ScriptUtils.decodePushData(deployed, offset).dataHex();
        if (isInt) return decodeScriptNumber(dataHex);
        return dataHex;
    }

    /** Decode a minimal little-endian sign-magnitude script number (inverse of
     * {@link #pushScriptNumber}'s data-push branch). */
    private static BigInteger decodeScriptNumber(String leHex) {
        if (leHex == null || leHex.isEmpty()) return BigInteger.ZERO;
        byte[] le = ScriptUtils.hexToBytes(leHex);
        boolean neg = (le[le.length - 1] & 0x80) != 0;
        le[le.length - 1] &= 0x7f;
        BigInteger mag = BigInteger.ZERO;
        for (int i = le.length - 1; i >= 0; i--) {
            mag = mag.shiftLeft(8).or(BigInteger.valueOf(le[i] & 0xff));
        }
        return neg ? mag.negate() : mag;
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
