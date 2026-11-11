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
        String envelope = inscription == null ? "" : inscription.toEnvelopeHex();
        // Inject ordinals envelope between code and state (matches Go/Rust/Python/Zig/Ruby SDKs).
        return buildCodeScript(artifact, constructorArgs, inscription) + envelope;
    }

    /**
     * The spliced code script WITHOUT the ordinals envelope: the template with
     * every constructor-arg / codeSepIndex placeholder substituted and every
     * N-051 {@code codePartLenSlots} field set to the deployed code-part
     * length. The envelope is part of {@code _codePart}, so when
     * {@code inscription} is non-null its length is counted in that value even
     * though its bytes are not returned. Parity target: TS
     * {@code RunarContract.buildCodeScript}.
     */
    static String buildCodeScript(
        RunarArtifact artifact,
        List<Object> constructorArgs,
        Inscription inscription
    ) {
        String tpl = artifact.scriptHex();

        // Build the unified list of template slot substitutions (constructor args
        // + codeSepIndex slots), then apply them in descending template
        // byte-offset order so each splice preserves earlier offsets. Mirrors
        // the Go SDK's `buildCodeScript`.
        List<Sub> subs = new ArrayList<>();
        for (ConstructorSlot slot : artifact.constructorSlots()) {
            Object arg = resolveConstructorArg(artifact, constructorArgs, slot.paramIndex());
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

        // N-051: the deploy-time code-part length pins. The inscription
        // envelope, when present, is part of `_codePart`.
        int envelopeLen = inscription == null ? 0 : inscription.toEnvelopeHex().length() / 2;
        return patchCodePartLenSlots(
            artifact, workingHex.toString(), subs, (long) workingHex.length() / 2 + envelopeLen);
    }

    /** One template placeholder substitution: the 1-byte OP_0 at {@code byteOffset} becomes {@code encoded}. */
    record Sub(int byteOffset, String encoded) {}

    /**
     * N-051 — write the deployed code-part length into every
     * {@code codePartLenSlots} field of a spliced code script.
     *
     * <p>The compiler cannot know the deployed length of a code part that bakes
     * a variable-width readonly constructor arg (a ByteString, a bigint), so the
     * {@code SIZE(_codePart)} equality pin carries a 4-byte little-endian field
     * the SDK fills in. The field is fixed-width, so writing it changes no
     * length and no offset. A wrong or missing value is fail-safe on chain
     * (honest spends fail OP_NUMEQUAL); it is never a lower bound.
     *
     * @param spliced     the template with every OP_0 placeholder substituted
     * @param subs        those substitutions, by TEMPLATE byte offset (each
     *                    replaced one placeholder byte with {@code encoded})
     * @param codePartLen the deployed code-part length in bytes, including any
     *                    inscription envelope
     */
    static String patchCodePartLenSlots(
        RunarArtifact artifact,
        String spliced,
        List<Sub> subs,
        long codePartLen
    ) {
        List<RunarArtifact.CodePartLenSlot> slots = artifact.codePartLenSlots();
        if (slots.isEmpty()) return spliced;
        if (codePartLen < 0 || codePartLen > 0x7fffffffL) {
            throw new IllegalArgumentException(
                "patchCodePartLenSlots: code part length " + codePartLen + " does not fit the 4-byte pin field");
        }
        StringBuilder le = new StringBuilder(8);
        for (int i = 0; i < 4; i++) le.append(String.format("%02x", (codePartLen >> (8 * i)) & 0xff));
        String tpl = artifact.scriptHex();
        StringBuilder out = new StringBuilder(spliced);
        for (RunarArtifact.CodePartLenSlot slot : slots) {
            int off = slot.byteOffset();
            // The template must carry `04 <4 bytes> OP_BIN2NUM OP_NUMEQUAL
            // OP_VERIFY` here; anything else means the descriptor does not
            // describe this script.
            boolean shaped = off >= 1
                && (off + 7) * 2 <= tpl.length()
                && tpl.startsWith("04", (off - 1) * 2)
                && tpl.startsWith("819c69", (off + 4) * 2);
            if (!shaped) {
                throw new IllegalArgumentException(
                    "patchCodePartLenSlots: " + artifact.contractName() + " codePartLenSlots entry at byteOffset "
                        + off + " does not point at a verify_code_part_len length field "
                        + "(corrupted or mismatched artifact)");
            }
            int shift = 0;
            for (Sub sub : subs) {
                if (sub.byteOffset() < off) shift += sub.encoded().length() / 2 - 1;
            }
            int at = (off + shift) * 2;
            out.replace(at, at + 8, le.toString());
        }
        return out.toString();
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

    /**
     * N-223: shared out-of-range guard for every {@code constructorArgs.get(paramIndex)}
     * read reachable from a {@link ConstructorSlot}. The constructor only checks
     * {@code constructorArgs.size() == abi.constructor.params.size()} — it never
     * cross-checks that every slot's {@code paramIndex} actually falls within that
     * range. Before this fix, {@link #buildCodeScript}, {@link #resolvedCodeSepSlots},
     * and {@code RunarContract#adjustCodeSepOffset} each silently SKIPPED a slot
     * whose {@code paramIndex} was out of range (the placeholder byte stayed
     * unfilled, or the offset shift was simply wrong) instead of refusing. Parity
     * target: TS {@code RunarContract#resolveConstructorArg} (N-081 / N-223).
     */
    static Object resolveConstructorArg(RunarArtifact artifact, List<Object> constructorArgs, int paramIndex) {
        if (paramIndex < 0 || paramIndex >= constructorArgs.size()) {
            throw new IllegalArgumentException(
                "RunarContract: constructorSlots entry for " + artifact.contractName() + " has out-of-range "
                    + "paramIndex " + paramIndex + " (constructorArgs has " + constructorArgs.size() + " entries)");
        }
        return constructorArgs.get(paramIndex);
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
                // Deploy only ever writes a push or a small-integer opcode at a
                // constructor slot; any other opcode would otherwise be reported
                // as a value the script does not hold. Checked at every occurrence.
                if (!ScriptUtils.isPushOpcode(opcode)) {
                    throw new IllegalArgumentException(String.format(
                        "extractConstructorArgs: opcode 0x%02x at the constructor slot at template byte %d is not a push",
                        opcode, templateByteOffset));
                }
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
        // N-320: one conversion. Shifting a byte in at a time is quadratic: a
        // 1 MiB constructor arg held fromUtxo past the CPU budget.
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) be[i] = le[le.length - 1 - i];
        BigInteger mag = new BigInteger(1, be);
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
                if (cs.byteOffset() < slot.codeSepIndex()) {
                    String encoded = encodeConstructorArg(
                        resolveConstructorArg(artifact, constructorArgs, cs.paramIndex()),
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
