package runar.lang.sdk;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

import runar.lang.runtime.MockCrypto;

/**
 * ANF IR interpreter for off-chain execution of compiled Rúnar contracts.
 *
 * <p>Java port of the reference interpreter shipped in every other Rúnar
 * SDK ({@code packages/runar-py/runar/sdk/anf_interpreter.py},
 * {@code packages/runar-go/anf_interpreter.go},
 * {@code packages/runar-rs/src/sdk/anf_interpreter.rs},
 * {@code packages/runar-zig/src/sdk/anf_interpreter.zig}).
 *
 * <p>Two modes:
 * <ul>
 *   <li>{@link #computeNewState computeNewState(...)} — state-tracking
 *       simulation matching the Python/Go/Rust references. Skips
 *       {@code assert}, {@code check_preimage}, {@code deserialize_state},
 *       {@code get_state_script}, and {@code add_raw_output}; returns the
 *       new state map merged with {@code currentState}. Crypto primitives
 *       that aren't locally implementable
 *       (BN254/Poseidon2/SLH-DSA/sha256Compress) propagate
 *       {@link UnsupportedOperationException} from {@link MockCrypto}.</li>
 *   <li>{@link #executeStrict executeStrict(...)} — strict mode: same
 *       walk as {@code computeNewState} except {@code assert} bindings
 *       evaluate their condition and throw
 *       {@link AssertionFailureException} when the value is not truthy.
 *       Useful for "execute this method and check that asserts hold"
 *       smoke tests where the host wants a definite success/failure
 *       result. Note that {@code check_preimage} and
 *       {@code deserialize_state} still no-op (they're on-chain-only),
 *       and signature verification is mocked to always succeed.</li>
 * </ul>
 *
 * <p>The interpreter does not modify the artifact or the caller's
 * input maps. Returned state maps are fresh.
 */
public final class AnfInterpreter {

    private static final HexFormat HEX = HexFormat.of();

    private static final Set<String> IMPLICIT_PARAMS = Set.of(
        "_changePKH", "_changeAmount", "_newAmount", "txPreimage"
    );

    /**
     * The on-disk ANF spelling of a bigint literal: decimal digits with a
     * trailing {@code n}. Unambiguous against a hex ByteString literal, which
     * never contains {@code n}.
     */
    private static final java.util.regex.Pattern BIGINT_LITERAL =
        java.util.regex.Pattern.compile("-?\\d+n");

    private static final Set<String> CHAIN_ONLY_KINDS = Set.of(
        "check_preimage", "deserialize_state", "get_state_script"
    );

    private AnfInterpreter() {}

    // ------------------------------------------------------------------
    // Witness / mock-preimage context for intent-intrinsic execution
    // ------------------------------------------------------------------

    /**
     * Mutable bag of off-chain witness inputs that the AST-level
     * intent-covenant intrinsics ({@code extractPrevOutputScript},
     * {@code requireOutputP2PKH}, {@code currentBlockHeight}) desugar
     * into. Java port of the TS {@code TestContract.setPrevOutScript /
     * setSerialisedOutputs / setMockPreimage / setMockPreimageBytes}
     * channel.
     *
     * <p>The compiler lowers {@code extractPrevOutputScript(0n, ...)}
     * into a method parameter named {@code _prevOutScript_0} plus a
     * {@code hash256(_) === expected} assert; {@code requireOutputP2PKH}
     * lowers into {@code _serialisedOutputs} plus
     * {@code hash256(_) === extractOutputHash(txPreimage)} plus a
     * per-output substring assert; {@code currentBlockHeight} is sugar
     * for {@code extractLocktime(txPreimage)}.
     *
     * <p>Pass a populated {@code WitnessContext} to
     * {@link #executeStrict(Map, String, Map, Map, List, WitnessContext)}
     * to make those desugared chains actually evaluate against off-chain
     * test inputs instead of zero-bytes.
     */
    public static final class WitnessContext {
        private final Map<Integer, byte[]> prevOutScripts = new HashMap<>();
        private byte[] serialisedOutputs;
        private final Map<String, BigInteger> mockPreimage = new HashMap<>();
        private final Map<String, byte[]> mockPreimageBytes = new HashMap<>();

        public WitnessContext() {
            // Reference defaults match the TS RunarInterpreter._mockPreimage.
            mockPreimage.put("locktime", BigInteger.ZERO);
            mockPreimage.put("amount", BigInteger.valueOf(10_000));
            mockPreimage.put("version", BigInteger.ONE);
            mockPreimage.put("sequence", BigInteger.valueOf(0xfffffffeL));
        }

        /** Mirror of {@code TestContract.setPrevOutScript(inputIndex, bytes)}. */
        public WitnessContext setPrevOutScript(int inputIndex, byte[] bytes) {
            prevOutScripts.put(inputIndex, bytes == null ? null : bytes.clone());
            return this;
        }

        /** Mirror of {@code TestContract.setSerialisedOutputs(bytes)}. */
        public WitnessContext setSerialisedOutputs(byte[] bytes) {
            this.serialisedOutputs = bytes == null ? null : bytes.clone();
            return this;
        }

        /** Mirror of {@code TestContract.setMockPreimage({ field: value })}. */
        public WitnessContext setMockPreimage(String field, BigInteger value) {
            mockPreimage.put(field, value);
            return this;
        }

        /** Mirror of {@code TestContract.setMockPreimageBytes({ field: bytes })}. */
        public WitnessContext setMockPreimageBytes(String field, byte[] bytes) {
            mockPreimageBytes.put(field, bytes == null ? null : bytes.clone());
            return this;
        }

        byte[] prevOutScript(int idx) { return prevOutScripts.get(idx); }
        boolean hasPrevOutScript(int idx) { return prevOutScripts.containsKey(idx); }
        byte[] serialisedOutputs() { return serialisedOutputs; }
        BigInteger mockBigInt(String field, BigInteger fallback) {
            BigInteger v = mockPreimage.get(field);
            return v == null ? fallback : v;
        }
        byte[] mockBytes(String field, byte[] fallback) {
            byte[] v = mockPreimageBytes.get(field);
            return v == null ? fallback : v;
        }
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Compute the new state for a stateful contract method call by
     * walking the ANF IR. Skips asserts and on-chain-only operations.
     *
     * <p>Equivalent to {@code computeNewState} in the Python/Go/Rust
     * SDKs.
     */
    public static Map<String, Object> computeNewState(
        Map<String, Object> anf,
        String methodName,
        Map<String, Object> currentState,
        Map<String, Object> args,
        List<Object> constructorArgs
    ) {
        return run(anf, methodName, currentState, args, constructorArgs, false, null, null).newState;
    }

    /**
     * Like {@link #executeStrict} but skips asserts and on-chain-only
     * operations — useful when the SDK needs both the new state and the
     * data outputs declared via {@code addDataOutput} but cannot satisfy
     * on-chain assertions (e.g. the auto-injected hashOutputs check on
     * stateful contracts, which only validates against the runtime tx).
     *
     * <p>Mirrors {@code ComputeNewStateAndDataOutputs} in the Go SDK.
     */
    public static ExecutionResult computeNewStateAndDataOutputs(
        Map<String, Object> anf,
        String methodName,
        Map<String, Object> currentState,
        Map<String, Object> args,
        List<Object> constructorArgs
    ) {
        Run r = run(anf, methodName, currentState, args, constructorArgs, false, null, null);
        return new ExecutionResult(r.newState, r.dataOutputs, r.rawOutputs, r.outputs);
    }

    /**
     * Result bundle returned from a strict / lenient / on-chain-authoritative
     * execution. Carries the post-call state, the data outputs declared via
     * {@code this.addDataOutput(...)}, and the raw outputs declared via
     * {@code this.addRawOutput(...)} in the method body.
     *
     * <p>{@code rawOutputs} entries are surfaced verbatim — the simulator
     * does NOT introspect their script bytes (they are caller-supplied raw
     * locking-script bytes). Callers building the broadcast transaction
     * off-chain splice them in at the correct index.
     */
    public static final class ExecutionResult {
        public final Map<String, Object> newState;
        public final List<DataOutput> dataOutputs;
        public final List<DataOutput> rawOutputs;
        /**
         * State-class outputs (state continuation + raw) in SOURCE order
         * (finding G1). A transaction builder MUST emit these in this order —
         * the on-chain covenant folds them into {@code hashOutputs} in exactly
         * this order, so any other ordering fails input 0's state-check
         * OP_VERIFY. Empty for methods that emit no {@code this.addOutput(...)}
         * or {@code this.addRawOutput(...)}.
         */
        public final List<OrderedOutput> outputs;

        ExecutionResult(
            Map<String, Object> newState,
            List<DataOutput> dataOutputs,
            List<DataOutput> rawOutputs,
            List<OrderedOutput> outputs
        ) {
            this.newState = Collections.unmodifiableMap(newState);
            this.dataOutputs = Collections.unmodifiableList(dataOutputs);
            this.rawOutputs = Collections.unmodifiableList(rawOutputs);
            this.outputs = Collections.unmodifiableList(outputs);
        }
    }

    /**
     * A single output recorded from {@code this.addDataOutput(...)} during
     * interpretation. {@code script} is hex-encoded; {@code satoshis} is
     * the declared amount.
     */
    public record DataOutput(long satoshis, String script) {}

    /**
     * A single state-class output in the exact SOURCE order the method body
     * emits it, capturing the interleaving of {@code this.addOutput(...)}
     * (state continuation) and {@code this.addRawOutput(...)} (caller-supplied
     * script). The compiler folds these into the continuation
     * {@code hashOutputs} in this same order (see
     * {@code packages/runar-compiler/src/passes/04-anf-lower.ts} —
     * {@code add_output} and {@code add_raw_output} share one
     * {@code addOutputRefs} list), so a transaction builder MUST emit them in
     * this order or the on-chain state-check OP_VERIFY rejects (finding G1).
     *
     * <p>{@code kind} is {@code "state"} or {@code "raw"}. {@code script} is
     * populated (hex) for {@code raw} entries only; {@code state} entries take
     * the freshly computed continuation locking script from the caller. Data
     * outputs ({@code add_data_output}) are NOT included here — they are always
     * emitted after every state-class output, in their own {@code dataOutputs}
     * list.
     */
    public record OrderedOutput(String kind, long satoshis, String script) {}

    /**
     * Run the method body in strict mode: every {@code assert} binding's
     * condition is evaluated and the call throws
     * {@link AssertionFailureException} on failure.
     *
     * <p>Hash primitives (SHA-256, RIPEMD-160, hash160, hash256) are real.
     * ECDSA primitives ({@code checkSig}, {@code checkMultiSig},
     * {@code checkPreimage}) are mocked to {@code true}; for real ECDSA
     * verification use {@link #executeOnChainAuthoritative}.
     */
    public static ExecutionResult executeStrict(
        Map<String, Object> anf,
        String methodName,
        Map<String, Object> currentState,
        Map<String, Object> args,
        List<Object> constructorArgs
    ) {
        Run r = run(anf, methodName, currentState, args, constructorArgs, true, null, null);
        return new ExecutionResult(r.newState, r.dataOutputs, r.rawOutputs, r.outputs);
    }

    /**
     * Strict execution with a {@link WitnessContext} carrying off-chain
     * witness bytes ({@code _prevOutScript_<i>}, {@code _serialisedOutputs})
     * and mock preimage fields ({@code locktime}, {@code amount}, ...).
     *
     * <p>Mirrors the TS reference's
     * {@code c.setPrevOutScript / c.setSerialisedOutputs /
     * c.setMockPreimage / c.setMockPreimageBytes} setup channel used to
     * exercise the four intent-intrinsic fixtures end-to-end.
     */
    public static ExecutionResult executeStrict(
        Map<String, Object> anf,
        String methodName,
        Map<String, Object> currentState,
        Map<String, Object> args,
        List<Object> constructorArgs,
        WitnessContext witness
    ) {
        Run r = run(anf, methodName, currentState, args, constructorArgs, true, null, witness);
        return new ExecutionResult(r.newState, r.dataOutputs, r.rawOutputs, r.outputs);
    }

    /**
     * On-chain authoritative simulation: strict assert enforcement PLUS real
     * ECDSA verification ({@code checkSig}, {@code checkMultiSig}) and real
     * SHA-256 preimage check ({@code checkPreimage}) against the supplied
     * 32-byte BIP-143 sighash in {@code ctx}.
     *
     * <p>The {@code ctx} parameter is mandatory and carries the sighash, so
     * callers cannot invoke this entry point accidentally without supplying
     * the cryptographic inputs that verification needs.
     *
     * <p>{@code checkSig(sig, pk)} parses {@code pk} as a SEC1 secp256k1
     * point (compressed or uncompressed), parses {@code sig} as DER (with
     * an optional trailing sighash type byte stripped), and runs ECDSA
     * verification through BouncyCastle. Failure trips the enclosing
     * {@code assert(...)} and throws {@link AssertionFailureException}.
     *
     * <p>{@code checkMultiSig(sigs, pks)} iterates signatures left-to-right
     * and consumes pubkeys greedily, mirroring Bitcoin's
     * {@code OP_CHECKMULTISIG}. {@code sigs} and {@code pks} must be
     * {@code List<?>} of hex strings or byte arrays.
     *
     * <p>{@code checkPreimage(preimage)} computes
     * {@code SHA256(SHA256(preimage))} and compares to {@code ctx.sighash}
     * — the on-chain {@code OP_PUSH_TX} semantic.
     */
    public static ExecutionResult executeOnChainAuthoritative(
        Map<String, Object> anf,
        String methodName,
        Map<String, Object> currentState,
        Map<String, Object> args,
        List<Object> constructorArgs,
        OnChainCryptoContext ctx
    ) {
        if (ctx == null || ctx.sighash() == null || ctx.sighash().length != 32) {
            throw new IllegalArgumentException(
                "executeOnChainAuthoritative: ctx.sighash must be exactly 32 bytes"
            );
        }
        Run r = run(anf, methodName, currentState, args, constructorArgs, true, ctx, null);
        return new ExecutionResult(r.newState, r.dataOutputs, r.rawOutputs, r.outputs);
    }

    /**
     * Required cryptographic context for {@link #executeOnChainAuthoritative}.
     * The 32-byte BIP-143 sighash that crypto built-ins verify against.
     */
    public record OnChainCryptoContext(byte[] sighash) {
        public OnChainCryptoContext {
            if (sighash != null) sighash = sighash.clone();
        }
        @Override public byte[] sighash() { return sighash == null ? null : sighash.clone(); }

        /** Convenience constructor accepting a hex-encoded sighash. */
        public static OnChainCryptoContext fromHex(String hex) {
            return new OnChainCryptoContext(HEX.parseHex(hex));
        }
    }

    /**
     * Thrown when an {@code assert} binding's condition is falsy in strict
     * mode. Carries the contract method name plus the ANF binding name (e.g.
     * {@code t17}, {@code t8}) so a developer can pinpoint the exact failing
     * guard. Cross-tier wire format mirrors the TS / Go / Zig / Ruby SDKs:
     *
     * <pre>{@code
     * assert failed in <methodName>: binding '<bindingName>' evaluated to false
     * }</pre>
     */
    public static final class AssertionFailureException extends RuntimeException {
        private final String methodName;
        private final String bindingName;

        public AssertionFailureException(String methodName, String bindingName) {
            super(formatMessage(methodName, bindingName));
            this.methodName = methodName == null ? "" : methodName;
            this.bindingName = bindingName == null ? "" : bindingName;
        }

        /**
         * Legacy single-arg constructor retained for source-compatibility with
         * callers that don't yet carry the method/binding context. The
         * standard message format is parsed when possible to populate the
         * fields; otherwise they default to empty strings.
         */
        public AssertionFailureException(String message) {
            super(message);
            this.methodName = "";
            this.bindingName = "";
        }

        public String methodName() { return methodName; }
        public String bindingName() { return bindingName; }

        private static String formatMessage(String methodName, String bindingName) {
            return "assert failed in " + (methodName == null ? "" : methodName)
                + ": binding '" + (bindingName == null ? "" : bindingName) + "' evaluated to false";
        }
    }

    /** Thrown when the ANF IR is missing or refers to an unknown method. */
    public static final class InterpreterException extends RuntimeException {
        public InterpreterException(String message) {
            super(message);
        }
    }

    // ------------------------------------------------------------------
    // Top-level walk
    // ------------------------------------------------------------------

    private static final class Run {
        final Map<String, Object> newState;
        final List<DataOutput> dataOutputs;
        final List<DataOutput> rawOutputs;
        final List<OrderedOutput> outputs;
        Run(Map<String, Object> s, List<DataOutput> o, List<DataOutput> r, List<OrderedOutput> ord) {
            this.newState = s;
            this.dataOutputs = o;
            this.rawOutputs = r;
            this.outputs = ord;
        }
    }

    @SuppressWarnings("unchecked")
    private static Run run(
        Map<String, Object> anf,
        String methodName,
        Map<String, Object> currentState,
        Map<String, Object> args,
        List<Object> constructorArgs,
        boolean strict,
        OnChainCryptoContext realCrypto,
        WitnessContext witness
    ) {
        if (anf == null) {
            throw new InterpreterException("AnfInterpreter: anf IR is null");
        }
        if (currentState == null) currentState = Map.of();
        if (args == null) args = Map.of();
        if (constructorArgs == null) constructorArgs = List.of();

        List<Map<String, Object>> properties = listOfObjects(anf.get("properties"));
        List<Map<String, Object>> methods = listOfObjects(anf.get("methods"));

        Map<String, Object> method = null;
        for (Map<String, Object> m : methods) {
            String name = (String) m.get("name");
            boolean isPublic = m.get("isPublic") instanceof Boolean b && b;
            if (methodName.equals(name) && isPublic) {
                method = m;
                break;
            }
        }
        if (method == null) {
            throw new InterpreterException(
                "AnfInterpreter: method '" + methodName + "' not found in ANF IR"
            );
        }

        // Build constructor index for non-initialized properties
        Map<String, Integer> ctorIdx = new HashMap<>();
        int ci = 0;
        for (Map<String, Object> p : properties) {
            if (!p.containsKey("initialValue") || p.get("initialValue") == null) {
                ctorIdx.put((String) p.get("name"), ci);
                ci++;
            }
        }

        // Initialise environment with properties: mutable -> currentState,
        // non-initialised -> constructorArgs by ctor-param index, initialised
        // -> declared initialValue.
        Map<String, Object> env = new LinkedHashMap<>();
        for (Map<String, Object> p : properties) {
            String pname = (String) p.get("name");
            if (currentState.containsKey(pname)) {
                env.put(pname, currentState.get(pname));
            } else if (p.get("initialValue") != null) {
                env.put(pname, p.get("initialValue"));
            } else if (ctorIdx.containsKey(pname)) {
                int idx = ctorIdx.get(pname);
                if (idx < constructorArgs.size()) {
                    env.put(pname, constructorArgs.get(idx));
                }
            }
        }

        // Method params: skip implicit ones; map by name.
        // Auto-injected intent-intrinsic params (`_prevOutScript_<i>`,
        // `_serialisedOutputs`) read from the witness context instead of
        // `args`. Missing witness bytes raise InterpreterException with
        // the same "requires witness bytes" sentinel the TS reference uses.
        List<Map<String, Object>> params = listOfObjects(method.get("params"));
        for (Map<String, Object> param : params) {
            String pname = (String) param.get("name");
            if (IMPLICIT_PARAMS.contains(pname)) continue;
            if (pname != null && pname.startsWith("_prevOutScript_")) {
                int idx;
                try {
                    idx = Integer.parseInt(pname.substring("_prevOutScript_".length()));
                } catch (NumberFormatException nfe) {
                    idx = -1;
                }
                byte[] bytes = witness == null ? null : witness.prevOutScript(idx);
                if (bytes != null) {
                    env.put(pname, HEX.formatHex(bytes));
                    continue;
                }
                if (args.containsKey(pname)) {
                    env.put(pname, args.get(pname));
                    continue;
                }
                if (strict) {
                    throw new InterpreterException(
                        "extractPrevOutputScript(" + idx + ") requires witness bytes. "
                            + "Call WitnessContext.setPrevOutScript(" + idx
                            + ", bytes) before invoking the method."
                    );
                }
                continue;
            }
            if ("_serialisedOutputs".equals(pname)) {
                byte[] bytes = witness == null ? null : witness.serialisedOutputs();
                if (bytes != null) {
                    env.put(pname, HEX.formatHex(bytes));
                    continue;
                }
                if (args.containsKey(pname)) {
                    env.put(pname, args.get(pname));
                    continue;
                }
                if (strict) {
                    throw new InterpreterException(
                        "requireOutputP2PKH requires witness bytes. "
                            + "Call WitnessContext.setSerialisedOutputs(bytes) before invoking the method."
                    );
                }
                continue;
            }
            if (args.containsKey(pname)) {
                env.put(pname, args.get(pname));
            }
        }

        Map<String, Object> stateDelta = new LinkedHashMap<>();
        List<DataOutput> dataOutputs = new ArrayList<>();
        List<DataOutput> rawOutputs = new ArrayList<>();
        // State-class outputs (state continuation + raw) in source order (finding G1).
        List<OrderedOutput> outputs = new ArrayList<>();

        evalBindings(anf, listOfObjects(method.get("body")), env, stateDelta, dataOutputs, rawOutputs, outputs, strict, realCrypto, witness, methodName);

        Map<String, Object> newState = new LinkedHashMap<>();
        newState.putAll(currentState);
        newState.putAll(stateDelta);
        return new Run(newState, dataOutputs, rawOutputs, outputs);
    }

    // ------------------------------------------------------------------
    // Binding evaluation
    // ------------------------------------------------------------------

    private static void evalBindings(
        Map<String, Object> anf,
        List<Map<String, Object>> bindings,
        Map<String, Object> env,
        Map<String, Object> stateDelta,
        List<DataOutput> dataOutputs,
        List<DataOutput> rawOutputs,
        List<OrderedOutput> outputs,
        boolean strict,
        OnChainCryptoContext realCrypto,
        WitnessContext witness,
        String methodName
    ) {
        // A fresh per-method-body side map for raw byte-array-op results
        // (& | ^ << >> ~). Private method calls route through this overload,
        // so each private method gets its own map — matching the TS/Go/Python
        // references, which pass no scriptBytes across the private-method
        // boundary.
        evalBindings(anf, bindings, env, stateDelta, dataOutputs, rawOutputs, outputs, strict, realCrypto, witness, methodName, new java.util.HashSet<>(), new HashMap<>());
    }

    /**
     * Walk the binding list, propagating the continuation-taint set used
     * to skip the auto-injected stateful-contract continuation-hash assert
     * under strict mode. Bindings whose value is a {@code computeStateOutput}
     * call or {@code get_state_script} ANF node mark the head of the
     * synthetic continuation-hash subgraph; downstream bindings that consume
     * a tainted ref inherit the taint. Mirrors the Python reference's
     * {@code continuation_taint} mechanism.
     */
    private static void evalBindings(
        Map<String, Object> anf,
        List<Map<String, Object>> bindings,
        Map<String, Object> env,
        Map<String, Object> stateDelta,
        List<DataOutput> dataOutputs,
        List<DataOutput> rawOutputs,
        List<OrderedOutput> outputs,
        boolean strict,
        OnChainCryptoContext realCrypto,
        WitnessContext witness,
        String methodName,
        java.util.Set<String> continuationTaint,
        // Per-binding raw stack bytes for byte-array-op results (& | ^ << >> ~).
        // Keyed by binding name; lets a chained op read the real (possibly
        // non-minimal) length of a prior op's result instead of re-minimising
        // its numeric value. `env` stays pure (decoded values) so state
        // serialization is unaffected.
        Map<String, byte[]> scriptBytes
    ) {
        for (Map<String, Object> binding : bindings) {
            String bindingName = (String) binding.get("name");
            Map<String, Object> valueNode = asObject(binding.get("value"));
            Object val = evalValue(anf, valueNode, env, stateDelta, dataOutputs, rawOutputs, outputs, strict, realCrypto, witness, methodName, bindingName, continuationTaint, scriptBytes);
            env.put(bindingName, val);
            if (isContinuationOrigin(valueNode) || refsTainted(valueNode, continuationTaint)) {
                continuationTaint.add(bindingName);
            }
        }
    }

    private static boolean isContinuationOrigin(Map<String, Object> value) {
        if (value == null) return false;
        String kind = String.valueOf(value.getOrDefault("kind", ""));
        if ("call".equals(kind)) {
            Object f = value.get("func");
            if ("computeStateOutput".equals(f)
                || "buildChangeOutput".equals(f)
                || "buildDataOutput".equals(f)
                || "buildRawOutput".equals(f)) {
                return true;
            }
        }
        if ("get_state_script".equals(kind)
            || "add_output".equals(kind)
            || "add_raw_output".equals(kind)
            || "add_data_output".equals(kind)) {
            return true;
        }
        return false;
    }

    /** Return true if any ref-shaped field of {@code value} names a tainted binding. */
    private static boolean refsTainted(Map<String, Object> value, java.util.Set<String> taint) {
        if (value == null || taint.isEmpty()) return false;
        for (String k : new String[]{"left", "right", "operand", "object", "cond"}) {
            Object v = value.get(k);
            if (v instanceof String s && taint.contains(s)) return true;
        }
        Object args = value.get("args");
        if (args instanceof List<?> raw) {
            for (Object a : raw) {
                if (a instanceof String s && taint.contains(s)) return true;
            }
        }
        Object v = value.get("value");
        if (v instanceof String s) {
            String ref = s.startsWith("@ref:") ? s.substring(5) : s;
            if (taint.contains(ref)) return true;
        }
        for (String k : new String[]{"satoshis", "scriptBytes", "preimage"}) {
            Object x = value.get(k);
            if (x instanceof String s && taint.contains(s)) return true;
        }
        Object sv = value.get("stateValues");
        if (sv instanceof List<?> raw) {
            for (Object a : raw) {
                if (a instanceof String s && taint.contains(s)) return true;
            }
        }
        return false;
    }

    private static Object evalValue(
        Map<String, Object> anf,
        Map<String, Object> value,
        Map<String, Object> env,
        Map<String, Object> stateDelta,
        List<DataOutput> dataOutputs,
        List<DataOutput> rawOutputs,
        List<OrderedOutput> outputs,
        boolean strict,
        OnChainCryptoContext realCrypto,
        WitnessContext witness,
        String methodName,
        String bindingName,
        java.util.Set<String> continuationTaint,
        Map<String, byte[]> scriptBytes
    ) {
        String kind = String.valueOf(value.getOrDefault("kind", ""));

        switch (kind) {
            case "load_param":
            case "load_prop": {
                return env.get((String) value.get("name"));
            }
            case "load_const": {
                Object v = value.get("value");
                if (v instanceof String s && s.startsWith("@ref:")) {
                    String target = s.substring(5);
                    aliasScriptBytes(scriptBytes, target, bindingName);
                    return env.get(target);
                }
                // On-disk ANF spells every bigint as a `"<decimal>n"` STRING
                // (see `jsonWithBigInt` in runar-cli's compile command) — that
                // is the artifact every SDK loads with a bare JSON parse.
                // Decode it here so a const operand is a BigInteger, not a
                // String: the byte-op paths below gate on
                // `!(operand instanceof String)`, so leaving it a string
                // silently routes `<< >> & | ^ ~` down the ByteString branch
                // and the SDK builds a continuation the deployed script
                // disagrees with (NEW-008). Go / Rust / Zig already decode
                // this shape; this makes all seven agree with the script.
                //
                // Unambiguous: ANF ByteString literals are hex and `n` is not
                // a hex digit, so `^-?\d+n$` cannot be a bytestring.
                if (v instanceof String s && BIGINT_LITERAL.matcher(s).matches()) {
                    return new BigInteger(s.substring(0, s.length() - 1));
                }
                return v;
            }
            case "bin_op": {
                String op = (String) value.get("op");
                String leftRef = (String) value.get("left");
                String rightRef = (String) value.get("right");
                Object left = env.get(leftRef);
                Object right = env.get(rightRef);
                String resultType = (String) value.get("result_type");
                // Numeric byte-array ops (& | ^ << >>) thread the operands' real
                // stack bytes so chained expressions match the deployed script:
                // a shift/bitwise result can be non-minimal (e.g. `2 << 8`
                // leaves a 1-byte 0x00, whereas the minimal encoding of 0 is
                // empty), and the next length-sensitive op must see that real
                // length. An operand's bytes are the side-map entry if present,
                // else the minimal encoding of its numeric value. ByteString
                // ops (result_type 'bytes' / string operands) fall through to
                // evalBinOp's minimal-operand path.
                boolean isNumericByteOp =
                    ("&".equals(op) || "|".equals(op) || "^".equals(op)
                        || "<<".equals(op) || ">>".equals(op))
                    && !"bytes".equals(resultType)
                    && !(left instanceof String)
                    && !(right instanceof String);
                if (isNumericByteOp) {
                    byte[] ab = scriptBytes.containsKey(leftRef)
                        ? scriptBytes.get(leftRef)
                        : MockCrypto.encodeScriptNumber(toBigInt(left));
                    byte[] rb;
                    if ("<<".equals(op) || ">>".equals(op)) {
                        // Shift count is read as a number on-chain — only `ab`'s
                        // length is significant, so the count operand's bytes
                        // are never consulted for length. But being read AS A
                        // NUMBER means the count must be minimally encoded, or
                        // the shift aborts.
                        assertMinimalNumericOperand(scriptBytes, rightRef, right);
                        rb = scriptNumberShiftBytes(op, ab, toBigInt(right));
                    } else {
                        byte[] bb = scriptBytes.containsKey(rightRef)
                            ? scriptBytes.get(rightRef)
                            : MockCrypto.encodeScriptNumber(toBigInt(right));
                        rb = scriptNumberBitwiseBytes(op, ab, bb);
                    }
                    scriptBytes.put(bindingName, rb);
                    return MockCrypto.decodeScriptNumber(rb);
                }
                // Numeric consumers decode BOTH operands with fRequireMinimal,
                // so a threaded non-minimal intermediate (e.g. the 1-byte
                // [0x00] that `1 >> 1` leaves) aborts the script rather than
                // silently re-minimising to 0. Byte-typed ops are exempt: they
                // never carry threaded bytes and OP_CAT/OP_EQUAL impose no
                // numeric decode.
                boolean isBytesPath = "bytes".equals(resultType)
                    || (left instanceof String && right instanceof String);
                if (isNumericConsumerOp(op) && !isBytesPath) {
                    assertMinimalNumericOperand(scriptBytes, leftRef, left);
                    assertMinimalNumericOperand(scriptBytes, rightRef, right);
                }
                return evalBinOp(op, left, right, resultType);
            }
            case "unary_op": {
                String op = (String) value.get("op");
                String operandRef = (String) value.get("operand");
                Object operand = env.get(operandRef);
                String resultType = (String) value.get("result_type");
                // OP_INVERT threads the operand's real stack bytes too
                // (length-preserving): `~(2 << 8)` inverts the 1-byte 0x00 to
                // 0xff (= -127 decoded), not the minimal encoding of 0.
                if ("~".equals(op) && !"bytes".equals(resultType) && !(operand instanceof String)) {
                    byte[] ab = scriptBytes.containsKey(operandRef)
                        ? scriptBytes.get(operandRef)
                        : MockCrypto.encodeScriptNumber(toBigInt(operand));
                    byte[] rb = scriptNumberInvertBytes(ab);
                    scriptBytes.put(bindingName, rb);
                    return MockCrypto.decodeScriptNumber(rb);
                }
                // Every other unary op reads its operand as a script NUMBER
                // (`-` -> OP_NEGATE) or coerces it to a boolean (`!` ->
                // OP_NOT), both fRequireMinimal decodes. `~` never reaches here
                // on the numeric path — it is a byte op and must keep accepting
                // non-minimal bytes.
                assertMinimalNumericOperand(scriptBytes, operandRef, operand);
                return evalUnaryOp(op, operand, resultType);
            }
            case "call": {
                String func = (String) value.get("func");
                List<String> argNames = stringList(value.get("args"));
                // The single funnel every numeric builtin (`abs`, `min`, `max`,
                // `within`, `safediv`, `clamp`, `sign`, `bool`, ...) reads its
                // operands through. Only a NUMERIC byte-op result ever carries
                // threaded bytes, and a bigint argument is exactly what those
                // builtins decode with fRequireMinimal on chain — a ByteString
                // argument can never carry an entry here, so gating every
                // argument costs nothing and cannot miss a builtin.
                for (String n : argNames) {
                    assertMinimalNumericOperand(scriptBytes, n, env.get(n));
                }
                List<Object> argVals = new ArrayList<>(argNames.size());
                for (String n : argNames) argVals.add(env.get(n));
                // Strict mode: a `call(assert, x)` lowering path enforces the
                // predicate the same way the dedicated `assert` ANF node does.
                if (strict && "assert".equals(func)) {
                    Object pred = argVals.isEmpty() ? null : argVals.get(0);
                    if (!isTruthy(pred)) {
                        throw new AssertionFailureException(methodName, bindingName);
                    }
                    return null;
                }
                return evalCall(func, argVals, realCrypto, witness);
            }
            case "method_call": {
                String mname = (String) value.get("method");
                List<String> argNames = stringList(value.get("args"));
                List<Object> argVals = new ArrayList<>(argNames.size());
                for (String n : argNames) argVals.add(env.get(n));
                return evalMethodCall(anf, mname, argVals, env, stateDelta, dataOutputs, rawOutputs, outputs, strict, realCrypto, witness, methodName);
            }
            case "if": {
                Object cond = env.get((String) value.get("cond"));
                List<Map<String, Object>> branch = isTruthy(cond)
                    ? listOfObjects(value.get("then"))
                    : listOfObjects(value.get("else"));
                Map<String, Object> childEnv = new LinkedHashMap<>(env);
                evalBindings(anf, branch, childEnv, stateDelta, dataOutputs, rawOutputs, outputs, strict, realCrypto, witness, methodName, continuationTaint, scriptBytes);
                env.putAll(childEnv);
                if (!branch.isEmpty()) {
                    String lastName = (String) branch.get(branch.size() - 1).get("name");
                    aliasScriptBytes(scriptBytes, lastName, bindingName);
                    return childEnv.get(lastName);
                }
                return null;
            }
            case "loop": {
                long count = toBigInt(value.get("count")).longValueExact();
                String iterVar = (String) value.getOrDefault("iterVar", "");
                // Iteration `i` binds `iterVar = start + i*step` (issue #121).
                // Older ANF payloads without start/step describe zero-start
                // counting-up loops.
                BigInteger start = value.containsKey("start")
                    ? toBigInt(value.get("start")) : BigInteger.ZERO;
                BigInteger step = value.containsKey("step")
                    ? toBigInt(value.get("step")) : BigInteger.ONE;
                List<Map<String, Object>> body = listOfObjects(value.get("body"));
                Object lastVal = null;
                for (long i = 0; i < count; i++) {
                    env.put(iterVar, start.add(step.multiply(BigInteger.valueOf(i))));
                    Map<String, Object> loopEnv = new LinkedHashMap<>(env);
                    evalBindings(anf, body, loopEnv, stateDelta, dataOutputs, rawOutputs, outputs, strict, realCrypto, witness, methodName, continuationTaint, scriptBytes);
                    env.putAll(loopEnv);
                    if (!body.isEmpty()) {
                        String lastName = (String) body.get(body.size() - 1).get("name");
                        aliasScriptBytes(scriptBytes, lastName, bindingName);
                        lastVal = loopEnv.get(lastName);
                    }
                }
                return lastVal;
            }
            case "assert": {
                if (strict) {
                    // Marker-based skip: the compiler auto-emits the final
                    // continuation-hash check on every stateful-contract
                    // method (hash256(continuationOutputs) ===
                    // extractOutputHash(preimage)). The lowering pass
                    // (compilers/java/.../passes/AnfLower.java) tags ONLY
                    // that assert with isAutoInjectedStateCheck: true.
                    // The on-chain VM is the authoritative source for the
                    // check; we have no script bytes off-chain to make
                    // hash256(continuation) === extractOutputHash(preimage)
                    // hold. Developer-written covenant asserts with the
                    // identical IR shape carry no marker and ARE enforced
                    // (the previous taint heuristic misfired on them; see
                    // BUG-002).
                    if (Boolean.TRUE.equals(value.get("isAutoInjectedStateCheck"))) {
                        return null;
                    }
                    String predRef = (String) value.get("value");
                    Object cond = env.get(predRef);
                    if (!isTruthy(cond)) {
                        throw new AssertionFailureException(methodName, bindingName);
                    }
                }
                return null;
            }
            case "check_preimage": {
                // On-chain-only: the on-chain script enforces sighash
                // equality. Off-chain we can only mock it once the caller has
                // supplied witness bytes (i.e. is genuinely simulating a
                // concrete spend) — then mock-return TRUE so the wrapping
                // `assert(check_preimage(...))` in the stateful-contract
                // prologue doesn't trip strict mode. With no WitnessContext
                // the preimage is unverifiable off-chain, so we return a
                // falsy value and let strict mode report the failure at the
                // prologue assert — matching the TS/Go/Rust/Ruby/Zig tiers
                // (and the pinned cross-interpreter strict goldens). Real
                // preimage verification belongs in executeOnChainAuthoritative.
                return witness != null ? Boolean.TRUE : null;
            }
            case "update_prop": {
                String pname = (String) value.get("name");
                Object newVal = env.get((String) value.get("value"));
                env.put(pname, newVal);
                stateDelta.put(pname, newVal);
                return null;
            }
            case "add_output": {
                List<String> stateValues = stringList(value.get("stateValues"));
                if (!stateValues.isEmpty() && anf != null) {
                    List<String> mutableProps = new ArrayList<>();
                    for (Map<String, Object> p : listOfObjects(anf.get("properties"))) {
                        boolean ro = p.get("readonly") instanceof Boolean b && b;
                        if (!ro) mutableProps.add((String) p.get("name"));
                    }
                    for (int i = 0; i < stateValues.size() && i < mutableProps.size(); i++) {
                        Object resolved = env.get(stateValues.get(i));
                        env.put(mutableProps.get(i), resolved);
                        stateDelta.put(mutableProps.get(i), resolved);
                    }
                }
                // Record the state continuation output in source order (finding
                // G1): a method may interleave raw outputs around it, and the
                // on-chain covenant folds them into hashOutputs in exactly this
                // order. `script` is null — the caller supplies the freshly
                // computed continuation locking script.
                long stateSats = toBigInt(env.get((String) value.get("satoshis"))).longValueExact();
                outputs.add(new OrderedOutput("state", stateSats, null));
                return null;
            }
            case "add_data_output": {
                String satRef = (String) value.getOrDefault("satoshis", "");
                String scriptRef = (String) value.getOrDefault("scriptBytes", "");
                long sats = toBigInt(env.get(satRef)).longValueExact();
                Object scriptVal = env.get(scriptRef);
                String scriptHex = scriptVal instanceof String s ? s : "";
                dataOutputs.add(new DataOutput(sats, scriptHex));
                return null;
            }
            case "add_raw_output": {
                // `addRawOutput(satoshis, scriptBytes)`. The simulator does
                // NOT introspect the script bytes (they're caller-supplied
                // raw locking script); it forwards them in the result
                // envelope so an off-chain transaction builder can splice
                // the output in at the correct index. Crypto built-ins
                // remain mocked even in strict mode.
                long sats = toBigInt(env.get((String) value.get("satoshis"))).longValueExact();
                String script = (String) env.get((String) value.get("scriptBytes"));
                if (script == null) script = "";
                rawOutputs.add(new DataOutput(sats, script));
                // Also record in the ordered state-class output list so a
                // transaction builder can emit it at the correct source-order
                // index (finding G1).
                outputs.add(new OrderedOutput("raw", sats, script));
                return null;
            }
            default:
                if (CHAIN_ONLY_KINDS.contains(kind)) return null;
                return null;
        }
    }

    private static Object evalMethodCall(
        Map<String, Object> anf,
        String methodName,
        List<Object> argVals,
        Map<String, Object> callerEnv,
        Map<String, Object> stateDelta,
        List<DataOutput> dataOutputs,
        List<DataOutput> rawOutputs,
        List<OrderedOutput> outputs,
        boolean strict,
        OnChainCryptoContext realCrypto,
        WitnessContext witness,
        String callerMethodName
    ) {
        if (anf == null || methodName == null) return null;
        for (Map<String, Object> m : listOfObjects(anf.get("methods"))) {
            String name = (String) m.get("name");
            boolean isPublic = m.get("isPublic") instanceof Boolean b && b;
            if (methodName.equals(name) && !isPublic) {
                Map<String, Object> callEnv = new LinkedHashMap<>();
                // Copy property values from caller env
                for (Map<String, Object> p : listOfObjects(anf.get("properties"))) {
                    String pname = (String) p.get("name");
                    if (callerEnv.containsKey(pname)) callEnv.put(pname, callerEnv.get(pname));
                }
                // Map params to args
                List<Map<String, Object>> params = listOfObjects(m.get("params"));
                for (int i = 0; i < params.size() && i < argVals.size(); i++) {
                    callEnv.put((String) params.get(i).get("name"), argVals.get(i));
                }
                List<Map<String, Object>> body = listOfObjects(m.get("body"));
                Map<String, Object> childDelta = new LinkedHashMap<>();
                // Strict-mode failures inside a private helper still report
                // the public method name the caller invoked. Mirrors how the
                // TS SDK threads `methodName` through evalMethodCall.
                evalBindings(anf, body, callEnv, childDelta, dataOutputs, rawOutputs, outputs, strict, realCrypto, witness, callerMethodName);
                stateDelta.putAll(childDelta);
                // Mirror property mutations back into caller env
                for (Map.Entry<String, Object> e : childDelta.entrySet()) {
                    callerEnv.put(e.getKey(), e.getValue());
                }
                if (!body.isEmpty()) {
                    return callEnv.get((String) body.get(body.size() - 1).get("name"));
                }
                return null;
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Binary ops
    // ------------------------------------------------------------------

    private static Object evalBinOp(String op, Object left, Object right, String resultType) {
        if ("bytes".equals(resultType) || (isHexString(left) && isHexString(right))) {
            return evalBytesBinOp(op, asString(left), asString(right));
        }
        BigInteger l = toBigInt(left);
        BigInteger r = toBigInt(right);
        switch (op) {
            case "+":  return l.add(r);
            case "-":  return l.subtract(r);
            case "*":  return l.multiply(r);
            case "/":  return r.signum() == 0 ? BigInteger.ZERO : l.divide(r);
            case "%":  return r.signum() == 0 ? BigInteger.ZERO : l.remainder(r);
            case "==": case "===": return l.compareTo(r) == 0;
            case "!=": case "!==": return l.compareTo(r) != 0;
            case "<":  return l.compareTo(r) < 0;
            case "<=": return l.compareTo(r) <= 0;
            case ">":  return l.compareTo(r) > 0;
            case ">=": return l.compareTo(r) >= 0;
            case "&&": case "and": return isTruthy(left) && isTruthy(right);
            case "||": case "or":  return isTruthy(left) || isTruthy(right);
            // & | ^ << >> compile to OP_AND/OP_OR/OP_XOR/OP_LSHIFT/OP_RSHIFT,
            // which operate on the operands' minimal script-number BYTES, not
            // their numeric value. Route through the byte-array helpers so the
            // interpreter agrees with the deployed script byte-for-byte.
            case "&":  case "|":  case "^":  return scriptNumberBitwise(op, l, r);
            case "<<": case ">>": return scriptNumberShift(op, l, r);
            default:   return BigInteger.ZERO;
        }
    }

    private static Object evalBytesBinOp(String op, String left, String right) {
        switch (op) {
            case "+":  return left + right;
            case "==": case "===": return left.equals(right);
            case "!=": case "!==": return !left.equals(right);
            default:   return "";
        }
    }

    private static Object evalUnaryOp(String op, Object operand, String resultType) {
        if ("bytes".equals(resultType)) {
            if ("~".equals(op)) {
                byte[] data = HEX.parseHex(asString(operand));
                byte[] out = new byte[data.length];
                for (int i = 0; i < data.length; i++) out[i] = (byte) (~data[i] & 0xff);
                return HEX.formatHex(out);
            }
            return operand;
        }
        BigInteger v = toBigInt(operand);
        switch (op) {
            case "-":  return v.negate();
            case "!":  case "not": return !isTruthy(operand);
            // OP_INVERT flips the operand's script-number BYTES, not native
            // two's-complement ~n (~5 is -122 on-chain, not -6).
            case "~":  return scriptNumberInvert(v);
            default:   return v;
        }
    }

    // ------------------------------------------------------------------
    // Script-number bitwise / shift semantics (byte-array ops, NOT numeric)
    // ------------------------------------------------------------------
    //
    // OP_AND/OP_OR/OP_XOR/OP_INVERT/OP_LSHIFT/OP_RSHIFT operate on the RAW BYTES
    // of the operands' minimal script-number encoding, not on their numeric
    // value (spec/opcodes.md). AND/OR/XOR require equal-length operands and
    // abort otherwise; shifts treat the byte array as a big-endian bit string
    // and preserve its length (LSHIFT masks off overflow MSBs). These helpers
    // reproduce EXACTLY what the deployed script's opcode handlers do, so the
    // interpreter (which models values as BigInteger) agrees with the on-chain
    // script byte-for-byte. Mirrors the TS reference
    // packages/runar-testing/src/vm/utils.ts scriptNumber*. Callers convert
    // BigInteger -> minimal bytes -> byte op -> BigInteger.

    // The *Bytes helpers operate on RAW stack bytes (the exact byte array a
    // value occupies on the deployed script's stack), NOT a value's minimal
    // encoding. This matters for CHAINED expressions: a shift/bitwise RESULT can
    // be a non-minimal byte array (e.g. `2 << 8` leaves a 1-byte 0x00), and
    // feeding it to a length-sensitive `& | ^`/shift must see that real length
    // to agree with the deployed script. The interpreter threads these bytes via
    // a per-binding side map (see the `bin_op`/`unary_op` cases in evalValue);
    // values from other sources (literals, arithmetic) are minimal on-chain. The
    // BigInteger wrappers below re-encode operands to their minimal bytes and are
    // used by the single-op truth-table tests only.

    /**
     * Carry a binding's raw stack bytes across an ALIAS — a binding whose value
     * IS another binding's slot: the {@code load_const "@ref:<name>"} every
     * local rebind lowers to, an {@code if} adopting its taken arm's last
     * value, a {@code loop} adopting its body's. Without this, a chained
     * length-sensitive op re-minimises the aliased value and disagrees with the
     * deployed script (NEW-006: {@code (4n ^ 4n)} is a 1-byte {@code 0x00} on
     * the stack but empty when re-minimised from {@code 0n}).
     *
     * <p>Mirrors {@code aliasScriptBytes} in the TS SDK's anf-interpreter, and
     * the {@code rawSlots} marker StackLower already carries across the same
     * constructs.
     *
     * <p>CLEARS when the source has no entry: the alias target is then a
     * freshly pushed, minimal value, so a stale entry left by an earlier
     * binding of the SAME name ({@code let m0 = 4n ^ 4n; m0 = 300n;}) would
     * otherwise be read as this slot's width — a silently wrong value rather
     * than a throw.
     */
    private static void aliasScriptBytes(Map<String, byte[]> scriptBytes, String from, String to) {
        byte[] bytes = scriptBytes.get(from);
        if (bytes != null) {
            scriptBytes.put(to, bytes);
        } else {
            scriptBytes.remove(to);
        }
    }

    /** OP_AND/OP_OR/OP_XOR on raw stack bytes. Aborts (throws) on a length
     *  mismatch, exactly like the on-chain opcodes. */
    static byte[] scriptNumberBitwiseBytes(String op, byte[] av, byte[] bv) {
        if (av.length != bv.length) {
            String name = "&".equals(op) ? "OP_AND" : "|".equals(op) ? "OP_OR" : "OP_XOR";
            throw new InterpreterException(name + ": operands must be same length");
        }
        byte[] result = new byte[av.length];
        for (int i = 0; i < av.length; i++) {
            int x = av[i] & 0xff;
            int y = bv[i] & 0xff;
            int r = "&".equals(op) ? (x & y) : "|".equals(op) ? (x | y) : (x ^ y);
            result[i] = (byte) r;
        }
        return result;
    }

    /** OP_INVERT: flip every bit of the operand's raw stack bytes (length-preserving). */
    static byte[] scriptNumberInvertBytes(byte[] av) {
        byte[] result = new byte[av.length];
        for (int i = 0; i < av.length; i++) {
            result[i] = (byte) (~av[i] & 0xff);
        }
        return result;
    }

    /** OP_LSHIFT/OP_RSHIFT on raw stack bytes as a big-endian bit string,
     *  preserving byte length (LSHIFT masks off overflow MSBs). {@code shift} is
     *  the numeric shift count (read as a number on-chain, so only {@code val}'s
     *  bytes are length-significant). Negative shifts abort like the opcodes. */
    static byte[] scriptNumberShiftBytes(String op, byte[] val, BigInteger shift) {
        if (shift.signum() < 0) {
            throw new InterpreterException(
                ("<<".equals(op) ? "OP_LSHIFT" : "OP_RSHIFT") + ": negative shift");
        }
        if (val.length == 0 || shift.signum() == 0) {
            return val.clone();
        }
        int bitLen = val.length * 8;
        // A shift count >= bitLen zeroes every significant bit (LSHIFT masks the
        // overflow MSBs; RSHIFT drops all bits), so clamp huge counts to bitLen
        // rather than overflowing int in intValueExact() — matching the
        // arbitrary-precision tiers, which never abort on a large count.
        int n = shift.compareTo(BigInteger.valueOf(bitLen)) >= 0
            ? bitLen : shift.intValueExact();
        // Interpret the (little-endian) script-number bytes as a big-endian bit
        // string: val[0] is the most-significant byte of `num`.
        BigInteger num = BigInteger.ZERO;
        for (int i = 0; i < val.length; i++) {
            num = num.shiftLeft(8).or(BigInteger.valueOf(val[i] & 0xff));
        }
        if ("<<".equals(op)) {
            num = num.shiftLeft(n).and(BigInteger.ONE.shiftLeft(bitLen).subtract(BigInteger.ONE));
        } else {
            num = num.shiftRight(n);
        }
        byte[] result = new byte[val.length];
        for (int i = val.length - 1; i >= 0; i--) {
            result[i] = (byte) num.and(BigInteger.valueOf(0xff)).intValue();
            num = num.shiftRight(8);
        }
        return result;
    }

    /**
     * Whether a bin_op consumes its operands NUMERICALLY, i.e. lowers to an
     * opcode that decodes them with {@code fRequireMinimal = true}:
     * OP_ADD/OP_SUB/OP_MUL/OP_DIV/OP_MOD, OP_NUMEQUAL(VERIFY)/OP_NUMNOTEQUAL and
     * the relational ops. The byte-array ops {@code & | ^} and a shift's VALUE
     * operand are deliberately absent — they take raw bytes and only require
     * equal length. {@code &&}/{@code ||} cast to bool, which imposes no
     * minimal-encoding requirement either.
     */
    private static boolean isNumericConsumerOp(String op) {
        switch (op) {
            case "+": case "-": case "*": case "/": case "%":
            case "==": case "===": case "!=": case "!==":
            case "<": case "<=": case ">": case ">=":
                return true;
            default:
                return false;
        }
    }

    /**
     * Abort if {@code ref}'s threaded stack bytes are a NON-minimal encoding of
     * its decoded value — the exact case a numeric consumer rejects on chain
     * ("non-minimally encoded script number"). Only byte-array ops thread bytes,
     * so a ref absent from the side map is minimal by construction and passes.
     *
     * <p>Without this, {@code 1 >> 1} (which leaves the 1-byte {@code [0x00]},
     * NOT the empty minimal zero) is re-minimised to {@code 0} by the numeric
     * path: the interpreter reports a VALID spend for a script that aborts on
     * chain, leaving the UTXO permanently unspendable.
     */
    private static void assertMinimalNumericOperand(
        Map<String, byte[]> scriptBytes, String ref, Object val
    ) {
        byte[] raw = scriptBytes.get(ref);
        if (raw == null) return;
        if (!java.util.Arrays.equals(raw, MockCrypto.encodeScriptNumber(toBigInt(val)))) {
            throw new InterpreterException(
                "non-minimally encoded script number: operand '" + ref + "' occupies "
                + raw.length + " stack byte(s) but decodes to " + toBigInt(val));
        }
    }

    /** OP_AND/OP_OR/OP_XOR on two script-number-valued BigIntegers (minimal
     *  operands). Aborts on length mismatch, exactly like the on-chain opcodes. */
    static BigInteger scriptNumberBitwise(String op, BigInteger a, BigInteger b) {
        return MockCrypto.decodeScriptNumber(scriptNumberBitwiseBytes(
            op, MockCrypto.encodeScriptNumber(a), MockCrypto.encodeScriptNumber(b)));
    }

    /** OP_INVERT on a script-number-valued BigInteger (minimal operand). */
    static BigInteger scriptNumberInvert(BigInteger a) {
        return MockCrypto.decodeScriptNumber(
            scriptNumberInvertBytes(MockCrypto.encodeScriptNumber(a)));
    }

    /** OP_LSHIFT/OP_RSHIFT on a script-number-valued BigInteger (minimal
     *  operand). Preserves byte length; negative shifts abort like the opcodes. */
    static BigInteger scriptNumberShift(String op, BigInteger a, BigInteger shift) {
        return MockCrypto.decodeScriptNumber(
            scriptNumberShiftBytes(op, MockCrypto.encodeScriptNumber(a), shift));
    }

    // ------------------------------------------------------------------
    // Built-in calls
    // ------------------------------------------------------------------

    private static Object evalCall(String func, List<Object> args, OnChainCryptoContext realCrypto, WitnessContext witness) {
        switch (func) {
            // Mocked crypto unless real-crypto context is supplied.
            case "checkSig": {
                if (realCrypto == null) return Boolean.TRUE;
                return verifyEcdsaReal(args.get(0), args.get(1), realCrypto.sighash());
            }
            case "checkMultiSig": {
                if (realCrypto == null) return Boolean.TRUE;
                return verifyMultiSigReal(args.get(0), args.get(1), realCrypto.sighash());
            }
            case "checkPreimage": {
                if (realCrypto == null) return Boolean.TRUE;
                return verifyPreimageReal(args.get(0), realCrypto.sighash());
            }

            // Real hashes
            case "sha256":     return hashHex("sha256", args.get(0));
            case "hash256":    return hashHex("hash256", args.get(0));
            case "hash160":    return hashHex("hash160", args.get(0));
            case "ripemd160":  return hashHex("ripemd160", args.get(0));

            case "assert":     return null;

            // Byte ops
            case "num2bin": {
                BigInteger n = toBigInt(args.get(0));
                int len = toBigInt(args.get(1)).intValueExact();
                return num2binHex(n, len);
            }
            case "bin2num":    return bin2numBigInt(asString(args.get(0)));
            case "cat":        return asString(args.get(0)) + asString(args.get(1));
            case "substr": {
                String h = asString(args.get(0));
                int s = toBigInt(args.get(1)).intValueExact();
                int len = toBigInt(args.get(2)).intValueExact();
                int lo = Math.min(s * 2, h.length());
                int hi = Math.min((s + len) * 2, h.length());
                return h.substring(lo, hi);
            }
            case "reverseBytes": {
                String h = asString(args.get(0));
                StringBuilder sb = new StringBuilder(h.length());
                for (int i = h.length() - 2; i >= 0; i -= 2) {
                    sb.append(h, i, i + 2);
                }
                return sb.toString();
            }
            case "len":        return BigInteger.valueOf(asString(args.get(0)).length() / 2);

            // Math built-ins (delegate to MockCrypto where possible)
            case "abs":        return MockCrypto.abs(toBigInt(args.get(0)));
            case "min":        return MockCrypto.min(toBigInt(args.get(0)), toBigInt(args.get(1)));
            case "max":        return MockCrypto.max(toBigInt(args.get(0)), toBigInt(args.get(1)));
            case "within":     return MockCrypto.within(toBigInt(args.get(0)), toBigInt(args.get(1)), toBigInt(args.get(2)));
            case "safediv": {
                BigInteger d = toBigInt(args.get(1));
                if (d.signum() == 0) return BigInteger.ZERO;
                return toBigInt(args.get(0)).divide(d);
            }
            case "safemod": {
                BigInteger d = toBigInt(args.get(1));
                if (d.signum() == 0) return BigInteger.ZERO;
                return toBigInt(args.get(0)).remainder(d);
            }
            case "clamp":      return MockCrypto.clamp(toBigInt(args.get(0)), toBigInt(args.get(1)), toBigInt(args.get(2)));
            case "sign":       return MockCrypto.sign(toBigInt(args.get(0)));
            case "pow": {
                BigInteger e = toBigInt(args.get(1));
                if (e.signum() < 0) return BigInteger.ZERO;
                return MockCrypto.pow(toBigInt(args.get(0)), e);
            }
            case "sqrt": {
                BigInteger v = toBigInt(args.get(0));
                if (v.signum() <= 0) return BigInteger.ZERO;
                return v.sqrt();
            }
            case "gcd":        return MockCrypto.gcd(toBigInt(args.get(0)), toBigInt(args.get(1)));
            case "divmod": {
                BigInteger b = toBigInt(args.get(1));
                if (b.signum() == 0) return BigInteger.ZERO;
                return toBigInt(args.get(0)).divide(b);
            }
            case "log2": {
                BigInteger v = toBigInt(args.get(0));
                if (v.signum() <= 0) return BigInteger.ZERO;
                return BigInteger.valueOf(v.bitLength() - 1);
            }
            case "bool":       return isTruthy(args.get(0)) ? BigInteger.ONE : BigInteger.ZERO;
            case "mulDiv":     return toBigInt(args.get(0)).multiply(toBigInt(args.get(1))).divide(toBigInt(args.get(2)));
            case "percentOf":  return toBigInt(args.get(0)).multiply(toBigInt(args.get(1))).divide(BigInteger.valueOf(10000));

            // Preimage extractors. When a WitnessContext is supplied, read
            // the mock preimage fields from it (mirroring the TS reference's
            // `_mockPreimage` / `_mockPreimageBytes`). Otherwise fall back
            // to the same zero / default values the TS interpreter emits.
            case "extractLocktime":
                return witness != null
                    ? witness.mockBigInt("locktime", BigInteger.ZERO)
                    : BigInteger.ZERO;
            case "extractAmount":
                return witness != null
                    ? witness.mockBigInt("amount", BigInteger.valueOf(10_000))
                    : BigInteger.valueOf(10_000);
            case "extractVersion":
                return witness != null
                    ? witness.mockBigInt("version", BigInteger.ONE)
                    : BigInteger.ONE;
            case "extractSequence":
                return witness != null
                    ? witness.mockBigInt("sequence", BigInteger.valueOf(0xfffffffeL))
                    : BigInteger.valueOf(0xfffffffeL);
            case "extractInputIndex":
                return BigInteger.ZERO;
            case "extractSigHashType":
                return BigInteger.valueOf(0x41);
            case "extractOutputHash":
            case "extractOutputs":
                return HEX.formatHex(
                    witness != null ? witness.mockBytes("outputHash", new byte[32]) : new byte[32]
                );
            case "extractHashPrevouts":
                return HEX.formatHex(
                    witness != null ? witness.mockBytes("hashPrevouts", new byte[32]) : new byte[32]
                );
            case "extractHashSequence":
                return HEX.formatHex(
                    witness != null ? witness.mockBytes("hashSequence", new byte[32]) : new byte[32]
                );
            case "extractOutpoint":
                return HEX.formatHex(
                    witness != null ? witness.mockBytes("outpoint", new byte[36]) : new byte[36]
                );
            case "extractScriptCode":
                return "";

            // Post-quantum / proof-system primitives — delegate to MockCrypto
            // so they raise UnsupportedOperationException loudly. Never silently
            // truthy.
            case "verifyWOTS":
            case "verifySLHDSA_SHA2_128s":
            case "verifySLHDSA_SHA2_128f":
            case "verifySLHDSA_SHA2_192s":
            case "verifySLHDSA_SHA2_192f":
            case "verifySLHDSA_SHA2_256s":
            case "verifySLHDSA_SHA2_256f":
            case "sha256Compress":
            case "sha256Finalize":
            case "poseidon2Hash":
            case "bn254FieldAdd":
            case "bn254FieldMul":
                throw new UnsupportedOperationException(
                    "AnfInterpreter: '" + func + "' is not implementable off-chain in the Java SDK; "
                        + "test contracts that use this primitive via the compiler+VM path."
                );

            default:
                return null;
        }
    }

    // ------------------------------------------------------------------
    // Hash / number helpers
    // ------------------------------------------------------------------

    private static String hashHex(String name, Object input) {
        byte[] data = HEX.parseHex(asString(input));
        switch (name) {
            case "sha256":    return HEX.formatHex(MockCrypto.sha256(data));
            case "hash256":   return HEX.formatHex(MockCrypto.hash256(data));
            case "hash160":   return HEX.formatHex(MockCrypto.hash160(data));
            case "ripemd160": return HEX.formatHex(MockCrypto.ripemd160(data));
            default:          return "";
        }
    }

    /**
     * Bitcoin Script {@code num2bin} encoding: little-endian sign-and-magnitude
     * with the sign bit landing on the MSB of the padded output (not on the
     * last magnitude byte before padding).
     *
     * <p>Note: the Go and Python reference interpreters cut a corner here and
     * leave the sign bit on the last magnitude byte; that produces a wrong
     * round-trip for negative numbers ({@code bin2num(num2bin(-7, 8))} ends
     * up as 135). Java honours the spec because the on-chain VM does too.
     */
    static String num2binHex(BigInteger n, int byteLen) {
        if (n.signum() == 0) return repeatHex("00", byteLen);
        boolean negative = n.signum() < 0;
        BigInteger abs = n.abs();
        List<Integer> bytes = new ArrayList<>();
        while (abs.signum() > 0) {
            bytes.add(abs.and(BigInteger.valueOf(0xff)).intValueExact());
            abs = abs.shiftRight(8);
        }
        // If the highest magnitude byte has bit 7 set, push another zero byte
        // up so the sign bit (set below) doesn't collide with magnitude data.
        if (!bytes.isEmpty() && (bytes.get(bytes.size() - 1) & 0x80) != 0) {
            bytes.add(0x00);
        }
        while (bytes.size() < byteLen) bytes.add(0);
        if (bytes.size() > byteLen) bytes = bytes.subList(0, byteLen);

        if (negative) {
            int last = bytes.size() - 1;
            bytes.set(last, bytes.get(last) | 0x80);
        }

        StringBuilder sb = new StringBuilder(byteLen * 2);
        for (int b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** Bitcoin Script {@code bin2num} decoding: little-endian sign-and-magnitude. */
    static BigInteger bin2numBigInt(String h) {
        if (h == null || h.isEmpty()) return BigInteger.ZERO;
        byte[] bytes = HEX.parseHex(h);
        if (bytes.length == 0) return BigInteger.ZERO;
        boolean negative = (bytes[bytes.length - 1] & 0x80) != 0;
        if (negative) bytes[bytes.length - 1] = (byte) (bytes[bytes.length - 1] & 0x7f);
        BigInteger result = BigInteger.ZERO;
        for (int i = bytes.length - 1; i >= 0; i--) {
            result = result.shiftLeft(8).or(BigInteger.valueOf(bytes[i] & 0xff));
        }
        return negative ? result.negate() : result;
    }

    private static String repeatHex(String chunk, int count) {
        StringBuilder sb = new StringBuilder(chunk.length() * count);
        for (int i = 0; i < count; i++) sb.append(chunk);
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Real ECDSA / preimage verification (executeOnChainAuthoritative)
    // ------------------------------------------------------------------

    /** Coerce {@code arg} to a byte array. Hex string or raw byte[] accepted. */
    private static byte[] toBytes(Object v) {
        if (v == null) return null;
        if (v instanceof byte[] b) return b;
        if (v instanceof String s) {
            try { return HEX.parseHex(s); }
            catch (IllegalArgumentException e) { return null; }
        }
        return null;
    }

    /**
     * Verify an ECDSA signature against a 32-byte digest using BouncyCastle
     * (same secp256k1 curve as {@link LocalSigner}). Pubkey is SEC1
     * (compressed 33 bytes or uncompressed 65 bytes); signature is DER with
     * an optional trailing sighash type byte stripped. Returns false on any
     * decode error so the enclosing assert fires.
     */
    static boolean verifyEcdsaReal(Object sigVal, Object pkVal, byte[] sighash) {
        byte[] sigBytes = toBytes(sigVal);
        byte[] pkBytes  = toBytes(pkVal);
        if (sigBytes == null || pkBytes == null || sighash == null || sighash.length != 32) {
            return false;
        }
        // Strip trailing sighash type byte from a DER+hashtype blob.
        byte[] der = sigBytes;
        if (der.length >= 2 && (der[0] & 0xff) == 0x30) {
            int declared = (der[1] & 0xff) + 2;
            if (der.length == declared + 1) {
                der = Arrays.copyOf(der, declared);
            }
        }
        try {
            ECPoint q = LocalSigner.DOMAIN.getCurve().decodePoint(pkBytes);
            ECPublicKeyParameters params = new ECPublicKeyParameters(q, LocalSigner.DOMAIN);
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, params);
            ASN1Sequence seq = ASN1Sequence.getInstance(der);
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            return signer.verifySignature(sighash, r, s);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verify a list of signatures against a list of pubkeys. Mirrors
     * Bitcoin's {@code OP_CHECKMULTISIG}: iterate sigs left-to-right,
     * consume pubkeys greedily.
     */
    @SuppressWarnings("unchecked")
    static boolean verifyMultiSigReal(Object sigsVal, Object pksVal, byte[] sighash) {
        if (!(sigsVal instanceof List<?> rawSigs) || !(pksVal instanceof List<?> rawPks)) {
            return false;
        }
        List<Object> sigs = (List<Object>) rawSigs;
        List<Object> pks  = (List<Object>) rawPks;
        if (sigs.size() > pks.size()) return false;
        int pkIdx = 0;
        for (Object sig : sigs) {
            boolean matched = false;
            while (pkIdx < pks.size()) {
                boolean ok = verifyEcdsaReal(sig, pks.get(pkIdx), sighash);
                pkIdx++;
                if (ok) { matched = true; break; }
            }
            if (!matched) return false;
        }
        return true;
    }

    /**
     * Verify that {@code SHA256(SHA256(preimage)) == sighash} — the on-chain
     * {@code OP_PUSH_TX} semantic for {@code checkPreimage}.
     */
    static boolean verifyPreimageReal(Object preimageVal, byte[] sighash) {
        byte[] preBytes = toBytes(preimageVal);
        if (preBytes == null || sighash == null || sighash.length != 32) return false;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] first = md.digest(preBytes);
            md.reset();
            byte[] second = md.digest(first);
            return Arrays.equals(second, sighash);
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Coercion helpers
    // ------------------------------------------------------------------

    static BigInteger toBigInt(Object v) {
        if (v == null) return BigInteger.ZERO;
        if (v instanceof BigInteger bi) return bi;
        if (v instanceof Long l) return BigInteger.valueOf(l);
        if (v instanceof Integer i) return BigInteger.valueOf(i);
        if (v instanceof Double d) return BigInteger.valueOf(d.longValue());
        if (v instanceof Boolean b) return b ? BigInteger.ONE : BigInteger.ZERO;
        if (v instanceof String s) {
            String trimmed = s;
            if (!trimmed.isEmpty() && trimmed.charAt(trimmed.length() - 1) == 'n') {
                trimmed = trimmed.substring(0, trimmed.length() - 1);
            }
            try {
                return new BigInteger(trimmed);
            } catch (NumberFormatException nfe) {
                return BigInteger.ZERO;
            }
        }
        return BigInteger.ZERO;
    }

    static boolean isTruthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean b) return b;
        if (v instanceof BigInteger bi) return bi.signum() != 0;
        if (v instanceof Long l) return l != 0;
        if (v instanceof Integer i) return i != 0;
        if (v instanceof Double d) return d != 0.0;
        if (v instanceof String s) return !s.isEmpty() && !"0".equals(s) && !"false".equals(s);
        return false;
    }

    static String asString(Object v) {
        if (v == null) return "";
        if (v instanceof String s) return s;
        return v.toString();
    }

    /** Heuristic: even-length hex string that isn't a numeric literal. */
    static boolean isHexString(Object v) {
        if (!(v instanceof String s) || s.isEmpty() || s.length() % 2 != 0) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok) return false;
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object o) {
        if (o == null) return Map.of();
        if (o instanceof Map<?, ?> m) return (Map<String, Object>) m;
        throw new InterpreterException("AnfInterpreter: expected object, got " + o.getClass().getSimpleName());
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> listOfObjects(Object o) {
        if (o == null) return List.of();
        if (!(o instanceof List<?> raw)) {
            throw new InterpreterException("AnfInterpreter: expected array, got " + o.getClass().getSimpleName());
        }
        List<Map<String, Object>> out = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (item instanceof Map<?, ?> m) out.add((Map<String, Object>) m);
        }
        return out;
    }

    private static List<String> stringList(Object o) {
        if (!(o instanceof List<?> raw)) return List.of();
        List<String> out = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (item instanceof String s) out.add(s);
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Convenience: load ANF from a JSON artifact string
    // ------------------------------------------------------------------

    /**
     * Extract the {@code anf} sub-tree from a compiled artifact JSON
     * string. Accepts either a bare artifact, a wrapper that embeds the
     * {@code anf} alongside an {@code artifact} field, or a wrapper
     * with {@code artifact.anf}.
     *
     * <p>Returns {@code null} if no ANF tree is present.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> loadAnf(String json) {
        Object tree = Json.parse(json);
        Map<String, Object> root = Json.asObject(tree);
        if (root.containsKey("anf") && root.get("anf") instanceof Map) {
            return (Map<String, Object>) root.get("anf");
        }
        if (root.containsKey("artifact") && root.get("artifact") instanceof Map) {
            Map<String, Object> art = (Map<String, Object>) root.get("artifact");
            if (art.containsKey("anf") && art.get("anf") instanceof Map) {
                return (Map<String, Object>) art.get("anf");
            }
        }
        return null;
    }
}
