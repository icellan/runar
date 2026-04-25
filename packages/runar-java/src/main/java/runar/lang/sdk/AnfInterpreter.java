package runar.lang.sdk;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    private static final Set<String> CHAIN_ONLY_KINDS = Set.of(
        "check_preimage", "deserialize_state", "get_state_script",
        "add_raw_output"
    );

    private AnfInterpreter() {}

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
        return run(anf, methodName, currentState, args, constructorArgs, false).newState;
    }

    /** Result bundle returned from a strict execution. */
    public static final class ExecutionResult {
        public final Map<String, Object> newState;
        public final List<DataOutput> dataOutputs;

        ExecutionResult(Map<String, Object> newState, List<DataOutput> dataOutputs) {
            this.newState = Collections.unmodifiableMap(newState);
            this.dataOutputs = Collections.unmodifiableList(dataOutputs);
        }
    }

    /**
     * A single output recorded from {@code this.addDataOutput(...)} during
     * interpretation. {@code script} is hex-encoded; {@code satoshis} is
     * the declared amount.
     */
    public record DataOutput(long satoshis, String script) {}

    /**
     * Run the method body in strict mode: every {@code assert} binding's
     * condition is evaluated and the call throws
     * {@link AssertionFailureException} on failure.
     *
     * <p>Crypto primitives available locally (SHA-256, RIPEMD-160,
     * hash160, hash256, ECDSA via mock) are real. Others
     * (BN254/Poseidon2/SLH-DSA/WOTS/sha256Compress) bubble up the
     * {@link UnsupportedOperationException} from {@link MockCrypto}.
     */
    public static ExecutionResult executeStrict(
        Map<String, Object> anf,
        String methodName,
        Map<String, Object> currentState,
        Map<String, Object> args,
        List<Object> constructorArgs
    ) {
        Run r = run(anf, methodName, currentState, args, constructorArgs, true);
        return new ExecutionResult(r.newState, r.dataOutputs);
    }

    /** Thrown when an {@code assert} binding's condition is falsy in strict mode. */
    public static final class AssertionFailureException extends RuntimeException {
        public AssertionFailureException(String message) {
            super(message);
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
        Run(Map<String, Object> s, List<DataOutput> o) { this.newState = s; this.dataOutputs = o; }
    }

    @SuppressWarnings("unchecked")
    private static Run run(
        Map<String, Object> anf,
        String methodName,
        Map<String, Object> currentState,
        Map<String, Object> args,
        List<Object> constructorArgs,
        boolean strict
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
        List<Map<String, Object>> params = listOfObjects(method.get("params"));
        for (Map<String, Object> param : params) {
            String pname = (String) param.get("name");
            if (IMPLICIT_PARAMS.contains(pname)) continue;
            if (args.containsKey(pname)) {
                env.put(pname, args.get(pname));
            }
        }

        Map<String, Object> stateDelta = new LinkedHashMap<>();
        List<DataOutput> dataOutputs = new ArrayList<>();

        evalBindings(anf, listOfObjects(method.get("body")), env, stateDelta, dataOutputs, strict);

        Map<String, Object> newState = new LinkedHashMap<>();
        newState.putAll(currentState);
        newState.putAll(stateDelta);
        return new Run(newState, dataOutputs);
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
        boolean strict
    ) {
        for (Map<String, Object> binding : bindings) {
            Object val = evalValue(anf, asObject(binding.get("value")), env, stateDelta, dataOutputs, strict);
            env.put((String) binding.get("name"), val);
        }
    }

    private static Object evalValue(
        Map<String, Object> anf,
        Map<String, Object> value,
        Map<String, Object> env,
        Map<String, Object> stateDelta,
        List<DataOutput> dataOutputs,
        boolean strict
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
                    return env.get(s.substring(5));
                }
                return v;
            }
            case "bin_op": {
                String op = (String) value.get("op");
                Object left = env.get((String) value.get("left"));
                Object right = env.get((String) value.get("right"));
                String resultType = (String) value.get("result_type");
                return evalBinOp(op, left, right, resultType);
            }
            case "unary_op": {
                String op = (String) value.get("op");
                Object operand = env.get((String) value.get("operand"));
                String resultType = (String) value.get("result_type");
                return evalUnaryOp(op, operand, resultType);
            }
            case "call": {
                String func = (String) value.get("func");
                List<String> argNames = stringList(value.get("args"));
                List<Object> argVals = new ArrayList<>(argNames.size());
                for (String n : argNames) argVals.add(env.get(n));
                return evalCall(func, argVals);
            }
            case "method_call": {
                String mname = (String) value.get("method");
                List<String> argNames = stringList(value.get("args"));
                List<Object> argVals = new ArrayList<>(argNames.size());
                for (String n : argNames) argVals.add(env.get(n));
                return evalMethodCall(anf, mname, argVals, env, stateDelta, dataOutputs, strict);
            }
            case "if": {
                Object cond = env.get((String) value.get("cond"));
                List<Map<String, Object>> branch = isTruthy(cond)
                    ? listOfObjects(value.get("then"))
                    : listOfObjects(value.get("else"));
                Map<String, Object> childEnv = new LinkedHashMap<>(env);
                evalBindings(anf, branch, childEnv, stateDelta, dataOutputs, strict);
                env.putAll(childEnv);
                if (!branch.isEmpty()) {
                    return childEnv.get((String) branch.get(branch.size() - 1).get("name"));
                }
                return null;
            }
            case "loop": {
                long count = toBigInt(value.get("count")).longValueExact();
                String iterVar = (String) value.getOrDefault("iterVar", "");
                List<Map<String, Object>> body = listOfObjects(value.get("body"));
                Object lastVal = null;
                for (long i = 0; i < count; i++) {
                    env.put(iterVar, BigInteger.valueOf(i));
                    Map<String, Object> loopEnv = new LinkedHashMap<>(env);
                    evalBindings(anf, body, loopEnv, stateDelta, dataOutputs, strict);
                    env.putAll(loopEnv);
                    if (!body.isEmpty()) {
                        lastVal = loopEnv.get((String) body.get(body.size() - 1).get("name"));
                    }
                }
                return lastVal;
            }
            case "assert": {
                if (strict) {
                    Object cond = env.get((String) value.get("value"));
                    if (!isTruthy(cond)) {
                        throw new AssertionFailureException(
                            "AnfInterpreter: assert failed on '" + value.get("value")
                                + "' (cond=" + cond + ")"
                        );
                    }
                }
                return null;
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
        boolean strict
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
                evalBindings(anf, body, callEnv, childDelta, dataOutputs, strict);
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
            case "&":  return l.and(r);
            case "|":  return l.or(r);
            case "^":  return l.xor(r);
            case "<<": return l.shiftLeft(r.intValueExact());
            case ">>": return l.shiftRight(r.intValueExact());
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
            case "~":  return v.not();
            default:   return v;
        }
    }

    // ------------------------------------------------------------------
    // Built-in calls
    // ------------------------------------------------------------------

    private static Object evalCall(String func, List<Object> args) {
        switch (func) {
            // Mocked crypto
            case "checkSig":
            case "checkMultiSig":
            case "checkPreimage":
                return Boolean.TRUE;

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

            // Preimage extractors that aren't backed by a real preimage in
            // the simulator return zero-bytes so dependent computations
            // continue without crashing. Real values are only meaningful
            // inside the on-chain VM.
            case "extractOutputHash":
            case "extractAmount":
                return repeatHex("00", 32);

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
