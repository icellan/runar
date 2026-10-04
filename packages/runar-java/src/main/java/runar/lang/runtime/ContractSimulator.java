package runar.lang.runtime;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import runar.lang.Builtins;
import runar.lang.SmartContract;
import runar.lang.StatefulSmartContract;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.SimulatedSpend;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.RabinPubKey;
import runar.lang.types.RabinSig;

/**
 * Off-chain simulator harness for exercising a Rúnar contract from
 * plain JUnit tests. The simulator activates
 * {@link SimulatorContext} for the duration of each {@code call(...)}
 * so the static builtins in {@code runar.lang.Builtins} delegate to the
 * real {@link MockCrypto} implementations rather than throwing.
 *
 * <p>For stateful contracts, the simulator threads {@link Preimage}
 * inputs and captures {@code addOutput(...)} invocations so tests can
 * inspect emitted outputs and round-trip state transitions across
 * multiple method calls. {@link #callStateful} does not trust the supplied
 * preimage: it builds the spending transaction the call really produces
 * (from the contract's compiled artifact, its pre-call state and the
 * outputs the method emitted) and fails unless the preimage is that
 * transaction's BIP-143 preimage. {@link #preimageFor} builds one.
 *
 * <p>Usage:
 * <pre>
 * var sim = ContractSimulator.stateless(new P2PKH(hash));
 * sim.call("unlock", sig, pubKey);            // asserts on success
 * sim.expectFailure("unlock", badSig, pubKey);
 * </pre>
 */
public final class ContractSimulator {

    private final SmartContract contract;
    private final boolean stateful;
    private final RunarArtifact artifact;
    private final List<Output> outputs = new ArrayList<>();
    private Preimage lastPreimage;

    private ContractSimulator(SmartContract contract, boolean stateful, RunarArtifact artifact) {
        this.contract = contract;
        this.stateful = stateful;
        this.artifact = artifact;
    }

    public static ContractSimulator stateless(SmartContract contract) {
        if (contract instanceof StatefulSmartContract) {
            throw new IllegalArgumentException("use ContractSimulator.stateful for stateful contracts");
        }
        return new ContractSimulator(contract, false, null);
    }

    /**
     * Stateful simulator without a compiled artifact. {@link #call} works;
     * {@link #callStateful} refuses, because it cannot build the spending
     * transaction a preimage must match.
     */
    public static ContractSimulator stateful(StatefulSmartContract contract) {
        return new ContractSimulator(contract, true, null);
    }

    /** Stateful simulator whose {@link #callStateful} checks preimages against {@code artifact}. */
    public static ContractSimulator stateful(StatefulSmartContract contract, RunarArtifact artifact) {
        if (artifact == null) throw new IllegalArgumentException("artifact is null");
        return new ContractSimulator(contract, true, artifact);
    }

    /** As {@link #stateful(StatefulSmartContract, RunarArtifact)}, compiling {@code source} first. */
    public static ContractSimulator stateful(StatefulSmartContract contract, Path source) {
        try {
            return stateful(contract, SimulatedSpend.compile(source));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public SmartContract contract() { return contract; }

    public List<Output> outputs() { return List.copyOf(outputs); }

    public Preimage lastPreimage() { return lastPreimage; }

    /**
     * Invoke a contract method by name. Arguments must match the method's
     * declared parameter types. Throws {@link AssertionError} with the
     * usual JVM semantics when an {@code assertThat} inside the contract
     * fails; propagates the original exception otherwise.
     */
    public Object call(String methodName, Object... args) {
        return invokeInto(outputs, methodName, args);
    }

    private Object invokeInto(List<Output> sink, String methodName, Object[] args) {
        Method target = findMethod(methodName, args);
        OutputCapture.push(sink);
        SimulatorContext.enter();
        try {
            return target.invoke(contract, args);
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            if (cause instanceof AssertionError ae) throw ae;
            if (cause instanceof RuntimeException re) throw re;
            throw new RuntimeException(cause);
        } catch (IllegalAccessException iae) {
            throw new RuntimeException("cannot invoke " + methodName + " on " + contract.getClass().getName(), iae);
        } finally {
            SimulatorContext.exit();
            OutputCapture.pop();
        }
    }

    /**
     * Call a stateful method with an injected preimage. The preimage is
     * stashed on the simulator; tests can read it back via
     * {@link #lastPreimage()}. Inside the call, contract code can access
     * the preimage via {@code this.currentPreimage()} (defined on
     * {@link runar.lang.StatefulSmartContract}).
     *
     * <p>F-129: this is the off-chain {@code checkPreimage}. The simulator
     * builds the one-input spending transaction the call produces (input 0
     * spends the contract's current locking script at the preimage's
     * outpoint / amount / nSequence, under its version / nLockTime / sighash
     * type; the outputs are the continuation the method really emitted) and
     * throws {@link AssertionError} unless {@code preimage} is exactly that
     * transaction's BIP-143 preimage. The input side (hashPrevouts,
     * hashSequence, scriptCode) is checked before the body runs, hashOutputs
     * after it, once the outputs are known. A terminal method (no
     * continuation) leaves its outputs to the spender, so its hashOutputs is
     * taken as supplied. Change outputs are not modelled (a change-free call).
     */
    public Object callStateful(String methodName, Preimage preimage, Object... args) {
        Spend spend = beginSpend(methodName, preimage);
        requireMatches(spend.honest(preimage, null), preimage);
        this.lastPreimage = preimage;
        int mark = outputs.size();
        SimulatorContext.setCurrentPreimage(preimage);
        Object result;
        try {
            result = call(methodName, args);
        } finally {
            SimulatorContext.clearCurrentPreimage();
        }
        List<Output> produced = new ArrayList<>(outputs.subList(mark, outputs.size()));
        requireMatches(spend.honest(preimage, spend.outputsOf(produced)), preimage);
        return result;
    }

    /**
     * The honest preimage for {@code callStateful(methodName, ..., args)}:
     * {@code template}'s spender-chosen fields (version, outpoint, amount,
     * nSequence, nLockTime, sighash type) with hashPrevouts, hashSequence,
     * scriptCode and hashOutputs computed from the spending transaction.
     * The method is dry-run to learn its outputs; every contract field is
     * restored afterwards and nothing is added to {@link #outputs()}. If the
     * dry run fails a contract assertion the call has no continuation to
     * commit to: the input side is still honest and hashOutputs is
     * {@code template}'s, so the real call fails on that same assertion.
     */
    public Preimage preimageFor(String methodName, Preimage template, Object... args) {
        Spend spend = beginSpend(methodName, template);
        Preimage inputSide = spend.honest(template, null);
        Map<Field, Object> snapshot = snapshotFields();
        List<Output> sink = new ArrayList<>();
        SimulatorContext.setCurrentPreimage(inputSide);
        try {
            invokeInto(sink, methodName, args);
            return spend.honest(template, spend.outputsOf(sink));
        } catch (AssertionError ae) {
            return inputSide;
        } finally {
            SimulatorContext.clearCurrentPreimage();
            restoreFields(snapshot);
        }
    }

    /**
     * Expect the given method call to fail with an {@link AssertionError}.
     * Returns normally if the contract's internal assert failed; throws
     * otherwise.
     */
    public AssertionError expectFailure(String methodName, Object... args) {
        try {
            call(methodName, args);
        } catch (AssertionError ae) {
            return ae;
        }
        throw new AssertionError("expected contract method '" + methodName + "' to fail but it succeeded");
    }

    // -----------------------------------------------------------------
    // F-129: the spending transaction behind callStateful's preimage.
    // -----------------------------------------------------------------

    private Spend beginSpend(String methodName, Preimage template) {
        if (!stateful) throw new IllegalStateException("contract is not stateful");
        if (template == null) throw new IllegalArgumentException("preimage is null");
        if (artifact == null) {
            throw new IllegalStateException(
                "callStateful checks the preimage against the spending transaction, which needs the "
                    + "contract's compiled artifact: use ContractSimulator.stateful(contract, artifact) "
                    + "or ContractSimulator.stateful(contract, sourcePath)");
        }
        RunarArtifact.ABIMethod abi = null;
        for (RunarArtifact.ABIMethod m : artifact.abi().methods()) {
            if (m.isPublic() && m.name().equals(methodName)) { abi = m; break; }
        }
        if (abi == null) {
            throw new IllegalArgumentException("no public method '" + methodName + "' in artifact "
                + artifact.contractName());
        }
        List<Object> ctorArgs = new ArrayList<>();
        for (RunarArtifact.ABIParam p : artifact.abi().constructor().params()) {
            ctorArgs.add(sdkValue(readField(p.name()), p.name()));
        }
        String lockingScript = SimulatedSpend.lockingScript(artifact, ctorArgs, currentState());
        return new Spend(abi, ctorArgs, lockingScript);
    }

    private final class Spend {
        final RunarArtifact.ABIMethod abi;
        final List<Object> ctorArgs;
        final String lockingScript;

        Spend(RunarArtifact.ABIMethod abi, List<Object> ctorArgs, String lockingScript) {
            this.abi = abi;
            this.ctorArgs = ctorArgs;
            this.lockingScript = lockingScript;
        }

        private boolean hasParam(String name) {
            for (RunarArtifact.ABIParam p : abi.params()) if (p.name().equals(name)) return true;
            return false;
        }

        /**
         * The outputs the compiler's continuation commits to, in its order:
         * state / raw outputs in source order, then data outputs (no change).
         * {@code null} for a terminal method, whose outputs the spender picks.
         */
        List<SimulatedSpend.Out> outputsOf(List<Output> produced) {
            List<SimulatedSpend.Out> outs = new ArrayList<>();
            if (hasParam("_newAmount")) {
                // Single-output continuation: the post-call state at _newAmount,
                // which off-chain is continuationAmount().
                outs.add(new SimulatedSpend.Out(Builtins.continuationAmount().longValueExact(),
                    SimulatedSpend.continuationScript(artifact, lockingScript, currentState())));
            } else if (hasParam("_changePKH")) {
                List<String> names = SimulatedSpend.stateFieldNamesInOrder(artifact);
                for (Output o : produced) {
                    if (o.isData()) continue;
                    if (o.isRaw()) {
                        outs.add(new SimulatedSpend.Out(o.satoshis.longValueExact(), hex(o.rawScriptBytes)));
                        continue;
                    }
                    if (o.values.length != names.size()) {
                        throw new IllegalStateException("addOutput passed " + o.values.length
                            + " values for " + names.size() + " state fields");
                    }
                    Map<String, Object> st = new HashMap<>();
                    for (int i = 0; i < names.size(); i++) st.put(names.get(i), sdkValue(o.values[i], names.get(i)));
                    outs.add(new SimulatedSpend.Out(o.satoshis.longValueExact(),
                        SimulatedSpend.continuationScript(artifact, lockingScript, st)));
                }
            } else {
                return null;
            }
            for (Output o : produced) {
                if (o.isData()) outs.add(new SimulatedSpend.Out(o.satoshis.longValueExact(), hex(o.rawScriptBytes)));
            }
            return outs;
        }

        /**
         * The preimage of the spending transaction with {@code template}'s
         * spender-chosen fields. {@code outs == null}: hashOutputs is taken
         * from {@code template} (outputs not known, or not contract-bound).
         */
        Preimage honest(Preimage template, List<SimulatedSpend.Out> outs) {
            byte[] op = template.outpoint();
            byte[] txidBe = new byte[32];
            for (int i = 0; i < 32; i++) txidBe[i] = op[31 - i];
            int vout = (op[32] & 0xff) | (op[33] & 0xff) << 8 | (op[34] & 0xff) << 16 | (op[35] & 0xff) << 24;
            byte[] bytes = SimulatedSpend.preimage(
                artifact, abi.name(), ctorArgs, lockingScript,
                outs == null ? List.of() : outs,
                (int) template.version(), hex(txidBe), vout, template.amount().longValueExact(),
                template.sequence(), (int) template.locktime(), (int) template.sighashType());
            if (outs == null) {
                // hashOutputs sits just before the trailing nLockTime and sighash type.
                System.arraycopy(template.hashOutputs(), 0, bytes, bytes.length - 40, 32);
            }
            return Preimage.parse(bytes);
        }
    }

    private static void requireMatches(Preimage expected, Preimage supplied) {
        if (Arrays.equals(expected.toBytes(), supplied.toBytes())) return;
        List<String> diff = new ArrayList<>();
        if (expected.version() != supplied.version()) diff.add("version");
        if (!Arrays.equals(expected.hashPrevouts(), supplied.hashPrevouts())) diff.add("hashPrevouts");
        if (!Arrays.equals(expected.hashSequence(), supplied.hashSequence())) diff.add("hashSequence");
        if (!Arrays.equals(expected.outpoint(), supplied.outpoint())) diff.add("outpoint");
        if (!expected.scriptCode().equals(supplied.scriptCode())) diff.add("scriptCode");
        if (!expected.amount().equals(supplied.amount())) diff.add("amount");
        if (expected.sequence() != supplied.sequence()) diff.add("nSequence");
        if (!Arrays.equals(expected.hashOutputs(), supplied.hashOutputs())) diff.add("hashOutputs");
        if (expected.locktime() != supplied.locktime()) diff.add("nLockTime");
        if (expected.sighashType() != supplied.sighashType()) diff.add("sighashType");
        throw new AssertionError("checkPreimage failed: the preimage is not the BIP-143 preimage of the "
            + "spending transaction this call produces (" + String.join(", ", diff) + " differ)");
    }

    private Map<String, Object> currentState() {
        Map<String, Object> st = new HashMap<>();
        for (RunarArtifact.StateField f : artifact.stateFields()) {
            st.put(f.name(), sdkValue(readField(f.name()), f.name()));
        }
        return st;
    }

    private Object readField(String name) {
        for (Class<?> c = contract.getClass(); c != null && c != SmartContract.class; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(contract);
            } catch (NoSuchFieldException ignored) {
                // keep walking up
            } catch (IllegalAccessException e) {
                throw new IllegalStateException("cannot read field '" + name + "'", e);
            }
        }
        throw new IllegalStateException("contract " + contract.getClass().getName()
            + " has no field '" + name + "' named by its artifact");
    }

    /** Java contract value to the value shape the SDK's script encoders take. */
    private static Object sdkValue(Object v, String what) {
        if (v instanceof Bigint b) return b.value();
        if (v instanceof BigInteger || v instanceof Boolean) return v;
        if (v instanceof Long || v instanceof Integer) return BigInteger.valueOf(((Number) v).longValue());
        if (v instanceof ByteString bs) return bs.toHex();
        if (v instanceof RabinSig r) return r.value();
        if (v instanceof RabinPubKey r) return r.value();
        throw new IllegalStateException("'" + what + "' has a value the simulator cannot encode: "
            + (v == null ? "null" : v.getClass().getName()));
    }

    private Map<Field, Object> snapshotFields() {
        Map<Field, Object> snap = new LinkedHashMap<>();
        for (Class<?> c = contract.getClass();
             c != null && c != StatefulSmartContract.class && c != SmartContract.class;
             c = c.getSuperclass()) {
            for (Field f : c.getDeclaredFields()) {
                int mod = f.getModifiers();
                if (Modifier.isStatic(mod) || Modifier.isFinal(mod)) continue;
                try {
                    f.setAccessible(true);
                    Object v = f.get(contract);
                    snap.put(f, v instanceof Object[] arr ? arr.clone() : v);
                } catch (IllegalAccessException e) {
                    throw new IllegalStateException("cannot snapshot field '" + f.getName() + "'", e);
                }
            }
        }
        return snap;
    }

    private void restoreFields(Map<Field, Object> snap) {
        for (Map.Entry<Field, Object> e : snap.entrySet()) {
            try {
                e.getKey().set(contract, e.getValue());
            } catch (IllegalAccessException ex) {
                throw new IllegalStateException("cannot restore field '" + e.getKey().getName() + "'", ex);
            }
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    private Method findMethod(String name, Object[] args) {
        Class<?> cls = contract.getClass();
        outer:
        for (Method m : cls.getDeclaredMethods()) {
            if (!m.getName().equals(name)) continue;
            if (m.getParameterCount() != args.length) continue;
            Class<?>[] types = m.getParameterTypes();
            for (int i = 0; i < args.length; i++) {
                if (args[i] != null && !wrap(types[i]).isAssignableFrom(args[i].getClass())) {
                    continue outer;
                }
            }
            m.setAccessible(true);
            return m;
        }
        throw new NoSuchMethodError(name + Arrays.toString(args) + " on " + cls.getName());
    }

    private static Class<?> wrap(Class<?> c) {
        if (!c.isPrimitive()) return c;
        if (c == int.class) return Integer.class;
        if (c == long.class) return Long.class;
        if (c == boolean.class) return Boolean.class;
        if (c == byte.class) return Byte.class;
        if (c == char.class) return Character.class;
        if (c == short.class) return Short.class;
        if (c == float.class) return Float.class;
        if (c == double.class) return Double.class;
        return c;
    }

    // -----------------------------------------------------------------
    // Output capture — thread-local bucket so contract.addOutput(...)
    // can route into the active simulator without passing a sim reference.
    // -----------------------------------------------------------------

    static final class OutputCapture {
        private static final ThreadLocal<ArrayList<List<Output>>> STACK =
            ThreadLocal.withInitial(ArrayList::new);

        static void push(List<Output> sink) { STACK.get().add(sink); }

        static void pop() {
            ArrayList<List<Output>> s = STACK.get();
            if (!s.isEmpty()) s.remove(s.size() - 1);
        }

        /** Package-private: routed from Builtins / SmartContract.addOutput. */
        static void emit(Output out) {
            ArrayList<List<Output>> s = STACK.get();
            if (!s.isEmpty()) s.get(s.size() - 1).add(out);
        }
    }

    /** A captured output emission from {@code this.addOutput(...)}. */
    public static final class Output {
        public enum Kind { STATE, RAW, DATA }

        public final Kind kind;
        public final java.math.BigInteger satoshis;
        public final Object[] values;
        public final byte[] rawScriptBytes; // non-null for RAW / DATA

        Output(Kind kind, java.math.BigInteger satoshis, Object[] values, byte[] rawScriptBytes) {
            this.kind = kind;
            this.satoshis = satoshis;
            this.values = values;
            this.rawScriptBytes = rawScriptBytes;
        }

        public static Output state(java.math.BigInteger satoshis, Object[] values) {
            return new Output(Kind.STATE, satoshis, values, null);
        }

        public static Output raw(java.math.BigInteger satoshis, byte[] script) {
            return new Output(Kind.RAW, satoshis, null, script);
        }

        public static Output data(java.math.BigInteger satoshis, byte[] script) {
            return new Output(Kind.DATA, satoshis, null, script);
        }

        public boolean isRaw() { return kind == Kind.RAW; }
        public boolean isData() { return kind == Kind.DATA; }
        public boolean isState() { return kind == Kind.STATE; }
    }

    /** Package-private accessor for {@link SmartContract#addOutput} delegation. */
    public static void captureOutput(java.math.BigInteger satoshis, Object[] values) {
        OutputCapture.emit(Output.state(satoshis, values));
    }

    public static void captureRawOutput(java.math.BigInteger satoshis, byte[] script) {
        OutputCapture.emit(Output.raw(satoshis, script));
    }

    public static void captureDataOutput(java.math.BigInteger satoshis, byte[] script) {
        OutputCapture.emit(Output.data(satoshis, script));
    }
}
