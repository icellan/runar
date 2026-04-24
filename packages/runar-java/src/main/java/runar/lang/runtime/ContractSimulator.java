package runar.lang.runtime;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import runar.lang.SmartContract;
import runar.lang.StatefulSmartContract;

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
 * multiple method calls.
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
    private final List<Output> outputs = new ArrayList<>();
    private Preimage lastPreimage;

    private ContractSimulator(SmartContract contract, boolean stateful) {
        this.contract = contract;
        this.stateful = stateful;
    }

    public static ContractSimulator stateless(SmartContract contract) {
        if (contract instanceof StatefulSmartContract) {
            throw new IllegalArgumentException("use ContractSimulator.stateful for stateful contracts");
        }
        return new ContractSimulator(contract, false);
    }

    public static ContractSimulator stateful(StatefulSmartContract contract) {
        return new ContractSimulator(contract, true);
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
        Method target = findMethod(methodName, args);
        OutputCapture.push(outputs);
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
     */
    public Object callStateful(String methodName, Preimage preimage, Object... args) {
        if (!stateful) throw new IllegalStateException("contract is not stateful");
        this.lastPreimage = preimage;
        SimulatorContext.setCurrentPreimage(preimage);
        try {
            return call(methodName, args);
        } finally {
            SimulatorContext.clearCurrentPreimage();
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
