package runar.lang.runtime;

/**
 * Thread-local switch that gates whether {@link runar.lang.Builtins}
 * delegates to the off-chain {@link MockCrypto} simulator implementations
 * or falls back to throwing {@code UnsupportedOperationException}.
 *
 * <p>The contract surface classes in {@code runar.lang.*} are consumed
 * primarily by the Rúnar compiler as AST extraction targets, not as a
 * runtime framework. Outside of the simulator, calling a builtin like
 * {@code hash160(pubKey)} in plain Java is a programming error — the
 * real execution happens on the Bitcoin Script VM. The simulator
 * milestone (M11) provides a JVM-native execution harness purely for
 * unit testing; entering the simulator flips this flag for the duration
 * of the call so the Builtins static methods do something useful.
 *
 * <p>This class is intentionally package-adjacent with {@link MockCrypto}
 * so the {@code runar.lang.Builtins} public API can remain a thin
 * dispatcher without dragging mock-specific types into its signature.
 */
public final class SimulatorContext {

    private static final ThreadLocal<Boolean> ACTIVE = ThreadLocal.withInitial(() -> Boolean.FALSE);

    private SimulatorContext() {}

    /** Returns true if the current thread is inside a simulator call. */
    public static boolean isActive() {
        return ACTIVE.get();
    }

    /**
     * Activates simulator mode for the current thread. Paired with
     * {@link #exit()} in a try/finally, typically by
     * {@link ContractSimulator}. Nested enters are supported via a
     * depth counter kept on the thread-local.
     */
    public static void enter() {
        DEPTH.set(DEPTH.get() + 1);
        ACTIVE.set(Boolean.TRUE);
    }

    /** Exits simulator mode for the current thread. */
    public static void exit() {
        int d = DEPTH.get() - 1;
        if (d <= 0) {
            DEPTH.set(0);
            ACTIVE.set(Boolean.FALSE);
        } else {
            DEPTH.set(d);
        }
    }

    private static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);

    // -----------------------------------------------------------------
    // Preimage propagation — lets StatefulSmartContract.currentPreimage()
    // read whatever the active ContractSimulator.callStateful threaded
    // through as the spending-transaction preimage.
    // -----------------------------------------------------------------

    private static final ThreadLocal<Preimage> PREIMAGE = new ThreadLocal<>();

    /** Set by {@link ContractSimulator} before invoking a stateful method. */
    public static void setCurrentPreimage(Preimage p) { PREIMAGE.set(p); }

    /** Cleared by {@link ContractSimulator} after the method returns. */
    public static void clearCurrentPreimage() { PREIMAGE.remove(); }

    /** Accessor used by {@link runar.lang.StatefulSmartContract#currentPreimage()}. */
    public static Preimage currentPreimage() { return PREIMAGE.get(); }
}
