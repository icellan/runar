package runar.lang;

import java.math.BigInteger;

import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.SimulatorContext;
import runar.lang.types.Bigint;

/**
 * Base class for stateless Rúnar contracts. All fields of a subclass
 * are implicitly readonly; the compiler rejects mutation in method
 * bodies.
 *
 * <p>Outside the simulator the {@code addOutput} / {@code addRawOutput}
 * methods throw, since actual output emission happens on-chain. Inside
 * the simulator (see {@link runar.lang.runtime.ContractSimulator}) they
 * route to the simulator's output capture, letting tests inspect what
 * the contract emitted across a method invocation.
 */
public abstract class SmartContract {

    protected SmartContract(Object... constructorArgs) {
        // The compiler replaces super(...) with a no-op AST binding.
        // Kept as a harmless constructor hook for test-time simulation.
    }

    /**
     * Add an output to the current spending transaction. Positional
     * values must match the mutable properties of the contract in
     * declaration order (stateful) or be absent (stateless).
     */
    protected final void addOutput(BigInteger satoshis, Object... values) {
        if (!SimulatorContext.isActive()) {
            throw new UnsupportedOperationException(
                "addOutput is a compile-time intrinsic; invoke via the off-chain simulator"
            );
        }
        ContractSimulator.captureOutput(satoshis, values);
    }

    /** Ergonomic {@code Bigint}-accepting overload that routes to {@link #addOutput(BigInteger, Object...)}. */
    protected final void addOutput(Bigint satoshis, Object... values) {
        addOutput(satoshis.value(), values);
    }

    /** Ergonomic {@code long}-accepting overload that routes to {@link #addOutput(BigInteger, Object...)}. */
    protected final void addOutput(long satoshis, Object... values) {
        addOutput(BigInteger.valueOf(satoshis), values);
    }

    /**
     * Add a raw output with caller-specified script bytes instead of
     * the contract's own codePart.
     */
    protected final void addRawOutput(BigInteger satoshis, byte[] scriptBytes) {
        if (!SimulatorContext.isActive()) {
            throw new UnsupportedOperationException(
                "addRawOutput is a compile-time intrinsic; invoke via the off-chain simulator"
            );
        }
        ContractSimulator.captureRawOutput(satoshis, scriptBytes);
    }

    /** Ergonomic {@code long}-accepting overload for {@link #addRawOutput(BigInteger, byte[])}. */
    protected final void addRawOutput(long satoshis, byte[] scriptBytes) {
        addRawOutput(BigInteger.valueOf(satoshis), scriptBytes);
    }

    /** Ergonomic overload accepting the script bytes as a Rúnar {@link runar.lang.types.ByteString}. */
    protected final void addRawOutput(BigInteger satoshis, runar.lang.types.ByteString scriptBytes) {
        addRawOutput(satoshis, scriptBytes.toByteArray());
    }

    /** Ergonomic {@code long} + {@link runar.lang.types.ByteString} overload. */
    protected final void addRawOutput(long satoshis, runar.lang.types.ByteString scriptBytes) {
        addRawOutput(BigInteger.valueOf(satoshis), scriptBytes.toByteArray());
    }

    /**
     * Add a data output -- an arbitrary-script output committed to by the
     * compiler-generated continuation hash. Unlike {@link #addRawOutput}
     * data outputs are tied to the state continuation, so spenders cannot
     * swap them out. Mirrors the TypeScript / Go / Python SDK shapes.
     */
    protected final void addDataOutput(BigInteger satoshis, runar.lang.types.ByteString scriptBytes) {
        if (!SimulatorContext.isActive()) {
            throw new UnsupportedOperationException(
                "addDataOutput is a compile-time intrinsic; invoke via the off-chain simulator"
            );
        }
        ContractSimulator.captureDataOutput(satoshis, scriptBytes.toByteArray());
    }

    /** Ergonomic {@code long}-accepting overload for {@link #addDataOutput(BigInteger, runar.lang.types.ByteString)}. */
    protected final void addDataOutput(long satoshis, runar.lang.types.ByteString scriptBytes) {
        addDataOutput(BigInteger.valueOf(satoshis), scriptBytes);
    }
}
