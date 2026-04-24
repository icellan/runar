package runar.lang;

import java.math.BigInteger;

import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.SimulatorContext;

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
}
