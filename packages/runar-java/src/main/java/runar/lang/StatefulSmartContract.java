package runar.lang;

import runar.lang.runtime.Preimage;
import runar.lang.runtime.SimulatorContext;
import runar.lang.types.SigHashPreimage;

/**
 * Base class for stateful Rúnar contracts. The compiler auto-injects
 * {@code checkPreimage} at method entry and state continuation at exit;
 * mutable fields become the contract's serialized state.
 *
 * <p>Wrap readonly fields in {@code @Readonly} (from
 * {@code runar.lang.annotations}); all unannotated fields are treated
 * as mutable state.
 *
 * <p>Public state-mutating methods may reference {@code this.txPreimage}
 * to inspect the spending transaction's sighash preimage. On-chain the
 * compiler wires it to the opcode-pushed preimage; under the simulator
 * the field resolves to whatever {@link Preimage} was passed into
 * {@link runar.lang.runtime.ContractSimulator#callStateful}, or a
 * zero-initialised default.
 */
public abstract class StatefulSmartContract extends SmartContract {

    /**
     * The sighash preimage of the spending transaction. On-chain this is
     * a compiler-injected stack push; under the simulator it resolves to
     * whatever {@link Preimage} the test supplied.
     */
    protected final SigHashPreimage txPreimage;

    protected StatefulSmartContract(Object... constructorArgs) {
        super(constructorArgs);
        // Under the simulator we populate this lazily from the active
        // Preimage; outside the simulator the compiler intercepts reads
        // and maps them to the on-chain stack push, so this field is
        // effectively a placeholder (zero-length bytes).
        this.txPreimage = new SigHashPreimage(new byte[0]);
    }

    /**
     * Returns the structured preimage object the simulator is threading
     * through the current call, if any. Returns {@code null} when called
     * outside a simulator context or when the current call did not
     * inject a preimage.
     */
    protected final Preimage currentPreimage() {
        if (!SimulatorContext.isActive()) return null;
        return SimulatorContext.currentPreimage();
    }
}
