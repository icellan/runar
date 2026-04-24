package runar.examples.addrawoutput;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

/**
 * RawOutputTest -- exercises {@code addRawOutput} alongside
 * {@code addOutput} for stateful contracts.
 *
 * <p>{@code addRawOutput} creates an output with caller-specified script
 * bytes instead of the contract's own codePart. Unlike
 * {@code addDataOutput}, the raw script is NOT committed to by the
 * continuation hash -- spenders could swap it out on-chain if they
 * wanted. Useful for paymail fallbacks and miner-configurable outputs.
 *
 * <p>Ports {@code examples/go/add-raw-output/RawOutputTest.runar.go}.
 */
class RawOutputTest extends StatefulSmartContract {

    Bigint count;

    RawOutputTest(Bigint count) {
        super(count);
        this.count = count;
    }

    /**
     * Emit a raw output with arbitrary script bytes, then increment the
     * counter and emit the state continuation.
     */
    @Public
    void sendToScript(ByteString scriptBytes) {
        this.addRawOutput(1000L, scriptBytes);
        this.count = this.count.plus(Bigint.ONE);
        this.addOutput(0L, this.count);
    }
}
