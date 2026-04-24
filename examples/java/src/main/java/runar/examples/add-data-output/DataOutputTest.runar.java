package runar.examples.adddataoutput;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

/**
 * DataOutputTest -- exercises {@code addDataOutput} alongside the state
 * continuation.
 *
 * <p>A data output emits an arbitrary-script output that IS included in
 * the compiler-generated continuation hash, in declaration order,
 * between state outputs and the change output. Unlike
 * {@code addRawOutput}, the script contents are committed to by the
 * continuation so spenders cannot swap them out.
 *
 * <p>Ports {@code examples/python/add-data-output/DataOutputTest.runar.py}.
 */
class DataOutputTest extends StatefulSmartContract {

    Bigint count;

    DataOutputTest(Bigint count) {
        super(count);
        this.count = count;
    }

    /**
     * Increment the counter and attach an arbitrary data output whose
     * bytes are committed to by the state continuation hash.
     */
    @Public
    void bump(ByteString payload) {
        this.count = this.count.plus(Bigint.ONE);
        this.addDataOutput(0L, payload);
    }
}
