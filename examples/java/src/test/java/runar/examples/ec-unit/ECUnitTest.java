package runar.examples.ecunit;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface + simulator tests for ECUnit. Exercises the per-primitive
 * smoke check via the off-chain simulator.
 */
class ECUnitTest {

    private static final ByteString PUB_KEY = ByteString.fromHex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );

    @Test
    void contractInstantiates() {
        ECUnit c = new ECUnit(PUB_KEY);
        assertNotNull(c);
    }

    @Test
    void testOpsSucceeds() {
        ECUnit c = new ECUnit(PUB_KEY);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("testOps");
    }
}
