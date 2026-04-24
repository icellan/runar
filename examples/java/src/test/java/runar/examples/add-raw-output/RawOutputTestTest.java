package runar.examples.addrawoutput;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RawOutputTestTest {

    @Test
    void sendToScriptEmitsRawThenStateOutput() {
        RawOutputTest c = new RawOutputTest(Bigint.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("sendToScript", ByteString.fromHex("abcdef"));

        assertEquals(2, sim.outputs().size());
        // First: raw output with our script bytes
        var first = sim.outputs().get(0);
        assertTrue(first.isRaw());
        assertEquals(BigInteger.valueOf(1000), first.satoshis);
        // Second: state-continuation output for the incremented count
        var second = sim.outputs().get(1);
        assertTrue(second.isState());
        assertEquals(BigInteger.ZERO, second.satoshis);
        assertEquals(Bigint.of(1), c.count);
    }
}
