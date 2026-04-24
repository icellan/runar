package runar.examples.adddataoutput;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataOutputTestTest {

    @Test
    void bumpEmitsDataOutputAndIncrementsCount() {
        DataOutputTest c = new DataOutputTest(Bigint.of(7));
        ContractSimulator sim = ContractSimulator.stateful(c);
        byte[] payload = new byte[]{0x01, 0x02, 0x03};
        sim.call("bump", ByteString.fromHex("010203"));

        assertEquals(Bigint.of(8), c.count);
        assertEquals(1, sim.outputs().size());
        var out = sim.outputs().get(0);
        assertTrue(out.isData());
        assertArrayEquals(payload, out.rawScriptBytes);
    }
}
