package runar.examples.tokennft;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface + simulator tests for SimpleNFT. Mirrors the Python
 * {@code NFTExample} pytest suite. Verifies that transfer emits a single
 * continuation output and burn is a terminal spend.
 */
class SimpleNFTTest {

    private static final PubKey ALICE = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final PubKey BOB   = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000002");
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

    @Test
    void contractInstantiates() {
        SimpleNFT c = new SimpleNFT(ALICE, ByteString.fromHex("abcd"), ByteString.fromHex("ef"));
        assertNotNull(c);
        assertEquals(ALICE, c.owner);
    }

    @Test
    void transferEmitsContinuationOutput() {
        SimpleNFT c = new SimpleNFT(ALICE, ByteString.fromHex("abcd"), ByteString.fromHex("ef"));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("transfer", SIG, BOB, Bigint.of(1));
        assertEquals(1, sim.outputs().size());
        assertEquals(Bigint.of(1).value(), sim.outputs().get(0).satoshis);
    }

    @Test
    void burnEmitsNoOutput() {
        SimpleNFT c = new SimpleNFT(ALICE, ByteString.fromHex("abcd"), ByteString.fromHex("ef"));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("burn", SIG);
        assertEquals(0, sim.outputs().size());
    }
}
