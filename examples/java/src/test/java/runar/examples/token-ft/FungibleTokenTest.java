package runar.examples.tokenft;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FungibleTokenTest {

    private static final PubKey ALICE = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final PubKey BOB   = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000002");
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));
    private static final ByteString TOKEN_ID = ByteString.fromHex("abcdef");

    @Test
    void contractInstantiates() {
        FungibleToken c = new FungibleToken(ALICE, Bigint.of(1000), TOKEN_ID);
        assertNotNull(c);
        assertEquals(Bigint.of(1000), c.balance);
    }

    @Test
    void partialTransferEmitsTwoOutputs() {
        FungibleToken c = new FungibleToken(ALICE, Bigint.of(1000), TOKEN_ID);
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("transfer", SIG, BOB, Bigint.of(300), Bigint.of(1));
        assertEquals(2, sim.outputs().size());
    }

    @Test
    void fullTransferEmitsOneOutput() {
        FungibleToken c = new FungibleToken(ALICE, Bigint.of(1000), TOKEN_ID);
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("transfer", SIG, BOB, Bigint.of(1000), Bigint.of(1));
        assertEquals(1, sim.outputs().size());
    }

    @Test
    void sendEmitsSingleOutput() {
        FungibleToken c = new FungibleToken(ALICE, Bigint.of(500), TOKEN_ID);
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("send", SIG, BOB, Bigint.of(1));
        assertEquals(1, sim.outputs().size());
    }

    @Test
    void transferRejectsOverdraft() {
        FungibleToken c = new FungibleToken(ALICE, Bigint.of(100), TOKEN_ID);
        ContractSimulator sim = ContractSimulator.stateful(c);
        assertThrows(
            AssertionError.class,
            () -> sim.call("transfer", SIG, BOB, Bigint.of(200), Bigint.of(1))
        );
    }
}
