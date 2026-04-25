package runar.examples.messageboard;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.Preimage;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MessageBoardTest {

    private static final PubKey OWNER = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final ByteString INITIAL = ByteString.fromHex("48656c6c6f"); // "Hello"
    private static final ByteString UPDATED = ByteString.fromHex("776f726c64"); // "world"
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

    @Test
    void contractInstantiates() {
        MessageBoard c = new MessageBoard(INITIAL, OWNER);
        assertNotNull(c);
        assertEquals(INITIAL, c.message);
        assertEquals(OWNER, c.owner);
    }

    @Test
    void postReplacesMessage() {
        MessageBoard c = new MessageBoard(INITIAL, OWNER);
        ContractSimulator sim = ContractSimulator.stateful(c);
        Preimage pre = Preimage.builder().build();
        sim.callStateful("post", pre, UPDATED);
        assertEquals(UPDATED, c.message);
    }

    @Test
    void postIgnoresOwnerSig() {
        // post() has no signature check — anyone can post.
        MessageBoard c = new MessageBoard(INITIAL, OWNER);
        ContractSimulator sim = ContractSimulator.stateful(c);
        Preimage pre = Preimage.builder().build();
        ByteString next = ByteString.fromHex("aabbccdd");
        sim.callStateful("post", pre, next);
        assertEquals(next, c.message);
    }

    @Test
    void burnAcceptsOwnerSig() {
        MessageBoard c = new MessageBoard(INITIAL, OWNER);
        ContractSimulator sim = ContractSimulator.stateful(c);
        Preimage pre = Preimage.builder().build();
        sim.callStateful("burn", pre, SIG);
    }

    @Test
    void burnRejectsNullSig() {
        MessageBoard c = new MessageBoard(INITIAL, OWNER);
        ContractSimulator sim = ContractSimulator.stateful(c);
        Preimage pre = Preimage.builder().build();
        assertThrows(AssertionError.class, () -> sim.callStateful("burn", pre, (Sig) null));
    }
}
