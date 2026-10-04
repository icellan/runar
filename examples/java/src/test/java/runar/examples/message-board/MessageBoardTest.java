package runar.examples.messageboard;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.Preimage;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MessageBoardTest {

    private static final PubKey OWNER = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final ByteString INITIAL = ByteString.fromHex("48656c6c6f"); // "Hello"
    private static final ByteString UPDATED = ByteString.fromHex("776f726c64"); // "world"
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

    /**
     * F-129: callStateful checks the preimage against the spending transaction
     * it builds from the compiled contract, so every call here passes the
     * honest preimage ({@code preimageFor}) built from the same spender-chosen
     * fields the test used to hand-roll.
     */
    private static final Path SOURCE = Path.of(
        "src", "main", "java", "runar", "examples", "message-board", "MessageBoard.runar.java"
    );

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
        ContractSimulator sim = ContractSimulator.stateful(c, SOURCE);
        Preimage pre = sim.preimageFor("post", Preimage.builder().build(), UPDATED);
        sim.callStateful("post", pre, UPDATED);
        assertEquals(UPDATED, c.message);
    }

    @Test
    void postIgnoresOwnerSig() {
        // post() has no signature check — anyone can post.
        MessageBoard c = new MessageBoard(INITIAL, OWNER);
        ContractSimulator sim = ContractSimulator.stateful(c, SOURCE);
        ByteString next = ByteString.fromHex("aabbccdd");
        Preimage pre = sim.preimageFor("post", Preimage.builder().build(), next);
        sim.callStateful("post", pre, next);
        assertEquals(next, c.message);
    }

    @Test
    void burnAcceptsOwnerSig() {
        MessageBoard c = new MessageBoard(INITIAL, OWNER);
        ContractSimulator sim = ContractSimulator.stateful(c, SOURCE);
        Preimage pre = sim.preimageFor("burn", Preimage.builder().build(), SIG);
        sim.callStateful("burn", pre, SIG);
    }

    @Test
    void burnRejectsNullSig() {
        MessageBoard c = new MessageBoard(INITIAL, OWNER);
        ContractSimulator sim = ContractSimulator.stateful(c, SOURCE);
        Preimage pre = sim.preimageFor("burn", Preimage.builder().build(), (Sig) null);
        AssertionError e = assertThrows(AssertionError.class, () -> sim.callStateful("burn", pre, (Sig) null));
        assertFalse(String.valueOf(e.getMessage()).startsWith("checkPreimage"),
            "rejected by burn's signature check, not by the preimage check");
    }
}
