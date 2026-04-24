package runar.examples.messageboard;

import org.junit.jupiter.api.Test;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Phase 1 surface-level test: the {@link MessageBoard} contract must
 * compile against the runar-java SDK and instantiate with a fixed
 * message and owner PubKey.
 *
 * <p>Runtime execution of {@code post(...)} / {@code burn(...)} requires
 * the off-chain simulator from M11 (stateful contracts inject
 * {@code checkPreimage} at method entry, which needs simulator
 * scaffolding).
 */
class MessageBoardTest {

    @Test
    void contractInstantiates() {
        ByteString message = ByteString.fromHex("48656c6c6f"); // "Hello"
        PubKey owner = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
        MessageBoard c = new MessageBoard(message, owner);
        assertNotNull(c);
        assertEquals(message, c.message);
        assertEquals(owner, c.owner);
        // TODO(M11): once ContractSimulator is fully wired, exercise method bodies here
    }
}
