package runar.examples.postquantumwots;

import org.junit.jupiter.api.Test;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PostQuantumWOTSTest {

    @Test
    void contractInstantiates() {
        ByteString pk = ByteString.fromHex("00".repeat(32));
        PostQuantumWOTS c = new PostQuantumWOTS(pk);
        assertNotNull(c);
        assertEquals(pk, c.pubkey);
    }
}
