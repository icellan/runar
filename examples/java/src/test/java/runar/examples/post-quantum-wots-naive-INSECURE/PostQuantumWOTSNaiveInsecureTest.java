package runar.examples.postquantumwotsnaiveinsecure;

import org.junit.jupiter.api.Test;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PostQuantumWOTSNaiveInsecureTest {

    @Test
    void contractInstantiates() {
        ByteString pk = ByteString.fromHex("00".repeat(32));
        PostQuantumWOTSNaiveInsecure c = new PostQuantumWOTSNaiveInsecure(pk);
        assertNotNull(c);
        assertEquals(pk, c.pubkey);
    }
}
