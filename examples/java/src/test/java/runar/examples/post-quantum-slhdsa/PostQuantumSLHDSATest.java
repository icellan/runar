package runar.examples.postquantumslhdsa;

import org.junit.jupiter.api.Test;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PostQuantumSLHDSATest {

    @Test
    void contractInstantiates() {
        ByteString pk = ByteString.fromHex("00".repeat(32));
        PostQuantumSLHDSA c = new PostQuantumSLHDSA(pk);
        assertNotNull(c);
        assertEquals(pk, c.pubkey);
    }
}
