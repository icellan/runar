package runar.examples.multimethod;

import org.junit.jupiter.api.Test;
import runar.lang.types.PubKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class MultiMethodTest {

    private static final PubKey OWNER  = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final PubKey BACKUP = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000002");

    @Test
    void contractInstantiates() {
        MultiMethod c = new MultiMethod(OWNER, BACKUP);
        assertNotNull(c);
        assertEquals(OWNER, c.owner);
        assertEquals(BACKUP, c.backup);
    }
}
