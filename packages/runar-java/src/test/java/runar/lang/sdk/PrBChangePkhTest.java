package runar.lang.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #213, SDK side — defence in depth only.
 *
 * <p>A stateful method's unlocking script pushes the compiler-injected
 * {@code _changePKH} (a Ripemd160, exactly 20 bytes). The consensus defence is
 * the covenant's entry gate on its width ({@code OP_SIZE 0x14
 * OP_NUMEQUALVERIFY}). {@code RunarContract} derives the change PKH as
 * hash160(pubkey), always 20 bytes; {@code StateSerializer.encodeChangePkh} is
 * the single encoder the change-PKH push goes through, and refuses anything
 * that is not exactly 20 bytes of hex. Proves nothing on chain.
 */
class PrBChangePkhTest {

    @Test
    void refusesWrongWidth() {
        for (int n : new int[] {19, 21, 54}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> StateSerializer.encodeChangePkh("ab".repeat(n)), n + "-byte changePKH");
            assertTrue(e.getMessage().contains("changePKH (Ripemd160) must be exactly 20 bytes"), e.getMessage());
        }
    }

    @Test
    void refusesNonHex() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.encodeChangePkh("zz".repeat(20)));
        assertTrue(e.getMessage().contains(
            "changePKH (Ripemd160) must be exactly 20 bytes of hex, got a non-hex string"), e.getMessage());
    }

    @Test
    void accepts20Bytes() {
        String pkh = "ab".repeat(20);
        assertEquals("14" + pkh, StateSerializer.encodeChangePkh(pkh));
    }
}
