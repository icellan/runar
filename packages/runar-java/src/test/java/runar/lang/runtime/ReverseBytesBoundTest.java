package runar.lang.runtime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Since D12 BM-F3 every compiler's reverseBytes ends in OP_0 OP_EQUALVERIFY,
 * so the script ABORTS on an input longer than 520 bytes. The simulator's
 * MockCrypto must refuse the same input rather than reverse it in full.
 */
class ReverseBytesBoundTest {

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 520})
    void reversesUpTo520(int n) {
        byte[] src = new byte[n];
        for (int i = 0; i < n; i++) src[i] = (byte) i;
        byte[] got = MockCrypto.reverseBytes(new ByteString(src)).toByteArray();
        assertEquals(n, got.length);
        for (int i = 0; i < n; i++) assertEquals(src[n - 1 - i], got[i]);
    }

    @Test
    void refuses521() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> MockCrypto.reverseBytes(new ByteString(new byte[521])));
        assertTrue(e.getMessage().contains("520"), e.getMessage());
    }
}
