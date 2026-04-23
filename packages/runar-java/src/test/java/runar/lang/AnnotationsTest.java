package runar.lang;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.*;

class AnnotationsTest {

    /** Minimal skeleton contract exercising the @Public / @Readonly shape. */
    static class FakeP2PKH extends SmartContract {
        @Readonly Addr pubKeyHash;

        FakeP2PKH(Addr pubKeyHash) {
            super(pubKeyHash);
            this.pubKeyHash = pubKeyHash;
        }

        @Public
        public void unlock(Sig sig, PubKey pubKey) {
            // Body is stubbed; this test only verifies annotation shape.
        }
    }

    @Test
    void readonlyAnnotationIsRetainedAtRuntime() throws NoSuchFieldException {
        Field f = FakeP2PKH.class.getDeclaredField("pubKeyHash");
        assertNotNull(f.getAnnotation(Readonly.class), "@Readonly should be retained at runtime");
    }

    @Test
    void publicAnnotationIsRetainedAtRuntime() throws NoSuchMethodException {
        Method m = FakeP2PKH.class.getDeclaredMethod("unlock", Sig.class, PubKey.class);
        assertNotNull(m.getAnnotation(Public.class), "@Public should be retained at runtime");
    }

    @Test
    void byteStringEqualityWorksAcrossSubtypes() {
        Addr a = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
        Addr b = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
        Addr c = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121315");
        assertEquals(a, b);
        assertNotEquals(a, c);
    }

    @Test
    void builtinStubsThrowExplicitly() {
        PubKey pk = PubKey.fromHex("02" + "00".repeat(32));
        UnsupportedOperationException ex = assertThrows(
            UnsupportedOperationException.class,
            () -> Builtins.hash160(pk)
        );
        assertTrue(ex.getMessage().contains("compile-time intrinsic"));
    }
}
