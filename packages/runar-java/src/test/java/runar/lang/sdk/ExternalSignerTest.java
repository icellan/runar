package runar.lang.sdk;

import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ExternalSignerTest {

    private static byte[] dummyPubKey() {
        byte[] pk = new byte[33];
        pk[0] = 0x02;
        for (int i = 1; i < 33; i++) pk[i] = (byte) i;
        return pk;
    }

    private static ExternalSigner.SignCallback noopCallback() {
        return (sighash, derivationKey) -> new byte[0];
    }

    @Test
    void constructor_rejectsNullPubKey() {
        assertThrows(NullPointerException.class,
            () -> new ExternalSigner(null, "addr", noopCallback()));
    }

    @Test
    void constructor_rejectsNullAddress() {
        assertThrows(NullPointerException.class,
            () -> new ExternalSigner(dummyPubKey(), null, noopCallback()));
    }

    @Test
    void constructor_rejectsNullCallback() {
        assertThrows(NullPointerException.class,
            () -> new ExternalSigner(dummyPubKey(), "addr", null));
    }

    @Test
    void pubKey_returnsDefensiveCopy() {
        ExternalSigner s = new ExternalSigner(dummyPubKey(), "addr", noopCallback());
        byte[] first = s.pubKey();
        // mutating the returned array must not affect subsequent calls
        for (int i = 0; i < first.length; i++) first[i] = (byte) 0xff;
        byte[] second = s.pubKey();
        assertArrayEquals(dummyPubKey(), second);
    }

    @Test
    void pubKey_isolatedFromConstructorArg() {
        byte[] arg = dummyPubKey();
        ExternalSigner s = new ExternalSigner(arg, "addr", noopCallback());
        // mutate the array we passed to the constructor
        for (int i = 0; i < arg.length; i++) arg[i] = 0x00;
        // the signer should have copied — its view is unchanged
        assertArrayEquals(dummyPubKey(), s.pubKey());
    }

    @Test
    void address_returnsConfiguredValue() {
        ExternalSigner s = new ExternalSigner(dummyPubKey(), "myAddr", noopCallback());
        assertEquals("myAddr", s.address());
    }

    @Test
    void sign_invokesCallbackWithExpectedArgs() {
        AtomicReference<byte[]> capturedSighash = new AtomicReference<>();
        AtomicReference<String> capturedKey = new AtomicReference<>();
        ExternalSigner.SignCallback cb = (sighash, derivationKey) -> {
            capturedSighash.set(sighash);
            capturedKey.set(derivationKey);
            return new byte[]{0x30, 0x00};
        };
        ExternalSigner s = new ExternalSigner(dummyPubKey(), "addr", cb);

        byte[] sighash = new byte[32];
        for (int i = 0; i < 32; i++) sighash[i] = (byte) (i * 7);
        s.sign(sighash, "m/44'/0'/0'/0/0");

        assertSame(sighash, capturedSighash.get());
        assertEquals("m/44'/0'/0'/0/0", capturedKey.get());
    }

    @Test
    void sign_returnsCallbackOutput() {
        byte[] expected = new byte[]{0x30, 0x44, 0x02, 0x20, (byte) 0xab};
        ExternalSigner s = new ExternalSigner(
            dummyPubKey(),
            "addr",
            (sighash, derivationKey) -> expected
        );
        byte[] got = s.sign(new byte[32], null);
        assertArrayEquals(expected, got);
    }
}
