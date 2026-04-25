package runar.examples.babybear;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link BabyBearDemo}.
 *
 * <p>Baby Bear contracts unwrap {@code Bigint} arguments via {@code .value()}
 * to interop with {@link runar.lang.runtime.MockCrypto}'s {@code BigInteger}
 * signatures. The Rúnar Java frontend does not yet recognise {@code .value()}
 * on {@code Bigint}, so a {@link runar.lang.sdk.CompileCheck} round-trip is
 * skipped for now — end-to-end conformance is exercised via the Go / TS /
 * Rust / Python / Zig / Ruby compilers.
 */
class BabyBearDemoTest {

    @Test
    void contractInstantiates() {
        BabyBearDemo c = new BabyBearDemo();
        assertNotNull(c);
    }
}
