package runar.examples.babybearext4;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link BabyBearExt4Demo}.
 *
 * <p>The Baby Bear Ext4 builtins are part of the Go-only crypto family
 * -- the Rúnar Java compiler does not yet ship Stack-IR codegen for them
 * and the Java SDK does not yet expose runtime implementations, so a
 * {@code CompileCheck} round-trip is intentionally omitted. End-to-end
 * conformance is exercised through the other compiler tiers via the
 * shared conformance suite.
 */
class BabyBearExt4DemoTest {

    @Test
    void contractInstantiates() {
        BabyBearExt4Demo c = new BabyBearExt4Demo();
        assertNotNull(c);
    }
}
