package runar.examples.babybear;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link BabyBearDemo}.
 *
 * <p>The Baby Bear field builtins are part of the Go-only crypto family
 * -- the Rúnar Java compiler does not yet ship Stack-IR codegen for them,
 * so a {@code CompileCheck} round-trip is intentionally omitted. End-to-
 * end conformance is exercised through the other compiler tiers via the
 * shared conformance suite.
 */
class BabyBearDemoTest {

    @Test
    void contractInstantiates() {
        BabyBearDemo c = new BabyBearDemo();
        assertNotNull(c);
    }
}
