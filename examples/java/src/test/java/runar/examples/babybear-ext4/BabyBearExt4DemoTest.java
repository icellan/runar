package runar.examples.babybearext4;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link BabyBearExt4Demo}.
 *
 * <p>Baby Bear Ext4 contracts use {@code new BigInteger(...)} expressions
 * which the Rúnar Java frontend does not yet parse, so a
 * {@link runar.lang.sdk.CompileCheck} round-trip is skipped for now.
 * Codegen-level conformance is exercised via the other compiler tiers.
 */
class BabyBearExt4DemoTest {

    @Test
    void contractInstantiates() {
        BabyBearExt4Demo c = new BabyBearExt4Demo();
        assertNotNull(c);
    }
}
