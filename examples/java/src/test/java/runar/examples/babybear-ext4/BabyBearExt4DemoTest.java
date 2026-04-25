package runar.examples.babybearext4;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import runar.lang.sdk.CompileCheck;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation + Rúnar frontend round-trip for
 * {@link BabyBearExt4Demo}.
 *
 * <p>The contract is Rúnar-pure source: arithmetic flows as
 * {@code Bigint} values through {@link runar.lang.Builtins} shims, so the
 * Rúnar Java frontend (parse → validate → typecheck) accepts it via
 * {@link CompileCheck#run(Path)}. Codegen-level conformance for the
 * Baby Bear Ext4 (Go-only) crypto family is exercised through the other
 * compiler tiers.
 */
class BabyBearExt4DemoTest {

    @Test
    void contractInstantiates() {
        BabyBearExt4Demo c = new BabyBearExt4Demo();
        assertNotNull(c);
    }

    @Test
    void compileCheck() {
        Path source = Path.of(
            "src", "main", "java", "runar", "examples", "babybear-ext4",
            "BabyBearExt4Demo.runar.java"
        );
        assertDoesNotThrow(() -> CompileCheck.run(source));
    }
}
