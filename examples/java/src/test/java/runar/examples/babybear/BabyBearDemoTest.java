package runar.examples.babybear;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import runar.lang.sdk.CompileCheck;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation + Rúnar frontend round-trip for
 * {@link BabyBearDemo}.
 *
 * <p>The contract is Rúnar-pure source: every argument flows as a
 * {@code Bigint} through {@link runar.lang.Builtins} shims, so the Rúnar
 * Java frontend (parse → validate → typecheck) accepts it via
 * {@link CompileCheck#run(Path)}. Codegen-level conformance for the Baby
 * Bear (Go-only) crypto family is exercised through the other compiler
 * tiers.
 */
class BabyBearDemoTest {

    @Test
    void contractInstantiates() {
        BabyBearDemo c = new BabyBearDemo();
        assertNotNull(c);
    }

    @Test
    void compileCheck() {
        Path source = Path.of(
            "src", "main", "java", "runar", "examples", "babybear",
            "BabyBearDemo.runar.java"
        );
        assertDoesNotThrow(() -> CompileCheck.run(source));
    }
}
