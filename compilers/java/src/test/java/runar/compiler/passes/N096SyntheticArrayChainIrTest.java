package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * N-096: the IR loader refuses a {@code syntheticArrayChain} the
 * expand-fixed-arrays pass could not have written, with the diagnostic shared
 * by all 7 tiers ({@code conformance/negatives/ir-synthetic-array-chain.test.ts}
 * holds the corpus). Before the rule this tier published the F-105 probe's
 * 1100-level property as a scalar constructor parameter.
 *
 * <p>Proves: the probe is refused at load time with the shared words, and the
 * FixedArray goldens still load. Does not prove the rest of the rule, which
 * the conformance corpus covers in every tier.
 */
class N096SyntheticArrayChainIrTest {

    private static String golden(String fixture) throws Exception {
        return Files.readString(Path.of("..", "..", "conformance", "tests", fixture, "expected-ir.json"));
    }

    @Test
    void f105ProbeIsRefusedWithTheSharedDiagnostic() throws Exception {
        String ir = golden("basic-p2pkh");
        StringBuilder chain = new StringBuilder("[");
        for (int i = 0; i < 1100; i++) {
            if (i > 0) chain.append(',');
            chain.append("{\"base\":\"deep\",\"index\":0,\"length\":1}");
        }
        chain.append(']');
        String deep = "{\"name\":\"deep\",\"type\":\"bigint\",\"readonly\":true,\"syntheticArrayChain\":" + chain + "},";
        int at = ir.indexOf("\"properties\"");
        int open = ir.indexOf('[', at) + 1;
        String probe = ir.substring(0, open) + deep + ir.substring(open);
        RuntimeException e = assertThrows(RuntimeException.class, () -> AnfLoader.parse(probe));
        assertEquals(
            "IR validation: malformed syntheticArrayChain on property 'deep': 1100 levels exceed the limit of 1023",
            e.getMessage());
    }

    @Test
    void fixedArrayGoldensStillLoad() throws Exception {
        for (String f : new String[] {"fixed-array-index", "fixed-array-write"}) {
            String ir = golden(f);
            assertDoesNotThrow(() -> AnfLoader.parse(ir), f);
        }
    }
}
