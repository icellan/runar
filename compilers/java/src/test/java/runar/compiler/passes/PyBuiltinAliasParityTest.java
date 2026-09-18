package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * R-039 — irregular Python builtin aliases must map identically in all 7 tiers.
 *
 * <p>Python contracts are written in snake_case and every tier's {@code .runar.py} parser rewrites
 * the identifiers to the canonical Rúnar camelCase names. Most names fall out of a mechanical
 * snake→camel rule, but five do not and therefore need an explicit entry in each tier's
 * special-name table:
 *
 * <pre>
 *   int_to_str           -> int2str            (digit: "to" collapses to "2")
 *   safe_div             -> safediv            (no interior capital)
 *   safe_mod             -> safemod            (no interior capital)
 *   div_mod              -> divmod             (no interior capital)
 *   require_output_p2pkh -> requireOutputP2PKH (all-caps PKH token)
 * </pre>
 *
 * <p>Before this test the Java tier had the first four but not
 * {@code require_output_p2pkh}: the mechanical rule produced
 * {@code requireOutputP2pkh}, which the type checker rejects as an unknown function, while the
 * Python tier compiled the very same source. CLAUDE.md makes frontend parity a no-exceptions
 * invariant, so that is a parity break.
 *
 * <p>The pinned hexes are the SEVEN-TIER agreed fold-OFF output.
 */
class PyBuiltinAliasParityTest {

    private static final String INT2STR_SNAKE =
        "from runar import SmartContract, Bigint, ByteString, public, assert_, int_to_str, len_\n"
        + "\n"
        + "\n"
        + "class Encoder(SmartContract):\n"
        + "    n: Bigint\n"
        + "\n"
        + "    def __init__(self, n: Bigint):\n"
        + "        super().__init__(n)\n"
        + "        self.n = n\n"
        + "\n"
        + "    @public\n"
        + "    def unlock(self):\n"
        + "        out: ByteString = int_to_str(self.n, 4)\n"
        + "        assert_(len_(out) == 4)\n";

    private static final String MATH_ALIASES =
        "from runar import SmartContract, Bigint, public, assert_\n"
        + "\n"
        + "\n"
        + "class Aliases(SmartContract):\n"
        + "    n: Bigint\n"
        + "\n"
        + "    def __init__(self, n: Bigint):\n"
        + "        super().__init__(n)\n"
        + "        self.n = n\n"
        + "\n"
        + "    @public\n"
        + "    def unlock(self):\n"
        + "        a: Bigint = safe_div(self.n, 3)\n"
        + "        b: Bigint = safe_mod(self.n, 3)\n"
        + "        c: Bigint = div_mod(self.n, 3)\n"
        + "        assert_(a + b + c > 0)\n";

    private static final String INTENT_SNAKE =
        "from runar import (\n"
        + "    StatefulSmartContract, ByteString, Bigint, Readonly, public,\n"
        + ")\n"
        + "\n"
        + "\n"
        + "class Intent(StatefulSmartContract):\n"
        + "    bondPKH: Readonly[ByteString]\n"
        + "    bondAmount: Readonly[Bigint]\n"
        + "    count: Bigint\n"
        + "\n"
        + "    def __init__(self, bondPKH: ByteString, bondAmount: Bigint, count: Bigint):\n"
        + "        super().__init__(bondPKH, bondAmount, count)\n"
        + "        self.bondPKH = bondPKH\n"
        + "        self.bondAmount = bondAmount\n"
        + "        self.count = count\n"
        + "\n"
        + "    @public\n"
        + "    def payBond(self):\n"
        + "        require_output_p2pkh(0, self.bondPKH, self.bondAmount)\n";

    private static final String UNKNOWN_BUILTIN =
        "from runar import SmartContract, Bigint, public, assert_\n"
        + "\n"
        + "\n"
        + "class Unknown(SmartContract):\n"
        + "    n: Bigint\n"
        + "\n"
        + "    def __init__(self, n: Bigint):\n"
        + "        super().__init__(n)\n"
        + "        self.n = n\n"
        + "\n"
        + "    @public\n"
        + "    def unlock(self):\n"
        + "        assert_(not_a_builtin(self.n) > 0)\n";

    @Test
    void intToStrLowersToTheSevenTierScript() throws Exception {
        assertEquals("0054808277549c", PipelineTestSupport.hex(INT2STR_SNAKE, "Encoder.runar.py"));
    }

    @Test
    void mathAliasesLowerToTheSevenTierScript() throws Exception {
        assertEquals(
            "00537692699600537692699700536e967b7b97757b7b937c9300a0",
            PipelineTestSupport.hex(MATH_ALIASES, "Aliases.runar.py"));
    }

    @Test
    void requireOutputP2pkhMatchesCamelCase() throws Exception {
        String camel = INTENT_SNAKE.replace("require_output_p2pkh", "requireOutputP2PKH");
        assertEquals(
            PipelineTestSupport.hex(camel, "Intent.runar.py"),
            PipelineTestSupport.hex(INTENT_SNAKE, "Intent.runar.py"));
    }

    @Test
    void unknownSnakeCaseFunctionIsStillRejected() {
        // Guards against the lazy fix: a blanket pass-through that maps any
        // snake_case identifier onto a builtin name would let this compile.
        Exception e = assertThrows(
            Exception.class, () -> PipelineTestSupport.hex(UNKNOWN_BUILTIN, "Unknown.runar.py"));
        assertTrue(
            String.valueOf(e.getMessage()).contains("notABuiltin"),
            "expected an unknown-function diagnostic for notABuiltin, got: " + e.getMessage());
    }
}
