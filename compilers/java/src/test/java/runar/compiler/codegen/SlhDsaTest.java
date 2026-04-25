package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.TsParser;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.passes.AnfLower;
import runar.compiler.passes.AnfOptimize;
import runar.compiler.passes.Emit;
import runar.compiler.passes.ExpandFixedArrays;
import runar.compiler.passes.Peephole;
import runar.compiler.passes.StackLower;
import runar.compiler.passes.Typecheck;
import runar.compiler.passes.Validate;

/**
 * Byte-identical parity tests for {@link SlhDsa} against the Python and
 * Rust reference codegen.
 *
 * <p>Hex prefixes were captured by running
 * {@code cd compilers/python && python3 -m runar_compiler --source <fixture>
 * --hex --disable-constant-folding} on a fixture that calls
 * {@code verifySLHDSA_SHA2_<variant>} once. Any divergence here means the
 * Java emitter has drifted and the compiler will produce non-conforming hex.
 */
class SlhDsaTest {

    // ------------------------------------------------------------------
    // Smoke tests on emitVerifySlhDsa directly
    // ------------------------------------------------------------------

    @Test
    void rejectsUnknownParamKey() {
        List<StackOp> ops = new ArrayList<>();
        assertThrows(RuntimeException.class,
            () -> SlhDsa.emitVerifySlhDsa(ops::add, "BLAKE_2_42"));
    }

    @Test
    void allParamKeysProduceOps() {
        for (String key : new String[]{"SHA2_128s", "SHA2_128f",
                "SHA2_192s", "SHA2_192f", "SHA2_256s", "SHA2_256f"}) {
            List<StackOp> ops = new ArrayList<>();
            SlhDsa.emitVerifySlhDsa(ops::add, key);
            assertFalse(ops.isEmpty(), "no ops for " + key);
            // First op of every variant is the OP_ROLL of "msg" past sig+pubkey.
            // The emit_verify_slh_dsa scripts open with `t.toTop("pubkey")`
            // but pubkey is already on top, so the first emission is the
            // PUSH+SPLIT for the (n) prefix on pubkey. That makes the first
            // op a PushOp of 0 (for pubkey already on top branch — OP_PICK_0
            // becomes OP_DUP) i.e. a DupOp; we just assert non-empty here
            // and rely on the byte-prefix tests below for content.
        }
    }

    @Test
    void emitterIsDeterministic() {
        List<StackOp> a = new ArrayList<>();
        List<StackOp> b = new ArrayList<>();
        SlhDsa.emitVerifySlhDsa(a::add, "SHA2_128s");
        SlhDsa.emitVerifySlhDsa(b::add, "SHA2_128s");
        assertEquals(a.size(), b.size(), "ops count drifts between runs");
        for (int i = 0; i < a.size(); i++) {
            assertEquals(a.get(i).op(), b.get(i).op(),
                "op[" + i + "] kind drifts");
        }
    }

    @Test
    void distinctVariantsProduceDistinctOpStreams() {
        List<StackOp> s = new ArrayList<>();
        List<StackOp> f = new ArrayList<>();
        SlhDsa.emitVerifySlhDsa(s::add, "SHA2_128s");
        SlhDsa.emitVerifySlhDsa(f::add, "SHA2_128f");
        // 128f has more layers / wider chains -- must emit substantially more ops.
        assertNotEquals(s.size(), f.size(),
            "SHA2_128s and SHA2_128f produced same op count -- variants confused");
        assertTrue(f.size() > s.size(),
            "expected SHA2_128f to be larger than SHA2_128s, got s=" + s.size()
            + " f=" + f.size());
    }

    @Test
    void paramKeyHelper() {
        assertEquals("SHA2_128s", SlhDsa.paramKey("verifySLHDSA_SHA2_128s"));
        assertEquals("SHA2_256f", SlhDsa.paramKey("verifySLHDSA_SHA2_256f"));
        assertThrows(IllegalArgumentException.class,
            () -> SlhDsa.paramKey("ecAdd"));
    }

    @Test
    void isSlhDsaBuiltinRecognisesAllSix() {
        for (String name : new String[]{
            "verifySLHDSA_SHA2_128s", "verifySLHDSA_SHA2_128f",
            "verifySLHDSA_SHA2_192s", "verifySLHDSA_SHA2_192f",
            "verifySLHDSA_SHA2_256s", "verifySLHDSA_SHA2_256f"
        }) {
            assertTrue(SlhDsa.isSlhDsaBuiltin(name), name + " should be SLH-DSA");
        }
        assertFalse(SlhDsa.isSlhDsaBuiltin("verifyWOTS"));
        assertFalse(SlhDsa.isSlhDsaBuiltin("ecAdd"));
    }

    // ------------------------------------------------------------------
    // Golden-hex comparison: end-to-end through the Java pipeline.
    //
    // The expected prefixes below were captured from the Python reference
    // compiler running on a minimal fixture for each parameter set.
    //
    // Source template:
    //
    //   import { SmartContract, assert, verifySLHDSA_<variant> } from 'runar-lang';
    //   import type { ByteString } from 'runar-lang';
    //   class C extends SmartContract {
    //     readonly pubkey: ByteString;
    //     constructor(pubkey: ByteString) { super(pubkey); this.pubkey = pubkey; }
    //     public spend(msg: ByteString, sig: ByteString) {
    //       assert(verifySLHDSA_<variant>(msg, sig, this.pubkey));
    //     }
    //   }
    //
    // Captured by:
    //   cd compilers/python && python3 -m runar_compiler \
    //     --source <fixture> --hex --disable-constant-folding
    // ------------------------------------------------------------------

    private static final String EXPECTED_PREFIX_128S =
        "007b7b7b607f78300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007e537a607f785579557958797e7e7ea804000000007ea8011e7f7501157f577f7c517f517f517f517f517f51";
    private static final String EXPECTED_PREFIX_128F =
        "007b7b7b607f78300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007e537a607f785579557958797e7e7ea8007c7604000000007ea87b7c7e7c04000000017ea8527f757c7e0119";
    private static final String EXPECTED_PREFIX_192S =
        "007b7b7b01187f7828000000000000000000000000000000000000000000000000000000000000000000000000000000007e537a01187f785579557958797e7e7ea8007c7604000000007ea87b7c7e7c04000000017ea8577f757c7e011e7f577f7c517f";
    private static final String EXPECTED_PREFIX_192F =
        "007b7b7b01187f7828000000000000000000000000000000000000000000000000000000000000000000000000000000007e537a01187f785579557958797e7e7ea8007c7604000000007ea87b7c7e7c04000000017ea85a7f757c7e01217f587f7c517f";
    private static final String EXPECTED_PREFIX_256S =
        "007b7b7b01207f782000000000000000000000000000000000000000000000000000000000000000007e537a01207f785579557958797e7e7ea8007c7604000000007ea87b7c7e7c04000000017ea85f7f757c7e01277f577f7c517f517f517f517f517f";
    private static final String EXPECTED_PREFIX_256F =
        "007b7b7b01207f782000000000000000000000000000000000000000000000000000000000000000007e537a01207f785579557958797e7e7ea8007c7604000000007ea87b7c7e7c04000000017ea85c7f757c7e01237f587f7c517f517f517f517f517f";

    private static final int EXPECTED_HEX_LEN_128S = 377180;
    private static final int EXPECTED_HEX_LEN_128F = 1067810;
    private static final int EXPECTED_HEX_LEN_192S = 553050;
    private static final int EXPECTED_HEX_LEN_192F = 1576064;
    private static final int EXPECTED_HEX_LEN_256S = 738192;
    private static final int EXPECTED_HEX_LEN_256F = 1458712;

    @Test
    void compilesSlhDsa128sToCanonicalHex() throws Exception {
        String hex = compileFixture("SHA2_128s");
        assertEquals(EXPECTED_HEX_LEN_128S, hex.length(),
            "SHA2_128s total hex length drift");
        assertEquals(EXPECTED_PREFIX_128S, hex.substring(0, EXPECTED_PREFIX_128S.length()),
            "SHA2_128s hex prefix drift");
    }

    @Test
    void compilesSlhDsa128fToCanonicalHex() throws Exception {
        String hex = compileFixture("SHA2_128f");
        assertEquals(EXPECTED_HEX_LEN_128F, hex.length(),
            "SHA2_128f total hex length drift");
        assertEquals(EXPECTED_PREFIX_128F, hex.substring(0, EXPECTED_PREFIX_128F.length()),
            "SHA2_128f hex prefix drift");
    }

    @Test
    void compilesSlhDsa192sToCanonicalHex() throws Exception {
        String hex = compileFixture("SHA2_192s");
        assertEquals(EXPECTED_HEX_LEN_192S, hex.length(),
            "SHA2_192s total hex length drift");
        assertEquals(EXPECTED_PREFIX_192S, hex.substring(0, EXPECTED_PREFIX_192S.length()),
            "SHA2_192s hex prefix drift");
    }

    @Test
    void compilesSlhDsa192fToCanonicalHex() throws Exception {
        String hex = compileFixture("SHA2_192f");
        assertEquals(EXPECTED_HEX_LEN_192F, hex.length(),
            "SHA2_192f total hex length drift");
        assertEquals(EXPECTED_PREFIX_192F, hex.substring(0, EXPECTED_PREFIX_192F.length()),
            "SHA2_192f hex prefix drift");
    }

    @Test
    void compilesSlhDsa256sToCanonicalHex() throws Exception {
        String hex = compileFixture("SHA2_256s");
        assertEquals(EXPECTED_HEX_LEN_256S, hex.length(),
            "SHA2_256s total hex length drift");
        assertEquals(EXPECTED_PREFIX_256S, hex.substring(0, EXPECTED_PREFIX_256S.length()),
            "SHA2_256s hex prefix drift");
    }

    @Test
    void compilesSlhDsa256fToCanonicalHex() throws Exception {
        String hex = compileFixture("SHA2_256f");
        assertEquals(EXPECTED_HEX_LEN_256F, hex.length(),
            "SHA2_256f total hex length drift");
        assertEquals(EXPECTED_PREFIX_256F, hex.substring(0, EXPECTED_PREFIX_256F.length()),
            "SHA2_256f hex prefix drift");
    }

    /**
     * Compile a synthesised single-builtin contract for the given variant
     * (e.g. {@code SHA2_128s}) and return the locking-script hex.
     */
    private static String compileFixture(String variant) throws Exception {
        String source = ""
            + "import { SmartContract, assert, verifySLHDSA_" + variant + " } from 'runar-lang';\n"
            + "import type { ByteString } from 'runar-lang';\n"
            + "\n"
            + "class C extends SmartContract {\n"
            + "  readonly pubkey: ByteString;\n"
            + "  constructor(pubkey: ByteString) { super(pubkey); this.pubkey = pubkey; }\n"
            + "  public spend(msg: ByteString, sig: ByteString) {\n"
            + "    assert(verifySLHDSA_" + variant + "(msg, sig, this.pubkey));\n"
            + "  }\n"
            + "}\n";

        ContractNode contract = TsParser.parse(source, "C.runar.ts");
        Validate.run(contract);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        // Mirror --disable-constant-folding: skip ConstantFold, run AnfOptimize.
        anf = AnfOptimize.run(anf);
        StackProgram stack = StackLower.run(anf);
        stack = Peephole.run(stack);
        return Emit.run(stack);
    }
}
