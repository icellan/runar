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

    // BUG-011: prefixes regenerated against the post-merge codegen — the new
    // OP_SIZE exact-length guard inserts `7c82..887c` (OP_SWAP, OP_SIZE,
    // pushBytes(sigLen), OP_EQUALVERIFY, OP_SWAP) directly after the existing
    // three-OP_TOALTSTACK preamble (`007b7b7b`). Lengths match the original
    // prefix lengths so the assertEquals substring contract is preserved.
    //
    // #137 (FIPS-205 conformance): the Hmsg MGF1 seed must be prefixed with
    // R || PK.seed (FIPS 205 Sec 11.2.1), which inserts two extra OP_PICKs
    // (`53795779`) and two extra OP_CATs (`7e7e`) into the Hmsg preamble --
    // inside the 100-hex-char window for every parameter set, so all six
    // prefixes below were re-captured from the fixed pipeline. All 7 tiers
    // emit byte-identical hex (conformance 72/72 in both fold modes).
    //
    // SLH-DSA MGF1 byte-order fix: the Hmsg last-block `swap` removal deletes an
    // OP_SWAP (`7c`) from the MGF1 tail, which falls inside the 100-byte prefix
    // window for 192s/192f/256s/256f (their shorter pkSeedPad padding puts the
    // MGF1 loop earlier than 128f's, whose window ends before it). Prefixes for
    // those four sets re-captured from the fixed pipeline.
    private static final String EXPECTED_PREFIX_128S =
        "007b7b7b7c8202b01e887c607f78300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007e537a607f7855795379577957795a797e7e7ea87e7e04000000007ea8011e7f7501157f57";
    private static final String EXPECTED_PREFIX_128F =
        "007b7b7b7c8202c042887c607f78300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007e537a607f7855795379577957795a797e7e7ea87e7e007c7604000000007ea87b7c7e7c04";
    private static final String EXPECTED_PREFIX_192S =
        "007b7b7b7c8202603f887c01187f7828000000000000000000000000000000000000000000000000000000000000000000000000000000007e537a01187f7855795379577957795a797e7e7ea87e7e007c7604000000007ea87b7c7e7c04000000017ea8";
    private static final String EXPECTED_PREFIX_192F =
        "007b7b7b7c8203508b00887c01187f7828000000000000000000000000000000000000000000000000000000000000000000000000000000007e537a01187f7855795379577957795a797e7e7ea87e7e007c7604000000007ea87b7c7e7c04000000017e";
    private static final String EXPECTED_PREFIX_256S =
        "007b7b7b7c82026074887c01207f782000000000000000000000000000000000000000000000000000000000000000007e537a01207f7855795379577957795a797e7e7ea87e7e007c7604000000007ea87b7c7e7c04000000017ea85f7f757e01277f57";
    private static final String EXPECTED_PREFIX_256F =
        "007b7b7b7c820360be00887c01207f782000000000000000000000000000000000000000000000000000000000000000007e537a01207f7855795379577957795a797e7e7ea87e7e007c7604000000007ea87b7c7e7c04000000017ea85c7f757e01237f";

    // BUG-011: each verifySLHDSA_* prologue now emits an OP_SIZE exact-length
    // guard (+5 Stack-IR ops per parameter set, +14 or +16 hex chars depending
    // on the size-push encoding) before the existing FORS / Merkle path
    // expansion. Numbers captured by running the test under the post-merge
    // codegen and reading the assertion-error report.
    //
    // SLH-DSA MGF1/FORS byte-order fix: the Hmsg last-block `swap` removal
    // trims one OP (-2 hex chars) for every digest spanning >1 SHA-256 block
    // (all sets except 128s), and the FORS index-extraction ceil fix widens the
    // 14-bit-field span from 2 to 3 bytes for 192s/256s (a=14), adding ops. New
    // lengths re-captured from the fixed pipeline; all 5 conformance goldens
    // (expected-script.hex) match the same codegen byte-for-byte.
    //
    // #137 (FIPS-205 conformance) shrank every parameter set slightly. Two
    // deviations were fixed in the shared emitter: (1) FIPS 205 Sec 11.2.1 --
    // Hmsg's MGF1 seed must be prefixed with R || PK.seed, and (2) FIPS 205
    // Alg. 8 lines 8-11 -- wots_pkFromSig must restore the key pair address
    // after setTypeAndClear(WOTS_PK). Net bytes fall because the PICKed 4-byte
    // key-pair address is cheaper to encode than the 4-zero-byte push it
    // replaces, once per hypertree layer. The prefix constants above are
    // unchanged: the drift lands past the 100-hex-char window.
    private static final int EXPECTED_HEX_LEN_128S = 377164;
    private static final int EXPECTED_HEX_LEN_128F = 1067702;
    private static final int EXPECTED_HEX_LEN_192S = 553136;
    private static final int EXPECTED_HEX_LEN_192F = 1575958;
    private static final int EXPECTED_HEX_LEN_256S = 738310;
    private static final int EXPECTED_HEX_LEN_256F = 1458636;

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
