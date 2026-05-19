package runar.lang.runtime;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.compiler.Cli;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.passes.AnfLower;
import runar.compiler.passes.ExpandFixedArrays;
import runar.compiler.passes.Typecheck;
import runar.compiler.passes.Validate;
import runar.lang.sdk.AnfInterpreter;
import runar.lang.sdk.AnfInterpreter.AssertionFailureException;
import runar.lang.sdk.AnfInterpreter.ExecutionResult;
import runar.lang.sdk.AnfInterpreter.InterpreterException;
import runar.lang.sdk.AnfInterpreter.WitnessContext;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Java mirror of the TS reference interpreter coverage for the three
 * intent-covenant intrinsics ({@code extractPrevOutputScript},
 * {@code requireOutputP2PKH}, {@code currentBlockHeight}) plus the
 * branched-readonly-len affine-checker exercise. Sources are the same
 * {@code .runar.ts} fixtures the TS reference test reads — the test
 * drives them through the Java compiler frontend
 * ({@link ParserDispatch} → {@link Validate} → {@link ExpandFixedArrays}
 * → {@link Typecheck} → {@link AnfLower} → {@link Cli#optimizeAnf}) and
 * runs the resulting ANF through {@link AnfInterpreter#executeStrict}
 * with off-chain witness bytes routed via {@link WitnessContext}.
 *
 * <p>One-to-one with
 * {@code packages/runar-testing/src/__tests__/intent-intrinsics-interpreter.test.ts}:
 * <ul>
 *   <li>3 tests for intent-prev-output-script (1 success + 2 failure)</li>
 *   <li>3 tests for intent-output-p2pkh (1 success + 2 failure)</li>
 *   <li>2 tests for intent-current-block-height (1 success + 1 failure)</li>
 *   <li>2 tests for branched-readonly-len (then + else)</li>
 * </ul>
 */
class IntentInterpreterTest {

    private static final HexFormat HEX = HexFormat.of();

    // ------------------------------------------------------------------
    // Fixture sources (resolved relative to packages/runar-java cwd)
    // ------------------------------------------------------------------

    private static final Path REPO_ROOT = Paths.get(System.getProperty("user.dir"), "..", "..");

    private static String src(String sub, String name) throws Exception {
        return Files.readString(REPO_ROOT.resolve("examples/ts/" + sub + "/" + name));
    }

    private static Map<String, Object> compile(String source, String fileName) throws Exception {
        ContractNode contract = ParserDispatch.parse(source, fileName);
        Validate.run(contract);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        // Match the user-facing CLI defaults: constant fold + general ANF cleanup.
        anf = Cli.optimizeAnf(anf, false);
        String json = Jcs.stringify(anf);
        return AnfInterpreter.loadAnf("{\"anf\":" + json + "}");
    }

    private static byte[] hash256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(md.digest(data));
    }

    /** Build a canonical 34-byte P2PKH output: 8 LE amount || 1976a914 || pkh || 88ac. */
    private static byte[] p2pkhOutput(long amount, byte[] pkh) {
        if (pkh.length != 20) throw new IllegalArgumentException("pkh must be 20 bytes");
        byte[] out = new byte[34];
        long a = amount;
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (a & 0xff);
            a >>>= 8;
        }
        out[8]  = (byte) 0x19;
        out[9]  = (byte) 0x76;
        out[10] = (byte) 0xa9;
        out[11] = (byte) 0x14;
        System.arraycopy(pkh, 0, out, 12, 20);
        out[32] = (byte) 0x88;
        out[33] = (byte) 0xac;
        return out;
    }

    // ==================================================================
    // intent-prev-output-script
    // ==================================================================

    @Test
    void intentPrevOutputScript_success() throws Exception {
        Map<String, Object> anf = compile(
            src("intent-prev-output-script", "IntentPrevOutputScript.runar.ts"),
            "IntentPrevOutputScript.runar.ts"
        );
        byte[] prevOutScript = HEX.parseHex("76a91400112233445566778899aabbccddeeff0011223388ac");
        byte[] expectedHash = hash256(prevOutScript);

        WitnessContext witness = new WitnessContext()
            .setPrevOutScript(0, prevOutScript);

        ExecutionResult r = AnfInterpreter.executeStrict(
            anf,
            "bind",
            Map.of("count", BigInteger.ZERO),
            Map.of(),
            List.of(HEX.formatHex(expectedHash), BigInteger.ZERO),
            witness
        );
        assertEquals(BigInteger.ONE, r.newState.get("count"),
            "count must be incremented when the witness hashes to expectedHash");
    }

    @Test
    void intentPrevOutputScript_failureWrongWitness() throws Exception {
        Map<String, Object> anf = compile(
            src("intent-prev-output-script", "IntentPrevOutputScript.runar.ts"),
            "IntentPrevOutputScript.runar.ts"
        );
        byte[] prevOutScript = HEX.parseHex("76a91400112233445566778899aabbccddeeff0011223388ac");
        byte[] expectedHash = hash256(prevOutScript);

        WitnessContext witness = new WitnessContext()
            .setPrevOutScript(0, HEX.parseHex("deadbeef"));

        AssertionFailureException ex = assertThrows(
            AssertionFailureException.class,
            () -> AnfInterpreter.executeStrict(
                anf,
                "bind",
                Map.of("count", BigInteger.ZERO),
                Map.of(),
                List.of(HEX.formatHex(expectedHash), BigInteger.ZERO),
                witness
            )
        );
        assertTrue(ex.getMessage().contains("assert failed"),
            "must trip the hash assertion: " + ex.getMessage());
    }

    @Test
    void intentPrevOutputScript_failureNoWitness() throws Exception {
        Map<String, Object> anf = compile(
            src("intent-prev-output-script", "IntentPrevOutputScript.runar.ts"),
            "IntentPrevOutputScript.runar.ts"
        );
        byte[] expectedHash = hash256(
            HEX.parseHex("76a91400112233445566778899aabbccddeeff0011223388ac")
        );

        // No setPrevOutScript call -> WitnessContext lookup returns null.
        WitnessContext witness = new WitnessContext();

        InterpreterException ex = assertThrows(
            InterpreterException.class,
            () -> AnfInterpreter.executeStrict(
                anf,
                "bind",
                Map.of("count", BigInteger.ZERO),
                Map.of(),
                List.of(HEX.formatHex(expectedHash), BigInteger.ZERO),
                witness
            )
        );
        assertTrue(ex.getMessage().contains("requires witness bytes"),
            "missing witness must surface explicitly: " + ex.getMessage());
    }

    // ==================================================================
    // intent-output-p2pkh
    // ==================================================================

    @Test
    void intentOutputP2pkh_success() throws Exception {
        Map<String, Object> anf = compile(
            src("intent-output-p2pkh", "IntentOutputP2PKH.runar.ts"),
            "IntentOutputP2PKH.runar.ts"
        );
        byte[] bondPKH = HEX.parseHex("00112233445566778899aabbccddeeff00112233");
        long bondAmount = 5000L;
        byte[] serialised = p2pkhOutput(bondAmount, bondPKH);
        byte[] outputHash = hash256(serialised);

        WitnessContext witness = new WitnessContext()
            .setSerialisedOutputs(serialised)
            .setMockPreimageBytes("outputHash", outputHash);

        ExecutionResult r = AnfInterpreter.executeStrict(
            anf,
            "payBond",
            Map.of("count", BigInteger.ZERO),
            Map.of(),
            List.of(HEX.formatHex(bondPKH), BigInteger.valueOf(bondAmount), BigInteger.ZERO),
            witness
        );
        assertEquals(BigInteger.ONE, r.newState.get("count"),
            "count must increment after both assertions pass");
    }

    @Test
    void intentOutputP2pkh_failureWrongPKH() throws Exception {
        Map<String, Object> anf = compile(
            src("intent-output-p2pkh", "IntentOutputP2PKH.runar.ts"),
            "IntentOutputP2PKH.runar.ts"
        );
        byte[] bondPKH = HEX.parseHex("00112233445566778899aabbccddeeff00112233");
        long bondAmount = 5000L;
        byte[] wrongPKH = HEX.parseHex("ffffffffffffffffffffffffffffffffffffffff");
        byte[] wrongSerialised = p2pkhOutput(bondAmount, wrongPKH);
        // Match the outer-hash check so the per-output substring compare is
        // the assert that trips (mirrors the TS reference test).
        byte[] wrongHashOutputs = hash256(wrongSerialised);

        WitnessContext witness = new WitnessContext()
            .setSerialisedOutputs(wrongSerialised)
            .setMockPreimageBytes("outputHash", wrongHashOutputs);

        AssertionFailureException ex = assertThrows(
            AssertionFailureException.class,
            () -> AnfInterpreter.executeStrict(
                anf,
                "payBond",
                Map.of("count", BigInteger.ZERO),
                Map.of(),
                List.of(HEX.formatHex(bondPKH), BigInteger.valueOf(bondAmount), BigInteger.ZERO),
                witness
            )
        );
        assertTrue(ex.getMessage().contains("assert failed"), ex.getMessage());
    }

    @Test
    void intentOutputP2pkh_failureHashOutputsMismatch() throws Exception {
        Map<String, Object> anf = compile(
            src("intent-output-p2pkh", "IntentOutputP2PKH.runar.ts"),
            "IntentOutputP2PKH.runar.ts"
        );
        byte[] bondPKH = HEX.parseHex("00112233445566778899aabbccddeeff00112233");
        long bondAmount = 5000L;
        byte[] serialised = p2pkhOutput(bondAmount, bondPKH);

        WitnessContext witness = new WitnessContext()
            .setSerialisedOutputs(serialised)
            // Wrong outputHash on the preimage -> outer hash assert fails first.
            .setMockPreimageBytes("outputHash", new byte[32]);

        AssertionFailureException ex = assertThrows(
            AssertionFailureException.class,
            () -> AnfInterpreter.executeStrict(
                anf,
                "payBond",
                Map.of("count", BigInteger.ZERO),
                Map.of(),
                List.of(HEX.formatHex(bondPKH), BigInteger.valueOf(bondAmount), BigInteger.ZERO),
                witness
            )
        );
        assertTrue(ex.getMessage().contains("assert failed"), ex.getMessage());
    }

    // ==================================================================
    // intent-current-block-height
    // ==================================================================

    @Test
    void intentCurrentBlockHeight_success() throws Exception {
        Map<String, Object> anf = compile(
            src("intent-current-block-height", "IntentCurrentBlockHeight.runar.ts"),
            "IntentCurrentBlockHeight.runar.ts"
        );
        WitnessContext witness = new WitnessContext()
            .setMockPreimage("locktime", BigInteger.valueOf(500_000L));

        ExecutionResult r = AnfInterpreter.executeStrict(
            anf,
            "spend",
            Map.of("count", BigInteger.ZERO),
            Map.of(),
            List.of(BigInteger.valueOf(1_000_000L), BigInteger.ZERO),
            witness
        );
        assertEquals(BigInteger.ONE, r.newState.get("count"));
    }

    @Test
    void intentCurrentBlockHeight_failureLocktimePastDeadline() throws Exception {
        Map<String, Object> anf = compile(
            src("intent-current-block-height", "IntentCurrentBlockHeight.runar.ts"),
            "IntentCurrentBlockHeight.runar.ts"
        );
        WitnessContext witness = new WitnessContext()
            .setMockPreimage("locktime", BigInteger.valueOf(999_999L));

        AssertionFailureException ex = assertThrows(
            AssertionFailureException.class,
            () -> AnfInterpreter.executeStrict(
                anf,
                "spend",
                Map.of("count", BigInteger.ZERO),
                Map.of(),
                List.of(BigInteger.valueOf(100L), BigInteger.ZERO),
                witness
            )
        );
        assertTrue(ex.getMessage().toLowerCase().contains("assert"), ex.getMessage());
    }

    // ==================================================================
    // branched-readonly-len  (both arms succeed)
    // ==================================================================

    @Test
    void branchedReadonlyLen_thenBranch() throws Exception {
        Map<String, Object> anf = compile(
            src("branched-readonly-len", "BranchedReadonlyLen.runar.ts"),
            "BranchedReadonlyLen.runar.ts"
        );
        // Stateful contract: strict mode mocks check_preimage only when a
        // WitnessContext is supplied (i.e. the caller is simulating a concrete
        // spend). An empty context is enough here — this contract uses no
        // intent intrinsics, so no prevOutScript / serialisedOutputs bytes are
        // needed; the context's presence is the "simulate a real spend" signal.
        ExecutionResult r = AnfInterpreter.executeStrict(
            anf,
            "spend",
            Map.of("count", BigInteger.TEN, "tag", "00"),
            Map.of("scratch", "aabbcc"),
            List.of(BigInteger.TEN, "00"),
            new WitnessContext()
        );
        assertEquals(BigInteger.valueOf(11), r.newState.get("count"));
        assertEquals("aabbcc", r.newState.get("tag"));
    }

    @Test
    void branchedReadonlyLen_elseBranch() throws Exception {
        Map<String, Object> anf = compile(
            src("branched-readonly-len", "BranchedReadonlyLen.runar.ts"),
            "BranchedReadonlyLen.runar.ts"
        );
        // Empty WitnessContext: signals "simulate a concrete spend" so strict
        // mode mocks the on-chain-only check_preimage prologue assert. See the
        // then-branch test for the rationale.
        ExecutionResult r = AnfInterpreter.executeStrict(
            anf,
            "spend",
            Map.of("count", BigInteger.TEN, "tag", "aa"),
            Map.of("scratch", ""),
            List.of(BigInteger.TEN, "aa"),
            new WitnessContext()
        );
        assertEquals(BigInteger.valueOf(9), r.newState.get("count"));
        assertEquals("3030", r.newState.get("tag"));
    }
}
