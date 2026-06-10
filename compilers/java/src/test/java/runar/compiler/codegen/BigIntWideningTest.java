package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.canonical.Jcs;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.stack.BigIntPushValue;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.passes.AnfLoader;
import runar.compiler.passes.Emit;

/**
 * Verifies that {@code BigIntLiteral} now carries arbitrary precision
 * through the entire Java pipeline (parse &rarr; IR JSON &rarr; codegen),
 * which is what lets the Java tier drop out of the {@code schnorr-zkp}
 * conformance allowlist.
 *
 * <p>The canonical secp256k1 group order
 * {@code 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}
 * is used as the load-bearing 256-bit literal. Earlier revisions of the
 * Java TS parser clamped numeric literals to int64 and silently emitted
 * {@code OP_0} for values outside that range, which produced bogus hex
 * for the {@code assert(within(s, 1n, EC_N))} malleability gate.
 */
class BigIntWideningTest {

    /** The secp256k1 group order — 256 bits, way beyond int64. */
    private static final BigInteger EC_N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    /**
     * The canonical Bitcoin Script little-endian sign-magnitude encoding
     * of {@link #EC_N} is 33 bytes (the high bit of the MSB is set, so a
     * sign byte 0x00 is appended). The push instruction is therefore
     * {@code 21} (push 33 bytes) followed by the LE-encoded value.
     */
    private static final String EXPECTED_EC_N_PUSH =
        "21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00";

    @Test
    void encodes256BitPushIdentically() {
        String hex = Emit.encodePushBigIntHex(EC_N);
        assertEquals(EXPECTED_EC_N_PUSH, hex,
            "256-bit EC_N must encode as a 33-byte LE sign-magnitude push");
    }

    @Test
    void roundTripsThroughStackProgram() {
        StackProgram p = new StackProgram("T", List.of(
            new StackMethod("unlock",
                List.<StackOp>of(new PushOp(new BigIntPushValue(EC_N))),
                0L)
        ));
        String hex = Emit.run(p);
        assertEquals(EXPECTED_EC_N_PUSH, hex);
    }

    @Test
    void canonicalIrEncodesOversizeAsQuotedNSuffix() {
        // Values that fit in JS Number.MAX_SAFE_INTEGER round-trip as bare
        // JSON integers; oversize bigints get the canonical `n` suffix.
        BigIntConst big = new BigIntConst(EC_N);
        Object raw = big.raw();
        assertTrue(raw instanceof String, "EC_N must serialise as a String, got " + raw.getClass());
        assertEquals(EC_N.toString(10) + "n", raw);

        BigIntConst small = new BigIntConst(BigInteger.valueOf(42));
        assertTrue(small.raw() instanceof BigInteger,
            "42 must serialise as a bare BigInteger, got " + small.raw().getClass());

        BigIntConst maxSafe = new BigIntConst(BigInteger.valueOf(9007199254740991L));
        assertTrue(maxSafe.raw() instanceof BigInteger);

        BigIntConst overSafe = new BigIntConst(BigInteger.valueOf(9007199254740992L));
        assertTrue(overSafe.raw() instanceof String);
        assertEquals("9007199254740992n", overSafe.raw());

        BigIntConst negOverSafe = new BigIntConst(BigInteger.valueOf(-9007199254740992L));
        assertTrue(negOverSafe.raw() instanceof String);
        assertEquals("-9007199254740992n", negOverSafe.raw());
    }

    @Test
    void canonicalJsonEmitsNSuffixForOversizeBigInt() {
        String json = Jcs.stringify(new BigIntConst(EC_N));
        assertEquals('"', json.charAt(0));
        assertTrue(json.endsWith("n\""),
            "oversize bigint must be quoted with trailing 'n', got " + json);
        assertTrue(json.contains(EC_N.toString(10)));
    }

    @Test
    void anfLoaderDecodesNSuffixStringAsBigInt() {
        // Hand-crafted minimal ANF program with a 256-bit constant carried
        // as a quoted "...n" string in the load_const value position.
        String irJson = "{\n"
            + "  \"contractName\": \"T\",\n"
            + "  \"properties\": [],\n"
            + "  \"methods\": [\n"
            + "    {\n"
            + "      \"name\": \"verify\",\n"
            + "      \"isPublic\": true,\n"
            + "      \"params\": [],\n"
            + "      \"body\": [\n"
            + "        { \"name\": \"t0\", \"value\": { \"kind\": \"load_const\", \"value\": \""
            + EC_N.toString(10) + "n\" } }\n"
            + "      ]\n"
            + "    }\n"
            + "  ]\n"
            + "}";
        var prog = AnfLoader.parse(irJson);
        var body = prog.methods().get(0).body();
        assertEquals(1, body.size());
        var v = body.get(0).value();
        assertNotNull(v);
        // Round-trip via Jcs gives back the same `n`-suffix encoding.
        String round = Jcs.stringify(v);
        assertTrue(round.contains(EC_N.toString(10) + "n"),
            "round-trip must preserve EC_N as `...n`, got " + round);
    }

    @Test
    void anfLoaderStillTreatsHexStringAsBytestring() {
        // A hex string without trailing `n` must remain a ByteString literal,
        // not be mis-decoded as a base-N decimal integer.
        String irJson = "{\n"
            + "  \"contractName\": \"T\",\n"
            + "  \"properties\": [],\n"
            + "  \"methods\": [\n"
            + "    { \"name\": \"verify\", \"isPublic\": true, \"params\": [],\n"
            + "      \"body\": [\n"
            + "        { \"name\": \"t0\", \"value\": { \"kind\": \"load_const\", \"value\": \"deadbeef\" } }\n"
            + "      ]\n"
            + "    }\n"
            + "  ]\n"
            + "}";
        var prog = AnfLoader.parse(irJson);
        String round = Jcs.stringify(prog.methods().get(0).body().get(0).value());
        assertTrue(round.contains("\"deadbeef\""),
            "bare hex must stay a ByteString, got " + round);
        assertFalse(round.contains("deadbeefn"));
    }

    @Test
    void schnorrZkpHexIsByteIdenticalToReference() throws Exception {
        // The conformance fixture lives at conformance/tests/schnorr-zkp.
        // Tests run from the compilers/java module root, so escape two
        // levels up.
        Path repoRoot = Path.of("..", "..").toAbsolutePath().normalize();
        Path source = repoRoot.resolve(
            "examples/ts/schnorr-zkp/SchnorrZKP.runar.ts");
        Path expectedHex = repoRoot.resolve(
            "conformance/tests/schnorr-zkp/expected-script.hex");
        if (!Files.exists(source) || !Files.exists(expectedHex)) {
            // Skip silently when the test is run outside the repo tree.
            return;
        }
        String expected = Files.readString(expectedHex).strip();
        // Drive the full Java pipeline programmatically so we don't need
        // a built jar on the classpath.
        String src = Files.readString(source);
        var ast = runar.compiler.frontend.TsParser.parse(src, source.toString());
        runar.compiler.passes.Validate.run(ast);
        runar.compiler.passes.Typecheck.run(ast);
        var anf = runar.compiler.passes.AnfLower.run(ast);
        // Match the canonical fold-OFF goldens (Cli passes --disable-constant-folding).
        anf = runar.compiler.Cli.optimizeAnf(anf, true);
        var stack = runar.compiler.passes.StackLower.run(anf);
        var opt = runar.compiler.passes.Peephole.run(stack);
        String hex = runar.compiler.passes.Emit.run(opt);
        assertEquals(expected, hex,
            "Java schnorr-zkp hex must byte-match the conformance reference");
    }
}
