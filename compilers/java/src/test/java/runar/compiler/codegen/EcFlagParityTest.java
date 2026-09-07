package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.passes.Emit;

/**
 * Cross-tier parity for the EXPERIMENTAL EC size flags.
 *
 * <p>The flags default off, so the ordinary conformance suite — which compiles with defaults —
 * cannot see them at all. Seven tiers could each ship a DIFFERENT {@code --ec-constant-pool} and the
 * suite would stay green.
 *
 * <p>That matters because the flags are not cosmetic: they change which reduction form is emitted
 * and which addition formula each ladder round uses. A tier that ports the constant pool but not the
 * sign lattice's {@code REDUCED} precondition produces a script that is smaller, passes its own
 * tests, and is wrong on {@code ecAdd((0,1), (2^256-1,1))}. Byte-identical output against a single
 * reference is the only cheap check that catches that.
 *
 * <p>{@code conformance/ec-flag-parity/expected.json} is derived from the TypeScript reference
 * compiler and re-derived by its own vitest, so it cannot go stale.
 */
class EcFlagParityTest {

    /** Emitters the flags cannot reach still take an (ignored) options argument here.
     *
     * <p>They are deliberately included: a tier that accidentally made {@code ecModReduce} or
     * {@code ecPointX} flag-sensitive would be diverging just as badly as one that ignored a flag.
     */
    private static BiConsumer<Consumer<StackOp>, Ec.EcCodegenOptions> ignoreOpts(
            Consumer<Consumer<StackOp>> f) {
        return (e, o) -> f.accept(e);
    }

    private static Map<String, BiConsumer<Consumer<StackOp>, Ec.EcCodegenOptions>> emitters() {
        Map<String, BiConsumer<Consumer<StackOp>, Ec.EcCodegenOptions>> m = new LinkedHashMap<>();
        m.put("EcAdd", Ec::emitEcAdd);
        m.put("EcMul", Ec::emitEcMul);
        m.put("EcMulGen", Ec::emitEcMulGen);
        m.put("EcNegate", Ec::emitEcNegate);
        m.put("EcOnCurve", Ec::emitEcOnCurve);
        m.put("EcModReduce", ignoreOpts(Ec::emitEcModReduce));
        m.put("EcEncodeCompressed", ignoreOpts(Ec::emitEcEncodeCompressed));
        m.put("EcMakePoint", ignoreOpts(Ec::emitEcMakePoint));
        m.put("EcPointX", ignoreOpts(Ec::emitEcPointX));
        m.put("EcPointY", ignoreOpts(Ec::emitEcPointY));
        m.put("P256Add", P256P384::emitP256Add);
        m.put("P256Mul", P256P384::emitP256Mul);
        m.put("P256MulGen", P256P384::emitP256MulGen);
        m.put("P256Negate", P256P384::emitP256Negate);
        m.put("P256OnCurve", P256P384::emitP256OnCurve);
        m.put("P256EncodeCompressed", ignoreOpts(P256P384::emitP256EncodeCompressed));
        m.put("VerifyECDSA_P256", P256P384::emitVerifyECDSA_P256);
        m.put("P384Add", P256P384::emitP384Add);
        m.put("P384Mul", P256P384::emitP384Mul);
        m.put("P384MulGen", P256P384::emitP384MulGen);
        m.put("P384Negate", P256P384::emitP384Negate);
        m.put("P384OnCurve", P256P384::emitP384OnCurve);
        m.put("P384EncodeCompressed", ignoreOpts(P256P384::emitP384EncodeCompressed));
        m.put("VerifyECDSA_P384", P256P384::emitVerifyECDSA_P384);
        return m;
    }

    /** The four flag combinations the fixture pins, in its own order. */
    private static final String[] VARIANTS = {"off", "pool", "sink", "comb"};

    private static Ec.EcCodegenOptions optionsFor(String variant) {
        return switch (variant) {
            case "off" -> null;
            case "pool" -> new Ec.EcCodegenOptions(true, false, false);
            case "sink" -> new Ec.EcCodegenOptions(true, true, false);
            case "comb" -> new Ec.EcCodegenOptions(true, true, true);
            default -> throw new IllegalArgumentException("unknown variant " + variant);
        };
    }

    private static Path fixturePath() {
        // src/test/java/runar/compiler/codegen -> compilers/java -> compilers -> repo root
        return Path.of(System.getProperty("user.dir"))
                .resolve("../../conformance/ec-flag-parity/expected.json")
                .normalize();
    }

    /**
     * Pull {@code {"bytes": N, "sha256": "..."}} for one (emitter, variant) out of the fixture.
     *
     * <p>Hand-rolled rather than pulling in a JSON dependency: this module has none, and the shape
     * is a fixed two-level map written by {@code JSON.stringify(..., 2)}. The scan is anchored on
     * the emitter's key so {@code EcMul} cannot match inside {@code EcMulGen}.
     */
    private static int[] lookupBytes(String json, String emitter, String variant) {
        int at = json.indexOf("\"" + emitter + "\": {");
        if (at < 0) {
            throw new AssertionError(emitter + ": no entry in the parity fixture");
        }
        int vAt = json.indexOf("\"" + variant + "\": {", at);
        if (vAt < 0) {
            throw new AssertionError(emitter + "/" + variant + ": no entry in the parity fixture");
        }
        int bAt = json.indexOf("\"bytes\":", vAt);
        int comma = json.indexOf(',', bAt);
        int bytes = Integer.parseInt(json.substring(bAt + 8, comma).trim());
        return new int[] {bytes, vAt};
    }

    private static String lookupHash(String json, String emitter, String variant) {
        int vAt = lookupBytes(json, emitter, variant)[1];
        int hAt = json.indexOf("\"sha256\":", vAt);
        int q1 = json.indexOf('"', hAt + 9);
        int q2 = json.indexOf('"', q1 + 1);
        return json.substring(q1 + 1, q2);
    }

    private static int[] emitAndSize(
            BiConsumer<Consumer<StackOp>, Ec.EcCodegenOptions> fn, Ec.EcCodegenOptions opts) {
        List<StackOp> ops = new ArrayList<>();
        fn.accept(ops::add, opts);
        String hex =
                Emit.run(new StackProgram("t", List.of(new StackMethod("t", ops, 0L))));
        return new int[] {hex.length() / 2};
    }

    private static String emitAndHash(
            BiConsumer<Consumer<StackOp>, Ec.EcCodegenOptions> fn, Ec.EcCodegenOptions opts) {
        List<StackOp> ops = new ArrayList<>();
        fn.accept(ops::add, opts);
        String hex =
                Emit.run(new StackProgram("t", List.of(new StackMethod("t", ops, 0L))));
        byte[] raw = new byte[hex.length() / 2];
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(raw);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Test
    void ecFlagParityAgainstTypeScriptReference() throws Exception {
        String json = Files.readString(fixturePath());
        for (Map.Entry<String, BiConsumer<Consumer<StackOp>, Ec.EcCodegenOptions>> en :
                emitters().entrySet()) {
            String name = en.getKey();
            for (String variant : VARIANTS) {
                Ec.EcCodegenOptions opts = optionsFor(variant);
                int wantBytes = lookupBytes(json, name, variant)[0];
                String wantHash = lookupHash(json, name, variant);
                int gotBytes = emitAndSize(en.getValue(), opts)[0];
                String gotHash = emitAndHash(en.getValue(), opts);
                assertEquals(
                        wantBytes,
                        gotBytes,
                        name + " under " + variant + ": Java and the TypeScript reference disagree"
                                + " on size");
                assertEquals(
                        wantHash,
                        gotHash,
                        name + " under " + variant + ": Java and the TypeScript reference disagree"
                                + " on bytes");
            }
        }
    }

    /**
     * A {@code null} options argument must be byte-identical to the shipping output. This is what
     * keeps the existing goldens, the size baseline and every cross-tier hex comparison from moving
     * while the flags are experimental.
     */
    @Test
    void ecFlagsDefaultOffIsByteIdentical() throws Exception {
        String json = Files.readString(fixturePath());
        for (Map.Entry<String, BiConsumer<Consumer<StackOp>, Ec.EcCodegenOptions>> en :
                emitters().entrySet()) {
            String name = en.getKey();
            String noneHash = emitAndHash(en.getValue(), null);
            String offHash =
                    emitAndHash(en.getValue(), new Ec.EcCodegenOptions(false, false, false));
            assertEquals(noneHash, offHash, name + ": null and all-false options disagree");
            assertEquals(
                    lookupHash(json, name, "off"), noneHash, name + ": default output moved");
        }
    }

    /**
     * The fixture must actually be reachable, and must really carry all four variants for a
     * flag-sensitive emitter — otherwise both tests above could pass vacuously.
     */
    @Test
    void fixtureIsPresentAndNonVacuous() throws Exception {
        String json = Files.readString(fixturePath());
        assertNotNull(json);
        // The reference genuinely diverges under the flags; a fixture where every
        // variant hashed the same would pass in a tier that ignored them entirely.
        assertNotEquals(
                lookupHash(json, "EcMul", "off"),
                lookupHash(json, "EcMul", "pool"),
                "fixture is vacuous: the pool flag does not move EcMul");
        assertNotEquals(
                lookupHash(json, "EcMulGen", "sink"),
                lookupHash(json, "EcMulGen", "comb"),
                "fixture is vacuous: the comb flag does not move EcMulGen");
        // `ecMul` takes its base at run time, so the comb cannot apply there.
        assertEquals(
                lookupHash(json, "EcMul", "sink"),
                lookupHash(json, "EcMul", "comb"),
                "the comb must not fire where the base is not a compile-time constant");
    }
}
