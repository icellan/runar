package runar.compiler;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-130: on the {@code .runar.java} surface this tier refused every compound
 * assignment ({@code this.x += ...} -> "unsupported expression kind
 * PLUS_ASSIGNMENT"), while the TS reference ({@code 01-parse-java.ts},
 * {@code finishExpressionStatement}) lowers {@code t op= e} to
 * {@code t = t op e} for {@code + - * / % & | ^ << >>}.
 *
 * <p>What this proves: the Java tier compiles {@code .runar.java} sources using
 * all ten compound operators (on a local, on a bigint property and on a
 * ByteString property) to the exact script the TS reference CLI emits for the
 * same files. The pinned digests were produced with
 * {@code runar-cli compile <file> --ir} (default flags, constant folding on)
 * at cdf4c873; for ARITH the Go, Rust, Python, Zig and Ruby tiers emit the
 * same digest. It also proves a bare {@code count += ...} is still refused,
 * now with the N-023 shared diagnostic rather than a blanket refusal; that a
 * unit-step {@code i += Bigint.ONE} for-update compiles like {@code i++}; and
 * that a compound state write or non-unit step in the for-update slot
 * (negatives N167/N168) is still refused, now by the loop-update rule.
 *
 * <p>What it does NOT prove: that the bitwise/shift compound forms
 * ({@code &= |= ^= <<= >>=}) agree across the other five tiers (their
 * {@code .runar.java} parsers refuse them today; only TS and Java accept),
 * on-chain execution of the result, or the fold-off byte stream.
 */
class N130CompoundAssignTest {

    private static final String HEADER = """
        package p;

        import runar.lang.StatefulSmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.types.Bigint;
        import runar.lang.types.ByteString;

        import static runar.lang.Builtins.assertThat;

        """;

    private static String contract(String name, String body) {
        return HEADER
            + "class " + name + " extends StatefulSmartContract {\n"
            + "    Bigint count;\n"
            + "    ByteString tag;\n\n"
            + "    " + name + "(Bigint count, ByteString tag) {\n"
            + "        super(count, tag);\n"
            + "        this.count = count;\n"
            + "        this.tag = tag;\n"
            + "    }\n\n"
            + "    @Public\n"
            + "    void step(Bigint d, ByteString m) {\n"
            + body
            + "        assertThat(this.count > 0);\n"
            + "    }\n"
            + "}\n";
    }

    private static final String ARITH_BODY = """
                Bigint t = d;
                t += 3;
                this.count += t;
                this.count -= 1;
                this.count *= 2;
                this.count /= 3;
                this.count %= 1000;
        """;

    private static final String BITWISE_BODY = """
                this.count <<= 2;
                this.count >>= 1;
                this.count &= 255;
                this.count |= 16;
                this.count ^= 5;
                this.tag &= m;
                this.tag |= m;
                this.tag ^= m;
        """;

    /** sha256 of the TS reference script hex for Arith.runar.java. */
    private static final String ARITH_TS_SHA256 =
        "211acb3712ea3a082c1657e21485f4d1176a2c480847d1622eaac31fc12b37fc";
    private static final int ARITH_TS_HEX_LEN = 1804;

    /** sha256 of the TS reference script hex for Compound.runar.java. */
    private static final String COMPOUND_TS_SHA256 =
        "a66871ae82eb652992f39ef9f8ef7f6474cf92bc424776d344127ec843643fce";
    private static final int COMPOUND_TS_HEX_LEN = 1880;

    @Test
    void arithmeticCompoundAssignmentsMatchTheTsReference(@TempDir Path tmp) throws Exception {
        String hex = hexOf(tmp, "Arith.runar.java", contract("Arith", ARITH_BODY));
        assertEquals(ARITH_TS_HEX_LEN, hex.length(), "script length differs from TS: " + hex);
        assertEquals(ARITH_TS_SHA256, sha256(hex), "script differs from TS: " + hex);
    }

    @Test
    void allTenCompoundOperatorsMatchTheTsReference(@TempDir Path tmp) throws Exception {
        String hex = hexOf(tmp, "Compound.runar.java", contract("Compound", ARITH_BODY + BITWISE_BODY));
        assertEquals(COMPOUND_TS_HEX_LEN, hex.length(), "script length differs from TS: " + hex);
        assertEquals(COMPOUND_TS_SHA256, sha256(hex), "script differs from TS: " + hex);
    }

    /** {@code this.x op= e} must lower exactly like the spelled-out {@code this.x = this.x op e}. */
    @Test
    void compoundFormEqualsTheExpandedForm(@TempDir Path tmp) throws Exception {
        String expanded = ARITH_BODY
            .replace("t += 3;", "t = t + 3;")
            .replace("this.count += t;", "this.count = this.count + t;")
            .replace("this.count -= 1;", "this.count = this.count - 1;")
            .replace("this.count *= 2;", "this.count = this.count * 2;")
            .replace("this.count /= 3;", "this.count = this.count / 3;")
            .replace("this.count %= 1000;", "this.count = this.count % 1000;");
        assertNotEquals(ARITH_BODY, expanded, "control source was not rewritten");
        assertEquals(
            hexOf(tmp, "Expanded.runar.java", contract("Arith", expanded)),
            hexOf(tmp, "Arith.runar.java", contract("Arith", ARITH_BODY)));
    }

    /** N-023 still owns the bare form: {@code count += x} writes the field in Java. */
    @Test
    void bareCompoundPropertyWriteIsRefusedWithTheN023Diagnostic(@TempDir Path tmp) throws Exception {
        Path p = tmp.resolve("Bare.runar.java");
        Files.writeString(p, contract("Bare", "        count += d;\n"));
        Result r = run("--source", p.toString(), "--hex");
        assertNotEquals(0, r.exit, "bare compound property write compiled: " + r.stdout);
        assertTrue(
            r.stderr.contains("bare assignment to property 'count' is not allowed; write `this.count = ...`"),
            "expected the N-023 diagnostic, got: " + r.stderr);
    }

    private static String loop(String name, String update) {
        return contract(name,
            "        for (Bigint i = Bigint.ZERO; i.lt(Bigint.TWO); " + update + ") {\n"
                + "            this.count = this.count.plus(Bigint.ONE);\n"
                + "        }\n");
    }

    /** sha256 of the TS reference script hex for the unit-step loop (all 7 tiers agree). */
    // N-216 (2026-10-21): re-pinned; one lowerUpdateProp `OP_2 OP_ROLL` now folds to OP_ROT (886 -> 885 B).
    private static final String UNIT_LOOP_TS_SHA256 =
        "6993bf337af1e5f184d954514ffb1b254e45e6001400fda896ff92022ba664e9";

    /** A unit-step {@code i += Bigint.ONE} loop update compiles exactly like {@code i++}. */
    @Test
    void unitStepCompoundLoopUpdateMatchesTheTsReference(@TempDir Path tmp) throws Exception {
        String hex = hexOf(tmp, "ForUnit.runar.java", loop("ForUnit", "i += Bigint.ONE"));
        assertEquals(UNIT_LOOP_TS_SHA256, sha256(hex), "script differs from TS: " + hex);
        assertEquals(hex, hexOf(tmp, "ForInc.runar.java", loop("ForInc", "i++")));
    }

    /**
     * With the blanket refusal gone, the loop-update rule must still refuse a
     * compound state write and a non-unit step in the for-update slot
     * (conformance/negatives N167, N168), with the TS reference diagnostic.
     */
    @Test
    void nonUnitOrStateCompoundLoopUpdatesAreRefusedByTheLoopRule(@TempDir Path tmp) throws Exception {
        String[] updates = {"this.count += Bigint.ONE", "i += Bigint.TWO", "i -= Bigint.TWO", "i *= Bigint.ONE"};
        int n = 0;
        for (String u : updates) {
            Path p = tmp.resolve("Bad" + n + ".runar.java");
            Files.writeString(p, loop("Bad" + n, u));
            n++;
            Result r = run("--source", p.toString(), "--hex");
            assertNotEquals(0, r.exit, u + " compiled: " + r.stdout);
            assertTrue(r.stderr.contains("For loop update must advance the loop variable by one"),
                u + ": expected the loop-update diagnostic, got: " + r.stderr);
        }
    }

    private static String sha256(String s) throws Exception {
        return HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.US_ASCII)));
    }

    private String hexOf(Path dir, String name, String body) throws Exception {
        Path p = dir.resolve(name);
        Files.writeString(p, body);
        Result r = run("--source", p.toString(), "--hex");
        assertEquals(0, r.exit, name + " failed to compile: " + r.stderr);
        return r.stdout.trim();
    }

    private record Result(int exit, String stdout, String stderr) {}

    private Result run(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream o = new PrintStream(out, true, StandardCharsets.UTF_8);
        PrintStream e = new PrintStream(err, true, StandardCharsets.UTF_8);
        int exit = new Cli(o, e).run(args);
        o.flush();
        e.flush();
        return new Result(exit, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }
}
