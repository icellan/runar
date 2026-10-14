package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import runar.compiler.Cli;

/**
 * N-264: call depth x nesting must not overflow the host stack.
 *
 * <p>Private methods are inlined at every call site, so F-213's per-method
 * nesting bound (128) and N-180's call-depth bound (128) compose
 * multiplicatively: a chain of D helpers that each call the next under K nested
 * ifs is D*K nested ifs after inlining. This tier threw an uncaught
 * {@code StackOverflowError} at D=16 x 120 (stack lowering recursed once per
 * nested if). User decision R106: lower iteratively, with an explicit work stack.
 *
 * <p>The source is remediation-logs/N-180/compgen.py's shape. The pinned digests
 * are sha256 of the script hex the UNMODIFIED Go compiler printed for the same
 * source (at 5b75534ec, before any N-264 change): goroutine stacks grow, so Go
 * compiled every depth, and its D=8 output was byte-identical to all six other
 * tiers'.
 *
 * <p>Proves: the CLI compiles D=32 x 120 (3,840 nested ifs) and the deepest
 * admissible chain D=127 x 120 on the default thread stack, byte-identical to
 * Go. Does not prove: the other tiers
 * (conformance/negatives/n264-composite-nesting-parity.test.ts drives all seven
 * CLIs), nor that Go's deep output is right beyond agreeing at D=8.
 */
class N264CompositeNestingTest {

    /** remediation-logs/N-180/compgen.py, verbatim. */
    private static String comp(int d, int k) {
        StringBuilder b = new StringBuilder();
        b.append("import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n");
        for (int i = 0; i < d; i++) {
            b.append(" private m").append(i).append("(x: bigint): bigint {\n");
            b.append("  let r: bigint = x;\n");
            for (int j = 0; j < k; j++) b.append("  if (x > ").append(j).append("n) {\n");
            b.append("  r = this.m").append(i + 1).append("(x);\n");
            for (int j = 0; j < k; j++) b.append("  }\n");
            b.append("  return r;\n }\n");
        }
        b.append(" private m").append(d).append("(x: bigint): bigint { return x; }\n public verify(a: bigint) { assert(this.m0(a) == this.t); }\n}\n");
        return b.toString();
    }

    private static String compileHex(Path dir, int d) throws Exception {
        Path src = dir.resolve("comp" + d + "k120.runar.ts");
        Files.writeString(src, comp(d, 120));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int rc = new Cli(new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8))
            .run(new String[] {"--source", src.toString(), "--hex"});
        assertEquals(0, rc, () -> err.toString(StandardCharsets.UTF_8));
        return out.toString(StandardCharsets.UTF_8).trim();
    }

    private static String sha256(String s) throws Exception {
        return HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void compilesD32x120ByteIdenticalToGo(@TempDir Path dir) throws Exception {
        assertEquals("edf53286692322f6787832929bb6aaf18d2b686e9bef2ad4683cbaf3e8a25fc2",
            sha256(compileHex(dir, 32)));
    }

    @Test
    void compilesD127x120ByteIdenticalToGo(@TempDir Path dir) throws Exception {
        assertEquals("d1a30af5609fe4b5704c58f518cb9bdd1f31fce14df88c650dcf33fe25153c53",
            sha256(compileHex(dir, 127)));
    }
}
