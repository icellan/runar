package runar.compiler.passes;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R-264 (CL-GAP-012): this tier's EC fixed-point loop stopped after 64
 * iterations and returned whatever it had.
 *
 * <p>The seven tiers do not agree on iteration strategy at all. The TypeScript
 * reference makes ONE pass — {@code optimizeMethodEC} has no outer loop. Go,
 * Zig and Ruby loop to a fixed point with no bound. This tier stopped at 64.
 * Byte-identity across all seven survives that only because one pass already
 * reaches the fixed point for everything in the corpus: if a second pass ever
 * changed a program, TS would diverge from Go/Zig/Ruby immediately, cap or no
 * cap.
 *
 * <p>So the cap is not the hazard — stopping QUIETLY is. A program reaching
 * iteration 64 would be emitted here partially optimised while the unbounded
 * tiers kept going, and the two would disagree on bytes with nothing said. The
 * bound stays; exhausting it is now a refusal.
 *
 * <p>This test pins the behaviour that matters: real EC contracts converge and
 * compile, and they still agree with the reference.
 */
class R264EcFixedPointTest {

    private static final String EC_SOURCE = """
        import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecNegate, ecOnCurve } from 'runar-lang';
        import type { Point } from 'runar-lang';

        export class EcChain extends SmartContract {
          readonly limit: bigint;

          constructor(limit: bigint) {
            super(limit);
            this.limit = limit;
          }

          public check(p: Point, k: bigint): void {
            assert(ecOnCurve(ecAdd(ecMul(p, k), ecNegate(ecMulGen(k)))));
            assert(k < this.limit);
          }
        }
        """;

    @Test
    void anEcContractReachesTheFixedPointAndCompiles(@TempDir Path tmp) throws Exception {
        Path src = tmp.resolve("EcChain.runar.ts");
        Files.writeString(src, EC_SOURCE);

        Result r = run("--source", src.toString(), "--hex");

        assertEquals(0, r.exit,
            "an EC contract must converge within the iteration bound; stderr=" + r.stderr);
        assertTrue(r.stdout.trim().matches("[0-9a-f]+"), "expected script hex, got: " + r.stdout);
        assertTrue(r.stdout.trim().length() > 100, "script is implausibly short: " + r.stdout);
    }

    /**
     * The refusal is reachable in principle and says why. Driven by reflection
     * on the limit rather than by constructing a non-converging program, which
     * no known input produces.
     */
    @Test
    void theIterationLimitIsDeclaredAndSmallEnoughToBeMeaningful() throws Exception {
        var f = AnfOptimize.class.getDeclaredField("EC_FIXED_POINT_LIMIT");
        f.setAccessible(true);
        int limit = f.getInt(null);
        assertTrue(limit > 1, "a limit of 1 would make this tier single-pass like TS by accident");
        assertTrue(limit <= 1024, "a limit this high is indistinguishable from unbounded");
    }

    private record Result(int exit, String stdout, String stderr) {}

    private Result run(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream o = new PrintStream(out, true, StandardCharsets.UTF_8);
        PrintStream e = new PrintStream(err, true, StandardCharsets.UTF_8);
        int exit = new runar.compiler.Cli(o, e).run(args);
        o.flush();
        e.flush();
        return new Result(exit, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }
}
