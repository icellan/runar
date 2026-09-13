package runar.compiler;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R-298 (CL-GAP-093): the early-return-nesting rewrite in AnfLower keys on
 * {@code elseBody() == null}, so an {@code if} carrying an EMPTY else-list is
 * treated as "has an else" and the rewrite never fires.
 *
 * <p>The reviewer filed this as LOW and conditional — "a structural ANF
 * divergence IF any parser emits {@code else: []}". One does, deliberately:
 * {@code SolParser.parseIf} mapped a missing else to {@code List.of()} to match
 * the Python reference's {@code else_=[]}, while the Java AST's own convention
 * (which the same comment acknowledges) is that {@code null} means "no else".
 *
 * <p>The consequence is not structural. With the rewrite suppressed,
 *
 * <pre>
 *   function pick(bigint v) private returns (bigint) {
 *       if (v == 1) { return 7; }
 *       return 9;
 *   }
 * </pre>
 *
 * lowers on the {@code .runar.sol} surface to {@code if cond then [7] else []}
 * followed by a SEPARATE {@code load_const 9} — so the method's result is the
 * trailing binding and {@code pick(1)} answers 9. The same source on the
 * {@code .runar.ts} and {@code .runar.move} surfaces, and on all six peer
 * tiers, answers 7.
 *
 * <p>It reaches real code: examples/sol/tic-tac-toe/TicTacToe.runar.sol has
 * been checked in for a long time and its {@code checkWinAfterMove} is exactly
 * this shape, so in this tier nobody could ever win.
 */
class R298EmptyElseEarlyReturnTest {

    private static final String SOL = """
        pragma runar ^0.1.0;

        contract P is StatefulSmartContract {
            bigint a = 0;

            constructor() {}

            function set(bigint v) public {
                this.a = this.pick(v);
            }

            function pick(bigint v) private returns (bigint) {
                if (v == 1) { return 7; }
                return 9;
            }
        }
        """;

    private static final String TS = """
        import { StatefulSmartContract } from 'runar-lang';

        export class P extends StatefulSmartContract {
          a: bigint = 0n;

          constructor() {
            super();
          }

          public set(v: bigint): void {
            this.a = this.pick(v);
          }

          private pick(v: bigint): bigint {
            if (v == 1n) { return 7n; }
            return 9n;
          }
        }
        """;

    private static final String MOVE = """
        module P {
            use runar::StatefulSmartContract;

            resource struct P {
                a: &mut bigint = 0,
            }

            public fun set(v: bigint) {
                self.a = self.pick(v);
            }

            fun pick(v: bigint): bigint {
                if (v == 1) { return 7; }
                return 9;
            }
        }
        """;

    @Test
    void everySurfaceLowersAnEarlyReturnTheSameWay(@TempDir Path tmp) throws Exception {
        String ts = hexOf(tmp, "P.runar.ts", TS);
        String sol = hexOf(tmp, "P.runar.sol", SOL);
        String move = hexOf(tmp, "P.runar.move", MOVE);

        assertEquals(ts, sol,
            "the .runar.sol surface lowers `if (c) { return A; } return B;` differently "
                + "from .runar.ts — the trailing return is not folded into the else");
        assertEquals(ts, move, ".runar.move diverged too");
    }

    @Test
    void theTrailingReturnIsFoldedIntoTheElseBranch(@TempDir Path tmp) throws Exception {
        String ir = irOf(tmp, "P.runar.sol", SOL);

        // The `if` must carry the trailing return as its else, and nothing may
        // follow it: a binding after the `if` IS the wrong answer, because it
        // becomes the method's result.
        assertTrue(
            ir.contains("\"else\":[{"),
            "the if has an empty else, so the trailing return was left outside it: " + ir);
        assertTrue(
            !ir.contains("\"else\":[]"),
            "an empty else-list survived lowering; the early-return rewrite did not fire");
    }

    /** Control: a real if/else was never affected and must stay unchanged. */
    @Test
    void anExplicitElseStillWorks(@TempDir Path tmp) throws Exception {
        String withElse = SOL.replace(
            "if (v == 1) { return 7; }\n        return 9;",
            "if (v == 1) { return 7; } else { return 9; }");
        assertNotEquals(withElse, SOL, "the control source was not rewritten");

        assertEquals(
            hexOf(tmp, "Ctl.runar.ts", TS.replace(
                "if (v == 1n) { return 7n; }\n    return 9n;",
                "if (v == 1n) { return 7n; } else { return 9n; }")),
            hexOf(tmp, "Ctl.runar.sol", withElse),
            "an explicit else must lower identically on both surfaces");
    }

    private String hexOf(Path dir, String name, String body) throws Exception {
        Path p = dir.resolve(name);
        Files.writeString(p, body);
        Result r = run("--source", p.toString(), "--hex");
        assertEquals(0, r.exit, name + " failed to compile: " + r.stderr);
        return r.stdout.trim();
    }

    private String irOf(Path dir, String name, String body) throws Exception {
        Path p = dir.resolve("ir-" + name);
        Files.writeString(p, body);
        Result r = run("--source", p.toString(), "--emit-ir");
        assertEquals(0, r.exit, name + " failed to compile: " + r.stderr);
        return r.stdout.replaceAll("\\s+", "");
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
