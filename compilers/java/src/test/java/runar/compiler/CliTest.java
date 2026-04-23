package runar.compiler;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CliTest {

    @Test
    void versionFlagPrintsVersionAndExitsZero() {
        Result r = run("--version");
        assertEquals(0, r.exit);
        assertEquals("runar-java " + Version.VALUE, r.stdout.trim());
        assertEquals("", r.stderr.trim());
    }

    @Test
    void helpFlagPrintsUsageAndExitsZero() {
        Result r = run("--help");
        assertEquals(0, r.exit);
        assertTrue(r.stdout.contains("--source"), "usage should mention --source");
        assertTrue(r.stdout.contains("--hex"), "usage should mention --hex");
    }

    @Test
    void noArgsPrintsUsageAndExitsNonZero() {
        Result r = run();
        assertEquals(2, r.exit);
    }

    @Test
    void unknownFlagExitsTwo() {
        Result r = run("--bogus");
        assertEquals(2, r.exit);
        assertTrue(r.stderr.contains("unknown flag"), "stderr should explain the unknown flag");
    }

    @Test
    void compileFlagsAreStubbed() {
        // Until milestone 3 lands the parser, compilation flags must exit non-zero
        // with an explicit "not implemented" message so conformance runs fail loudly.
        Result r = run("--source", "Counter.runar.java", "--hex", "--disable-constant-folding");
        assertEquals(64, r.exit);
        assertTrue(r.stderr.contains("not yet implemented"), "stderr should mention the stub state");
    }

    private record Result(int exit, String stdout, String stderr) {}

    private Result run(String... args) {
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        PrintStream outPs = new PrintStream(stdout, true, StandardCharsets.UTF_8);
        PrintStream errPs = new PrintStream(stderr, true, StandardCharsets.UTF_8);
        int exit = new Cli(outPs, errPs).run(args);
        outPs.flush();
        errPs.flush();
        return new Result(
            exit,
            stdout.toString(StandardCharsets.UTF_8),
            stderr.toString(StandardCharsets.UTF_8)
        );
    }
}
