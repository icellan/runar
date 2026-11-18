package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;

/**
 * #199 (release-trap warning) and D18 (dropped-continuation refusal), Java
 * tier. Port of packages/runar-compiler/src/passes/continuation-rules.ts.
 * Corpora: conformance/negatives/release-trap-cases.json and
 * conformance/negatives/dropped-continuation-cases.json.
 *
 * <p>Proves: the CLI warns (stderr, exit 0) on every #199 warn shape and on no
 * nowarn shape; refuses every D18 refuse shape with the shared text; compiles
 * every D18 accept shape; and refuses the TS-lowered, typecheck-skipped ANF of
 * the issue #180 Lock contract on the --ir path. Does not prove: the other six
 * tiers, or byte parity (gk-frontend-parity.test.ts).
 */
class D18ReleaseTrapTest {

    private static Path repo() throws IOException {
        for (Path p = Paths.get("").toAbsolutePath(); p != null; p = p.getParent()) {
            if (Files.isDirectory(p.resolve("conformance").resolve("negatives"))) return p;
        }
        throw new IOException("repo root not found");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> corpus(String name) throws IOException {
        String raw = Files.readString(repo().resolve("conformance/negatives").resolve(name));
        return (Map<String, Object>) AnfLoader.parseJsonTree(raw);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Map<String, Object> m, String key) {
        return (List<Map<String, Object>>) m.get(key);
    }

    private record Result(int exit, String stdout, String stderr) {
        String diag() { return stdout + "\n" + stderr; }
    }

    private static Result run(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exit = new Cli(new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8)).run(args);
        return new Result(exit, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private static Result cli(String fileName, String src) throws IOException {
        Path dir = Files.createTempDirectory("d18-");
        Path file = dir.resolve(fileName);
        Files.writeString(file, src);
        return run("--source", file.toString(), "--hex");
    }

    @Test
    void releaseTrapWarnsOnEveryWarnShape() throws Exception {
        List<Map<String, Object>> cases = list(corpus("release-trap-cases.json"), "warn");
        assertFalse(cases.isEmpty());
        for (Map<String, Object> c : cases) {
            String name = (String) c.get("name");
            Result r = cli((String) c.get("file"), (String) c.get("src"));
            assertEquals(0, r.exit(), name + ": " + r.stderr());
            assertFalse(r.stdout().isBlank(), name);
            assertTrue(r.stderr().contains((String) c.get("warning")), name + ": " + r.stderr());
        }
    }

    @Test
    void releaseTrapDoesNotWarnOnNowarnShapes() throws Exception {
        for (Map<String, Object> c : list(corpus("release-trap-cases.json"), "nowarn")) {
            String name = (String) c.get("name");
            Result r = cli((String) c.get("file"), (String) c.get("src"));
            assertEquals(0, r.exit(), name + ": " + r.stderr());
            assertFalse(r.diag().contains((String) c.get("warning_absent")), name);
        }
    }

    @Test
    void droppedContinuationIsRefused() throws Exception {
        List<Map<String, Object>> cases = list(corpus("dropped-continuation-cases.json"), "refuse");
        assertFalse(cases.isEmpty());
        for (Map<String, Object> c : cases) {
            String name = (String) c.get("name");
            Result r = cli((String) c.get("file"), (String) c.get("src"));
            assertNotEquals(0, r.exit(), name + " accepted: " + r.stdout());
            assertTrue(r.diag().contains((String) c.get("error")), name + ": " + r.diag());
        }
    }

    @Test
    void droppedContinuationAcceptShapesCompile() throws Exception {
        for (Map<String, Object> c : list(corpus("dropped-continuation-cases.json"), "accept")) {
            String name = (String) c.get("name");
            Result r = cli((String) c.get("file"), (String) c.get("src"));
            assertEquals(0, r.exit(), name + ": " + r.stderr());
            assertFalse(r.stdout().isBlank(), name);
        }
    }

    @Test
    void irPathRefusesIssue180Lock() throws Exception {
        Path ir = repo().resolve("compilers/java/src/test/java/runar/compiler/passes/d18_issue180_lock.ir.json");
        String error = null;
        for (Map<String, Object> c : list(corpus("dropped-continuation-cases.json"), "refuse")) {
            if ("issue-180-lock".equals(c.get("name"))) error = (String) c.get("error");
        }
        Result r = run("--ir", ir.toString(), "--hex");
        assertNotEquals(0, r.exit(), "accepted the Lock IR: " + r.stdout());
        assertFalse(r.diag().contains("Exception in thread"), r.diag());
        assertTrue(r.diag().contains(error), r.diag());
    }

    /**
     * Per path: the TS ANF of terminal-branch-writes-nothing with an update_prop
     * added to its raw-output {@code if} arm (the IR ir-release-trap.test.ts hand-builds).
     */
    @Test
    void irPathRefusesWriteOnRawBranch() throws Exception {
        Path ir = repo().resolve("compilers/java/src/test/java/runar/compiler/passes/d18_write_on_raw_branch.ir.json");
        String error = null;
        for (Map<String, Object> c : list(corpus("dropped-continuation-cases.json"), "refuse")) {
            if ("write-on-raw-branch-sibling-add-output".equals(c.get("name"))) error = (String) c.get("error");
        }
        Result r = run("--ir", ir.toString(), "--hex");
        assertNotEquals(0, r.exit(), "accepted the write-on-raw-branch IR: " + r.stdout());
        assertFalse(r.diag().contains("Exception in thread"), r.diag());
        assertTrue(r.diag().contains(error), r.diag());
    }

    @Test
    void irPathAcceptsTerminalBranchWritesNothing() throws Exception {
        Path ir = repo().resolve(
            "compilers/java/src/test/java/runar/compiler/passes/d18_terminal_branch_writes_nothing.ir.json");
        Result r = run("--ir", ir.toString(), "--hex");
        assertEquals(0, r.exit(), r.diag());
        assertFalse(r.stdout().isBlank());
    }
}
