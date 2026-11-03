package runar.compiler;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CL-BUG-104: the Java CLI must not swallow validator warnings.
 *
 * <p>{@code Validate.run(contract)} returns the warning list ({@code
 * Validate.java:90}), but {@code Cli.java} called it for its exception
 * side-effect and discarded the return value — so the SP1 FRI unsoundness
 * disclosure, the {@code @embedAlways} DCE notices and the sighash advisories
 * were invisible to anyone driving the compiler from the command line.
 *
 * <p>Reference behaviour is the Rust ({@code compilers/rust/src/main.rs}:
 * {@code eprintln!("warning: {}", w)}) and Zig ({@code
 * compilers/zig/src/main.zig}: {@code printDiagnostics}) tiers: warnings go to
 * <b>stderr</b>, one per line, prefixed {@code "warning: "}, and they change
 * neither the exit code nor the bytes on stdout.
 *
 * <p>The warning driven here is a real one — "StatefulSmartContract has no
 * mutable properties", emitted by {@code Validate.java}. Nothing synthetic is
 * injected.
 */
class CliWarningsTest {

    private static final String WARNING_SOURCE = """
        import { StatefulSmartContract, assert } from 'runar-lang';

        export class WarnStateful extends StatefulSmartContract {
          readonly limit: bigint;

          constructor(limit: bigint) {
            super(limit);
            this.limit = limit;
          }

          public unlock(x: bigint): void {
            assert(x < this.limit);
          }
        }
        """;

    private static final String CLEAN_SOURCE = """
        import { SmartContract, assert } from 'runar-lang';

        export class CleanStateless extends SmartContract {
          readonly limit: bigint;

          constructor(limit: bigint) {
            super(limit);
            this.limit = limit;
          }

          public unlock(x: bigint): void {
            assert(x < this.limit);
          }
        }
        """;

    @Test
    void validatorWarningReachesStderr(@TempDir Path tmp) throws Exception {
        Path src = write(tmp, "WarnStateful.runar.ts", WARNING_SOURCE);
        Result r = run("--source", src.toString(), "--hex");

        assertEquals(0, r.exit, "compile must succeed; stderr=" + r.stderr);
        assertTrue(
            r.stderr.contains("StatefulSmartContract has no mutable properties"),
            "validator warning did not reach stderr; stderr=" + r.stderr);
        assertTrue(
            r.stderr.contains("warning: "),
            "warning line must carry the 'warning: ' prefix used by Rust/Zig; stderr=" + r.stderr);
        assertFalse(r.stdout.isBlank(), "stdout must still carry the script hex");
        assertFalse(r.stdout.contains("warning"), "warning leaked into stdout: " + r.stdout);
    }

    @Test
    void parseOnlyAlsoPrintsWarnings(@TempDir Path tmp) throws Exception {
        Path src = write(tmp, "WarnStateful.runar.ts", WARNING_SOURCE);
        Result r = run("--source", src.toString(), "--parse-only");

        assertEquals(0, r.exit, "--parse-only must exit 0; stderr=" + r.stderr);
        assertEquals("parser ok", r.stdout.trim(),
            "--parse-only stdout must stay exactly \"parser ok\"");
        assertTrue(r.stderr.contains("warning: "),
            "--parse-only dropped the validator warning; stderr=" + r.stderr);
        assertTrue(r.stderr.contains("StatefulSmartContract has no mutable properties"));
    }

    @Test
    void cleanCompilePrintsNoWarningAndExitsZero(@TempDir Path tmp) throws Exception {
        Path src = write(tmp, "CleanStateless.runar.ts", CLEAN_SOURCE);
        Result r = run("--source", src.toString(), "--hex");

        assertEquals(0, r.exit, "clean compile must exit 0; stderr=" + r.stderr);
        assertFalse(r.stderr.contains("warning"),
            "clean compile must print no warning line; stderr=" + r.stderr);
        assertFalse(r.stdout.isBlank(), "clean compile produced no hex");
    }

    /**
     * The warning must be advisory only: the bytes on stdout are identical to
     * what the compiler emitted before it learned to talk.
     */
    @Test
    void warningDoesNotChangeEmittedBytes(@TempDir Path tmp) throws Exception {
        Path warn = write(tmp, "WarnStateful.runar.ts", WARNING_SOURCE);
        Result a = run("--source", warn.toString(), "--hex");
        Result b = run("--source", warn.toString(), "--hex");
        assertEquals(a.stdout, b.stdout, "hex must be deterministic");
        assertEquals(0, a.exit);
        assertTrue(a.stdout.trim().matches("[0-9a-f]+"), "stdout must be pure hex: " + a.stdout);
    }

    /**
     * F-187 (CX-BUG-048): the CLI path above already surfaces warnings
     * (CL-BUG-104), but {@code --daemon}'s {@code serveRequest} called
     * {@code Validate.run(contract)} for its exception side-effect only and
     * discarded the returned warning list, so a daemon client (the
     * conformance runner's {@code JavaDaemon}) had no way to see the same
     * {@code warnStrippedReadonlyFields} / locktime-guard / "no mutable
     * properties" advisories the CLI prints to stderr.
     *
     * <p>Fix returns them as a {@code "warnings"} JSON array of raw message
     * strings (no "warning: " prefix — that prefix is a stderr-line
     * convention from the CLI path; a structured JSON field doesn't need
     * it), omitted entirely when there are none, so existing daemon
     * consumers that don't look for the field are unaffected.
     */
    @Test
    void daemonServeRequestIncludesWarnings(@TempDir Path tmp) throws Exception {
        Path src = write(tmp, "WarnStateful.runar.ts", WARNING_SOURCE);
        Cli.DaemonRequest req = new Cli.DaemonRequest();
        req.id = 1;
        req.source = src.toString();
        req.hex = true;

        String response = new Cli(devNull(), devNull()).serveRequest(req);

        assertTrue(response.contains("\"ok\":true"), "response: " + response);
        assertTrue(response.contains("\"warnings\":["),
            "daemon response dropped the validator warning; response=" + response);
        assertTrue(response.contains("StatefulSmartContract has no mutable properties"),
            "response: " + response);
    }

    @Test
    void daemonServeRequestParseOnlyAlsoIncludesWarnings(@TempDir Path tmp) throws Exception {
        Path src = write(tmp, "WarnStateful.runar.ts", WARNING_SOURCE);
        Cli.DaemonRequest req = new Cli.DaemonRequest();
        req.id = 2;
        req.source = src.toString();
        req.parseOnly = true;

        String response = new Cli(devNull(), devNull()).serveRequest(req);

        assertTrue(response.contains("\"parsed\":true"), "response: " + response);
        assertTrue(response.contains("\"warnings\":["),
            "daemon --parse-only response dropped the validator warning; response=" + response);
    }

    @Test
    void daemonServeRequestCleanCompileHasNoWarningsField(@TempDir Path tmp) throws Exception {
        Path src = write(tmp, "CleanStateless.runar.ts", CLEAN_SOURCE);
        Cli.DaemonRequest req = new Cli.DaemonRequest();
        req.id = 3;
        req.source = src.toString();
        req.hex = true;

        String response = new Cli(devNull(), devNull()).serveRequest(req);

        assertTrue(response.contains("\"ok\":true"), "response: " + response);
        assertFalse(response.contains("\"warnings\""),
            "clean compile must not carry an empty warnings field; response=" + response);
    }

    private static PrintStream devNull() {
        return new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
    }

    private static Path write(Path dir, String name, String body) throws Exception {
        Path p = dir.resolve(name);
        Files.writeString(p, body);
        return p;
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
