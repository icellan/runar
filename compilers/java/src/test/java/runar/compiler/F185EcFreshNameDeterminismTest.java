package runar.compiler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * F-185 — the EC optimizer used to name its fused-scalar helper from a
 * JVM-global {@code AtomicInteger} ({@code __ec_opt_N}) that was never reset,
 * so the long-lived {@code --daemon} (and any two compiles in one JVM) emitted
 * different canonical ANF for byte-identical input: the first request got
 * {@code __ec_opt_1}, the second {@code __ec_opt_2}.
 *
 * <p>Proves: the same EC-fusing contract compiled twice in one JVM — through
 * the CLI and through two back-to-back daemon requests, fold on and off —
 * yields byte-identical canonical ANF, and the helper is named the way the TS
 * reference ({@code anf-ec.ts} {@code freshName}) names it: {@code <binding>_k}
 * ({@code t4_k} for this contract, as {@code runar compile --ir} prints).
 *
 * <p>Does not prove: full ANF byte-identity with TS (the TS artifact prints
 * bigint constants as {@code "5n"} strings; only the helper name is compared
 * here), or anything about the other tiers' helper names (N-112).
 */
class F185EcFreshNameDeterminismTest {

    private static final String SRC = """
        import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';

        class EcOpt extends SmartContract {
            constructor() {
                super();
            }

            public spend(a: bigint) {
                assert(ecOnCurve(ecAdd(ecMulGen(2n), ecMulGen(3n))));
            }
        }
        """;

    private static Path writeSource() throws Exception {
        Path dir = Files.createTempDirectory("f185");
        Path p = dir.resolve("EcOpt.runar.ts");
        Files.writeString(p, SRC);
        return p;
    }

    private static String runCli(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exit = new Cli(new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8)).run(args);
        assertEquals(0, exit, err.toString(StandardCharsets.UTF_8));
        return out.toString(StandardCharsets.UTF_8);
    }

    private static void assertTsHelperName(String ir) {
        assertFalse(ir.contains("__ec_opt_"), "process-counter helper name leaked: " + ir);
        assertTrue(ir.contains("\"t4_k\""), "expected the TS freshName helper t4_k: " + ir);
    }

    @Test
    void cliCompileTwiceInOneJvmIsIdentical() throws Exception {
        Path src = writeSource();
        for (String fold : new String[] {null, "--disable-constant-folding"}) {
            String[] args = fold == null
                ? new String[] {"--source", src.toString(), "--emit-ir"}
                : new String[] {"--source", src.toString(), "--emit-ir", fold};
            String first = runCli(args);
            String second = runCli(args);
            assertEquals(first, second, "same program, same JVM, different ANF");
            assertTsHelperName(first);
        }
    }

    @Test
    void daemonIdenticalRequestsGiveIdenticalIr() throws Exception {
        Path src = writeSource();
        String path = src.toString().replace("\\", "\\\\");
        StringBuilder req = new StringBuilder();
        int id = 1;
        for (boolean noFold : new boolean[] {false, true}) {
            for (int i = 0; i < 2; i++) {
                req.append("{\"id\":").append(id++).append(",\"source\":\"").append(path)
                    .append("\",\"emitIr\":true,\"disableConstantFolding\":").append(noFold).append("}\n");
            }
        }
        req.append("{\"id\":99,\"shutdown\":true}\n");

        InputStream savedIn = System.in;
        String stdout;
        try {
            System.setIn(new ByteArrayInputStream(req.toString().getBytes(StandardCharsets.UTF_8)));
            stdout = runCli("--daemon");
        } finally {
            System.setIn(savedIn);
        }

        Pattern irField = Pattern.compile("\"ir\":(\"(?:[^\"\\\\]|\\\\.)*\")");
        List<String> irs = new ArrayList<>();
        for (String line : stdout.split("\n")) {
            Matcher m = irField.matcher(line);
            if (m.find()) irs.add(m.group(1));
        }
        assertEquals(4, irs.size(), stdout);
        assertEquals(irs.get(0), irs.get(1), "fold-on: identical daemon requests gave different ANF");
        assertEquals(irs.get(2), irs.get(3), "fold-off: identical daemon requests gave different ANF");
        for (String ir : irs) assertTsHelperName(ir.replace("\\\"", "\""));
    }
}
