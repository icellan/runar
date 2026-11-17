package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * Grok v1 frontend findings, Java tier. The corpora are the cross-tier ones in
 * {@code conformance/negatives/}, shared with the other six tiers' unit tests
 * and the conformance negatives gates.
 *
 * <ul>
 *   <li>GK-BUG-015: a repeated method name is a validate error with the shared
 *       message; each renamed twin compiles.</li>
 *   <li>GK-GAP-013: {@code AnfLower.run} refuses malformed intent-intrinsic
 *       calls instead of lowering them to {@code load_const ""}; typecheck
 *       still refuses first.</li>
 *   <li>GK-GAP-010: a public method's SigHashPreimage parameter must reach
 *       checkPreimage on every path.</li>
 *   <li>GK-GAP-005/006: suffixes match ignoring ASCII case (same hex), an
 *       unknown suffix is refused with the shared message, no file name means
 *       TypeScript.</li>
 * </ul>
 */
class GkFrontendTest {

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

    private record Result(int exit, String stdout, String stderr) {}

    private static Result cli(String fileName, String src) throws IOException {
        Path dir = Files.createTempDirectory("gk-");
        Path file = dir.resolve(fileName);
        Files.writeString(file, src);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exit = new Cli(new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8))
            .run(new String[] {"--source", file.toString(), "--hex"});
        return new Result(exit, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    @Test
    void gk015DuplicateMethodIsRefused() throws Exception {
        for (Map<String, Object> c : list(corpus("duplicate-method-cases.json"), "cases")) {
            String name = (String) c.get("name");
            Result r = cli((String) c.get("file"), (String) c.get("src"));
            assertNotEquals(0, r.exit(), name + " accepted: " + r.stdout());
            assertTrue((r.stderr() + r.stdout()).contains((String) c.get("error")), name + ": " + r.stderr());
            Result twin = cli((String) c.get("file"), (String) c.get("twin"));
            assertEquals(0, twin.exit(), name + " twin: " + twin.stderr());
        }
    }

    @Test
    void gk013LowererRefusesMalformedIntentShapes() throws Exception {
        for (Map<String, Object> c : list(corpus("intent-shape-cases.json"), "cases")) {
            String name = (String) c.get("name");
            ContractNode contract = ParserDispatch.parse((String) c.get("src"), "Bad.runar.ts");
            assertFalse(Typecheck.collect(contract).isEmpty(), name + ": typecheck accepted");
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> AnfLower.run(contract), name);
            assertTrue(e.getMessage().contains((String) c.get("lowerError")), name + ": " + e.getMessage());
        }
    }

    @Test
    void gk010PreimageCheckedOnEveryPath() throws Exception {
        Map<String, Object> corpus = corpus("preimage-checked-cases.json");
        for (Map<String, Object> c : list(corpus, "refuse")) {
            String name = (String) c.get("name");
            Result r = cli((String) c.get("file"), (String) c.get("src"));
            assertNotEquals(0, r.exit(), name + " accepted");
            assertTrue((r.stderr() + r.stdout()).contains((String) c.get("error")), name + ": " + r.stderr());
        }
        for (Map<String, Object> c : list(corpus, "accept")) {
            Result r = cli((String) c.get("file"), (String) c.get("src"));
            assertEquals(0, r.exit(), c.get("name") + ": " + r.stderr());
        }
    }

    /** D10: a stateless Rust-DSL contract cannot declare tx_preimage. */
    @Test
    void d10StatelessRustTxPreimageIsRefused() throws Exception {
        Map<String, Object> corpus = corpus("rust-tx-preimage-cases.json");
        assertTrue(list(corpus, "refuse").size() >= 5);
        for (Map<String, Object> c : list(corpus, "refuse")) {
            String name = (String) c.get("name");
            String want = (String) c.get("error");
            ParserDispatch.ParseException e = assertThrows(ParserDispatch.ParseException.class,
                () -> ParserDispatch.parse((String) c.get("src"), (String) c.get("file")), name);
            assertTrue(e.getMessage().contains(want), name + ": " + e.getMessage());
            Result r = cli((String) c.get("file"), (String) c.get("src"));
            assertNotEquals(0, r.exit(), name + " accepted");
            assertTrue((r.stderr() + r.stdout()).contains(want), name + ": " + r.stderr());
        }
        for (Map<String, Object> c : list(corpus, "accept")) {
            String name = (String) c.get("name");
            ContractNode contract = ParserDispatch.parse((String) c.get("src"), (String) c.get("file"));
            assertEquals(runar.compiler.ir.ast.ParentClass.STATEFUL_SMART_CONTRACT, contract.parentClass(), name);
            assertTrue(contract.properties().stream().noneMatch(p -> p.name().equals("txPreimage")), name);
            Result r = cli((String) c.get("file"), (String) c.get("src"));
            assertEquals(0, r.exit(), name + ": " + r.stderr());
        }
    }

    @Test
    void gk005ExtensionDispatch() throws Exception {
        String ts = Files.readString(repo().resolve("examples/ts/p2pkh/P2PKH.runar.ts"));
        String py = Files.readString(repo().resolve("examples/python/p2pkh/P2PKH.runar.py"));
        List<String[]> pairs = new ArrayList<>();
        pairs.add(new String[] {ts, "P2PKH.runar.ts", "P2PKH.RUNAR.TS"});
        pairs.add(new String[] {py, "P2PKH.runar.py", "P2PKH.RUNAR.PY"});
        for (String[] p : pairs) {
            Result lo = cli(p[1], p[0]);
            Result up = cli(p[2], p[0]);
            assertEquals(0, lo.exit(), lo.stderr());
            assertEquals(0, up.exit(), up.stderr());
            assertEquals(lo.stdout(), up.stdout(), p[1] + " vs " + p[2]);
        }
        ParserDispatch.ParseException e = assertThrows(ParserDispatch.ParseException.class,
            () -> ParserDispatch.parse(ts, "P2PKH.runar.xyz"));
        assertEquals("unsupported file extension: P2PKH.runar.xyz (expected .runar.ts, .runar.sol, .runar.move, "
            + ".runar.go, .runar.rs, .runar.py, .runar.rb, .runar.zig, or .runar.java)", e.getMessage());
        assertEquals("P2PKH", ParserDispatch.parse(ts, null).name());
        assertEquals("P2PKH", ParserDispatch.parse(ts, "").name());
    }
}
