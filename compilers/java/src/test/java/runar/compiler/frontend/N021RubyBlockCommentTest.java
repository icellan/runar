package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import runar.compiler.Cli;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.PropertyNode;

/**
 * N-021 (CL-BUG-197) — {@code =begin} ... {@code =end} embedded documents in
 * .runar.rb.
 *
 * <p>Pre-fix this tier's Ruby-surface tokenizer knew only {@code #} comments.
 * In a column-0 {@code =begin} ... {@code =end} block every line was lexed as
 * code: the "commented-out" {@code drain} became a live spend path, the
 * {@code =} of {@code =end} was skipped as an unknown class-body token and its
 * {@code end} closed the class early, dropping the guarded {@code unlock}. The
 * crafted contract below compiled to 517777 (OP_TRUE OP_NIP OP_NIP,
 * anyone-can-spend) with ABI [drain].
 *
 * <p>The rule (user decision R11) is the Ruby tier's F-018 rule, ported to Go
 * by F-012, which is Ruby's own: {@code =begin} / {@code =end} open and close
 * a block comment only at column 0 and only as a whole word (followed by
 * whitespace or end of line); every line from {@code =begin} through
 * {@code =end} is a comment; an unterminated {@code =begin} is refused with
 * "unterminated '=begin' block comment starting at line N: missing '=end'".
 * This tier's frontend refusals are strings; this one reads
 * {@code file:N: message} (no column), the text the Go tier prints for its
 * column-0 location.
 *
 * <p>What this proves: this tier parses the crafted contract to exactly
 * {@code unlock} (LF, CRLF, text or a tab after the markers) and compiles it
 * (fold OFF) to the basic-p2pkh golden, with no {@code drain} in the artifact;
 * an unterminated {@code =begin} (also one "closed" only by {@code =endx}) is
 * refused with the shared text at its line; an indented {@code =begin} and
 * {@code =beginx} are not openers.
 * What it does not prove: other tiers; the parser's separate silent skip of
 * unknown class-body tokens (N-004); {@code __END__} or other Ruby lexical
 * forms.
 */
class N021RubyBlockCommentTest {

    private static final String FILE = "P2PKH.runar.rb";

    private static final String ATTACK = String.join("\n", List.of(
        "require 'runar'",
        "",
        "class P2PKH < Runar::SmartContract",
        "  prop :pub_key_hash, Addr",
        "",
        "  def initialize(pub_key_hash)",
        "    super(pub_key_hash)",
        "    @pub_key_hash = pub_key_hash",
        "  end",
        "",
        "=begin",
        "  Old debugging entry point, disabled:",
        "  runar_public sig: Sig, pk: PubKey",
        "  def drain(sig, pk)",
        "    assert true",
        "  end",
        "end",
        "=end",
        "",
        "  runar_public sig: Sig, pub_key: PubKey",
        "  def unlock(sig, pub_key)",
        "    assert hash160(pub_key) == @pub_key_hash",
        "    assert check_sig(sig, pub_key)",
        "  end",
        "end",
        ""));

    private static String unterminated(int line) {
        return FILE + ":" + line + ": unterminated '=begin' block comment starting at line "
            + line + ": missing '=end'";
    }

    private static Map<String, String> variants() {
        Map<String, String> v = new LinkedHashMap<>();
        v.put("lf", ATTACK);
        v.put("crlf", ATTACK.replace("\n", "\r\n"));
        v.put("text after markers", ATTACK.replace("\n=begin\n", "\n=begin legacy notes\n")
            .replace("\n=end\n", "\n=end trailing words\n"));
        v.put("tab after markers", ATTACK.replace("\n=begin\n", "\n=begin\tx\n")
            .replace("\n=end\n", "\n=end\tx\n"));
        return v;
    }

    private static String refusal(String source) {
        try {
            ParserDispatch.parse(source, FILE);
            return null;
        } catch (ParserDispatch.ParseException e) {
            return e.getMessage();
        }
    }

    private static List<String> methods(String source) throws Exception {
        return ParserDispatch.parse(source, FILE).methods().stream().map(MethodNode::name).toList();
    }

    @Test
    void backdoorIsNotASpendPath() throws Exception {
        for (Map.Entry<String, String> e : variants().entrySet()) {
            ContractNode c = ParserDispatch.parse(e.getValue(), FILE);
            assertEquals(List.of("unlock"), c.methods().stream().map(MethodNode::name).toList(), e.getKey());
            assertEquals(List.of("pubKeyHash"), c.properties().stream().map(PropertyNode::name).toList(), e.getKey());
        }
    }

    @Test
    void compilesToTheBasicP2pkhGolden(@TempDir Path dir) throws Exception {
        String golden = Files.readString(Path.of("../../conformance/tests/basic-p2pkh/expected-script.hex")).trim();
        int i = 0;
        for (Map.Entry<String, String> e : variants().entrySet()) {
            Path p = dir.resolve("v" + (i++) + "-" + FILE);
            Files.writeString(p, e.getValue());
            String[] hex = run("--source", p.toString(), "--hex", "--disable-constant-folding");
            assertEquals("0", hex[0], e.getKey() + ": " + hex[2]);
            assertEquals(golden, hex[1].trim().toLowerCase(), e.getKey());
            String[] art = run("--source", p.toString(), "--disable-constant-folding");
            assertEquals("0", art[0], e.getKey() + ": " + art[2]);
            assertTrue(art[1].contains("\"unlock\""), e.getKey() + ": " + art[1]);
            assertFalse(art[1].contains("drain"), e.getKey() + ": " + art[1]);
        }
    }

    @Test
    void unterminatedBeginIsRefusedAtItsLine() {
        String got = refusal(ATTACK.replace("\n=end\n", "\n"));
        assertNotNull(got, "accepted an unterminated =begin");
        assertTrue(got.contains(unterminated(11)), got);
    }

    @Test
    void endxDoesNotCloseABlock() {
        String got = refusal(ATTACK.replace("\n=end\n", "\n=endx\n"));
        assertNotNull(got, "=endx closed the block");
        assertTrue(got.contains(unterminated(11)), got);
    }

    @Test
    void beginOnLastLineIsUnterminated() {
        String got = refusal("require 'runar'\n=begin");
        assertNotNull(got);
        assertTrue(got.contains(unterminated(2)), got);
    }

    // Boundary controls: only a column-0 whole-word `=begin` opens a comment,
    // so the lines after these are still lexed as code (`drain` is parsed).
    @Test
    void indentedBeginIsNotAComment() throws Exception {
        String src = ATTACK.replace("\n=begin\n", "\n  =begin\n").replace("\n=end\n", "\n  =end\n");
        assertTrue(methods(src).contains("drain"));
    }

    @Test
    void beginxIsNotAComment() throws Exception {
        assertTrue(methods(ATTACK.replace("\n=begin\n", "\n=beginx\n")).contains("drain"));
    }

    private static String[] run(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream o = new PrintStream(out, true, StandardCharsets.UTF_8);
        PrintStream e = new PrintStream(err, true, StandardCharsets.UTF_8);
        int exit = new Cli(o, e).run(args);
        return new String[] {
            String.valueOf(exit), out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8)
        };
    }
}
