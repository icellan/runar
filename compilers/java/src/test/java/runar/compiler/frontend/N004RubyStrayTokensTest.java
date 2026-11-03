package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * N-004 (CL-BUG-257) — stray class-level tokens in .runar.rb.
 *
 * <p>The parser skipped any class-body token it did not recognise and ignored
 * everything after the class's {@code end}. An INDENTED {@code =begin} is not
 * a comment in Ruby: it lexes as {@code =} then {@code begin}, both were
 * skipped, the "commented-out" {@code drain} became a method, the block's
 * {@code end} closed the class, and the real guarded {@code unlock} was
 * dropped with no diagnostic, leaving {@code drain} (assert true) as the only
 * spend path.
 *
 * <p>The rule is the TS reference's: a class-body token other than
 * {@code prop}, {@code runar_public}, {@code params}, {@code def} or a bare
 * {@code private} / {@code public} marker is refused with "Unexpected token in
 * class body: '&lt;tok&gt;'", and the first token after the class's
 * {@code end} with "Unexpected token after class end: '&lt;tok&gt;'". This
 * tier's refusals are {@code file:line:col: message} lines.
 *
 * <p>What this proves: the indented backdoor, stray class-body tokens and
 * trailing code after the class are refused, the first diagnostic carrying the
 * shared text at the offending token's line; bare {@code private} /
 * {@code public} markers and trailing blank lines and comments still parse.
 * What it does not prove: emitted bytes, other tiers (see
 * conformance/negatives/n004-rb-stray-token-parity.test.ts), characters the
 * tokenizer drops, or a class with no closing {@code end}.
 */
class N004RubyStrayTokensTest {

    private static final String FILE = "P2PKH.runar.rb";

    private static String p2pkh(String body, String tail) {
        return String.join("\n", List.of(
            "require 'runar'",
            "",
            "class P2PKH < Runar::SmartContract",
            "  prop :pub_key_hash, Addr",
            "",
            "  def initialize(pub_key_hash)",
            "    super(pub_key_hash)",
            "    @pub_key_hash = pub_key_hash",
            "  end",
            body,
            "  runar_public sig: Sig, pub_key: PubKey",
            "  def unlock(sig, pub_key)",
            "    assert hash160(pub_key) == @pub_key_hash",
            "    assert check_sig(sig, pub_key)",
            "  end",
            "end",
            tail));
    }

    private static final String INDENTED = p2pkh(String.join("\n", List.of(
        "",
        "  =begin",
        "  Old debugging entry point, disabled:",
        "  runar_public sig: Sig, pk: PubKey",
        "  def drain(sig, pk)",
        "    assert true",
        "  end",
        "end",
        "  =end",
        "")), "");

    private static String body(String tok) {
        return "Unexpected token in class body: '" + tok + "'";
    }

    private static String after(String tok) {
        return "Unexpected token after class end: '" + tok + "'";
    }

    private static void assertRefused(String name, String src, String want, int line) {
        Exception e = assertThrows(Exception.class, () -> ParserDispatch.parse(src, FILE), name);
        String first = e.getMessage().split("\n")[0];
        assertTrue(first.endsWith(want) && first.startsWith(FILE + ":" + line + ":"),
            name + ": first error " + first + ", want " + want + " at line " + line);
    }

    @Test
    void strayClassLevelTokensAreRefused() {
        assertRefused("indented =begin backdoor", INDENTED, body("="), 11);
        assertRefused("stray 42 + ?", p2pkh("\n  42 + ?\n", ""), body("42"), 11);
        assertRefused("stray = end", p2pkh("\n  = end\n", ""), body("="), 11);
        assertRefused("bare identifier", p2pkh("\n  foo\n", ""), body("foo"), 11);
        assertRefused("identifier after class", p2pkh("", "foo\n"), after("foo"), 17);
        assertRefused("end after class", p2pkh("", "end\n"), after("end"), 17);
        assertRefused("method after class", p2pkh("", "def drain(sig)\n  assert true\nend\n"), after("def"), 17);
        assertRefused("class after class", p2pkh("", "class Other < Runar::SmartContract\nend\n"), after("class"), 17);
    }

    @Test
    void visibilityMarkersAndTrailingBlanksAreAccepted() {
        assertDoesNotThrow(() -> ParserDispatch.parse(p2pkh("", ""), FILE));
        assertDoesNotThrow(() -> ParserDispatch.parse(p2pkh("\n  private\n\n  public\n", ""), FILE));
        assertDoesNotThrow(() -> ParserDispatch.parse(p2pkh("", "\n# trailing note\n\n"), FILE));
    }
}
