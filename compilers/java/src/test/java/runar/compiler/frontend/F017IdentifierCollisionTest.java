package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * F-017 — two distinct source identifiers that a surface's name conversion
 * maps to ONE Rúnar name are refused with one shared diagnostic.
 *
 * <p>Before the rule, {@code tmp = n + 1; tmp_ = n + 2; assert_(tmp == tmp_)}
 * in a .runar.py contract (always false under Python semantics) bound both
 * spellings to one variable and compiled to {@code OP_DUP OP_DUP OP_NUMEQUAL}:
 * an always-TRUE guard.
 *
 * <p>This tier's Move parser ALSO mapped differently from the reference:
 * {@code String.split("_")} drops trailing empty fields, so {@code tmp_} stayed
 * {@code tmp_} on .runar.move where every other tier says {@code tmp}. The
 * {@code move} case pins the converged mapping.
 *
 * <p>What this proves: the Java tier's frontend refuses a collision on each of
 * the five renaming surfaces (.py/.rs/.rb/.move/.go) with exactly the text the
 * TS reference emits, picks the same pair regardless of declaration order, and
 * does not refuse {@code sum_} on its own or a local that reuses a property's
 * exact spelling.
 *
 * <p>What it does NOT prove: anything about the other tiers (their own suites
 * and conformance/negatives/N46-N50 cover that), or the semantics of a local
 * that shadows a property under the same spelling (N-016, a separate item).
 */
class F017IdentifierCollisionTest {

    private static final Pattern COLLISION = Pattern.compile("identifier collision: [^\\n;]*'; rename one of them");

    private static String msg(String a, String b, String name) {
        return "identifier collision: '" + a + "' and '" + b + "' both convert to '" + name + "'; rename one of them";
    }

    private static String py(String body) {
        return "from runar import SmartContract, Bigint, public, assert_\n\n\n"
            + "class Trail(SmartContract):\n    k: Bigint\n\n"
            + "    def __init__(self, k: Bigint):\n        super().__init__(k)\n        self.k = k\n\n"
            + "    @public\n    def unlock(self, n: Bigint):\n" + body + "\n";
    }

    private static final String RS = "use runar::prelude::*;\n\n#[runar::contract]\nstruct Trail {\n"
        + "    #[readonly]\n    k: Int,\n}\n\nimpl Trail {\n    pub fn unlock(&self, n: Int) {\n"
        + "        let n_ = n + 1;\n        assert!(n_ == n);\n    }\n}\n";

    private static final String RB = "require 'runar'\n\nclass Trail < Runar::SmartContract\n"
        + "  prop :k, Bigint\n\n  def initialize(k)\n    super(k)\n    @k = k\n  end\n\n"
        + "  runar_public n: Bigint\n  def unlock(n)\n    k_ = n + 1\n    assert k_ == @k\n  end\nend\n";

    private static final String MOVE = "module Trail {\n    use runar::types::{Int};\n\n"
        + "    struct Trail {\n        k: Int,\n    }\n\n"
        + "    public fun unlock(contract: &Trail, n: Int) {\n        let tmp = n + 1;\n"
        + "        let tmp_ = n + 2;\n        assert!(tmp == tmp_, 0);\n    }\n}\n";

    private static final String GO = "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\n"
        + "type Trail struct {\n\trunar.SmartContract\n\tK runar.Int `runar:\"readonly\"`\n}\n\n"
        + "func (c *Trail) Unlock(n runar.Int) {\n\tk := n + 1\n\trunar.Assert(k == c.K)\n}\n";

    /** The identifier-collision diagnostics the frontend refuses {@code source} with. */
    private static List<String> collisions(String source, String fileName) {
        List<String> out = new ArrayList<>();
        try {
            ParserDispatch.parse(source, fileName);
        } catch (ParserDispatch.ParseException e) {
            Matcher m = COLLISION.matcher(e.getMessage());
            while (m.find()) out.add(m.group());
        }
        return out;
    }

    private static void assertRefused(String source, String fileName, String expected) {
        assertThrows(ParserDispatch.ParseException.class, () -> ParserDispatch.parse(source, fileName),
            fileName + " was accepted; it must be refused");
        assertEquals(List.of(expected), collisions(source, fileName));
    }

    @Test
    void pyCollisionsAreRefused() {
        assertRefused(py("        tmp = n + 1\n        tmp_ = n + 2\n        assert_(tmp == tmp_)"), "Trail.runar.py", msg("tmp", "tmp_", "tmp"));
        assertRefused(py("        _tmp = n + 1\n        tmp = n + 2\n        assert_(_tmp == tmp)"), "Trail.runar.py", msg("_tmp", "tmp", "tmp"));
        assertRefused(py("        a__b = n + 1\n        a_b = n + 2\n        assert_(a__b == a_b)"), "Trail.runar.py", msg("a__b", "a_b", "aB"));
        assertRefused(py("        acc = n\n        for i_ in range(3):\n            acc = acc + 1\n        i = acc\n        assert_(i == n + 3)"), "Trail.runar.py", msg("i", "i_", "i"));
    }

    @Test
    void rsRbMoveGoCollisionsAreRefused() {
        assertRefused(RS, "Trail.runar.rs", msg("n", "n_", "n"));
        assertRefused(RB, "Trail.runar.rb", msg("k", "k_", "k"));
        assertRefused(MOVE, "Trail.runar.move", msg("tmp", "tmp_", "tmp"));
        assertRefused(GO, "Trail.runar.go", msg("K", "k", "k"));
    }

    @Test
    void pairChoiceIsIndependentOfDeclarationOrder() {
        assertRefused(
            py("        z_ = n + 1\n        z = n + 2\n        b__c = n + 3\n        b_c = n + 4\n        bC = n + 5\n        assert_(z + z_ + b__c + b_c + bC > 0)"),
            "Trail.runar.py", msg("bC", "b__c", "bC"));
    }

    @Test
    void nonCollidingNamesAreAccepted() {
        for (String body : List.of(
                "        x = n + 1\n        y = n + 2\n        assert_(x != y)",
                "        sum_ = n + 1\n        sum_ = sum_ + 1\n        assert_(sum_ == n + 2)",
                "        k = n + 1\n        assert_(k == self.k)")) {
            assertEquals(List.of(), collisions(py(body), "Trail.runar.py"), body);
        }
    }
}
