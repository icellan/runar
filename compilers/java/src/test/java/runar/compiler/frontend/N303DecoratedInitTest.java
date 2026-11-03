package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParamNode;

/**
 * N-303 - a decorated {@code def __init__} in .runar.py is the constructor.
 *
 * <p>The TS reference ({@code parseMethodDef} in 01-parse-python.ts) decides
 * "this is the constructor" from the method NAME alone, whatever decorators
 * precede it: {@code @public def __init__} and {@code @foo def __init__} both
 * yield the ordinary constructor and add no method. Before the fix this tier
 * sent every decorated {@code def} down the method path, so the constructor
 * became a method named {@code constructor} next to an auto-generated one.
 *
 * <p>What this proves: the Java tier's .runar.py frontend produces the same
 * AST shape as the undecorated control for a decorated __init__ (one
 * constructor with the declared params, only {@code unlock} in the method
 * list, no refusal).
 *
 * <p>What it does NOT prove: the other tiers (their own suites / the matrix in
 * the N-303 log), or the compiled hex.
 */
class N303DecoratedInitTest {

    private static String py(String decorator) {
        return "from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig\n\n"
            + "class P2PKH(SmartContract):\n"
            + "    pub_key_hash: Addr\n\n"
            + decorator
            + "    def __init__(self, pub_key_hash: Addr):\n"
            + "        super().__init__(pub_key_hash)\n"
            + "        self.pub_key_hash = pub_key_hash\n\n"
            + "    @public\n"
            + "    def unlock(self, sig: Sig, pub_key: PubKey):\n"
            + "        assert_(hash160(pub_key) == self.pub_key_hash)\n"
            + "        assert_(check_sig(sig, pub_key))\n";
    }

    private static void assertConstructor(String label, String decorator) {
        ContractNode c;
        try {
            c = ParserDispatch.parse(py(decorator), "P2PKH.runar.py");
        } catch (ParserDispatch.ParseException e) {
            fail(label + ": unexpected refusal: " + e.getMessage());
            return;
        }
        List<String> methods = new ArrayList<>();
        for (MethodNode m : c.methods()) methods.add(m.name());
        assertEquals(List.of("unlock"), methods, label);
        List<String> params = new ArrayList<>();
        for (ParamNode p : c.constructor().params()) params.add(p.name());
        assertEquals("constructor", c.constructor().name(), label);
        assertEquals(List.of("pubKeyHash"), params, label);
    }

    @Test
    void aDecoratedInitIsTheConstructor() {
        assertConstructor("undecorated", "");
        assertConstructor("@public", "    @public\n");
        assertConstructor("@foo", "    @foo\n");
    }
}
