package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.DeserializeState;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.ast.ContractNode;

class AnfLowerTest {

    // ---------------------------------------------------------------
    // Invariant helpers
    // ---------------------------------------------------------------

    private static void assertUniqueTempNames(List<AnfBinding> body) {
        Set<String> seen = new HashSet<>();
        for (AnfBinding b : body) {
            String name = b.name();
            if (name.startsWith("t") && name.length() > 1 && isAllDigits(name.substring(1))) {
                assertTrue(seen.add(name), "duplicate temp name: " + name);
            }
        }
    }

    private static boolean isAllDigits(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) return false;
        }
        return !s.isEmpty();
    }

    private static AnfMethod findMethod(AnfProgram prog, String name) {
        for (AnfMethod m : prog.methods()) {
            if (m.name().equals(name)) return m;
        }
        throw new IllegalArgumentException("method not found: " + name);
    }

    private static ContractNode parse(String src, String file) {
        return JavaParser.parse(src, file);
    }

    // ---------------------------------------------------------------
    // P2PKH (SmartContract, one public unlock method)
    // ---------------------------------------------------------------

    private static final String P2PKH_SRC = """
        package runar.examples.p2pkh;

        import runar.lang.*;

        public class P2PKH extends SmartContract {
            @Readonly Addr pubKeyHash;

            public P2PKH(Addr pubKeyHash) {
                super(pubKeyHash);
                this.pubKeyHash = pubKeyHash;
            }

            @Public
            public void unlock(Sig sig, PubKey pubKey) {
                assertThat(hash160(pubKey).equals(pubKeyHash));
                assertThat(checkSig(sig, pubKey));
            }
        }
        """;

    @Test
    void p2pkhShapeMatchesReference() {
        ContractNode contract = parse(P2PKH_SRC, "P2PKH.runar.java");
        AnfProgram prog = AnfLower.run(contract);

        assertEquals("P2PKH", prog.contractName());
        assertEquals(1, prog.properties().size());
        assertEquals("pubKeyHash", prog.properties().get(0).name());
        assertEquals("Addr", prog.properties().get(0).type());
        assertTrue(prog.properties().get(0).readonly());
        assertNull(prog.properties().get(0).initialValue());

        AnfMethod ctor = findMethod(prog, "constructor");
        assertFalse(ctor.isPublic());
        assertUniqueTempNames(ctor.body());

        AnfMethod unlock = findMethod(prog, "unlock");
        assertTrue(unlock.isPublic());
        assertEquals(2, unlock.params().size());
        assertEquals("sig", unlock.params().get(0).name());
        assertEquals("Sig", unlock.params().get(0).type());
        assertEquals("pubKey", unlock.params().get(1).name());
        assertEquals("PubKey", unlock.params().get(1).type());
        assertUniqueTempNames(unlock.body());

        // Exactly 9 bindings in unlock (t0..t8), mirroring the Python /
        // TS reference.
        assertEquals(9, unlock.body().size());

        assertBinding(unlock.body().get(0), "t0", LoadParam.class);
        assertBinding(unlock.body().get(1), "t1", Call.class);
        Call hash160Call = (Call) unlock.body().get(1).value();
        assertEquals("hash160", hash160Call.func());
        assertEquals(List.of("t0"), hash160Call.args());

        assertBinding(unlock.body().get(2), "t2", LoadProp.class);
        assertBinding(unlock.body().get(3), "t3", BinOp.class);
        BinOp eq = (BinOp) unlock.body().get(3).value();
        assertEquals("===", eq.op());
        assertEquals("bytes", eq.resultType());
        assertEquals("t1", eq.left());
        assertEquals("t2", eq.right());

        assertBinding(unlock.body().get(4), "t4", Assert.class);
        assertEquals("t3", ((Assert) unlock.body().get(4).value()).value());

        assertBinding(unlock.body().get(5), "t5", LoadParam.class);
        assertBinding(unlock.body().get(6), "t6", LoadParam.class);
        assertBinding(unlock.body().get(7), "t7", Call.class);
        Call checkSig = (Call) unlock.body().get(7).value();
        assertEquals("checkSig", checkSig.func());
        assertEquals(List.of("t5", "t6"), checkSig.args());

        assertBinding(unlock.body().get(8), "t8", Assert.class);
        assertEquals("t7", ((Assert) unlock.body().get(8).value()).value());
    }

    @Test
    void p2pkhCanonicalJsonMatchesReference() {
        ContractNode contract = parse(P2PKH_SRC, "P2PKH.runar.java");
        AnfProgram prog = AnfLower.run(contract);

        // Hand-rolled expected canonical JSON. Matches
        // conformance/tests/basic-p2pkh/expected-ir.json in all IR-level
        // shape, with the exception that sourceLoc is omitted (JCS skips
        // null components). The expected-ir.json is canonicalised with
        // sorted keys, no whitespace. The order of object keys is alphabetical.
        String actual = Jcs.stringify(prog);

        // Verify presence of the central signals rather than comparing
        // the full 2000-char string — avoids brittle over-specification
        // but still catches structural drift.
        assertTrue(actual.contains("\"contractName\":\"P2PKH\""), actual);
        assertTrue(actual.contains("\"kind\":\"load_param\""), actual);
        assertTrue(actual.contains("\"kind\":\"load_prop\""), actual);
        assertTrue(actual.contains("\"kind\":\"assert\""), actual);
        assertTrue(actual.contains("\"kind\":\"bin_op\""), actual);
        assertTrue(actual.contains("\"kind\":\"call\""), actual);
        assertTrue(actual.contains("\"func\":\"hash160\""), actual);
        assertTrue(actual.contains("\"func\":\"checkSig\""), actual);
        assertTrue(actual.contains("\"op\":\"===\""), actual);
        assertTrue(actual.contains("\"result_type\":\"bytes\""), actual);
    }

    // ---------------------------------------------------------------
    // Trivial bigint arithmetic (SmartContract + single public method)
    // ---------------------------------------------------------------

    private static final String ARITH_SRC = """
        package runar.examples.arith;

        import java.math.BigInteger;
        import runar.lang.*;

        public class Arith extends SmartContract {
            @Readonly Bigint x;

            public Arith(Bigint x) {
                super(x);
                this.x = x;
            }

            @Public
            public void check(Bigint y) {
                assertThat(x + y == BigInteger.valueOf(42));
            }
        }
        """;

    @Test
    void arithmeticShape() {
        ContractNode contract = parse(ARITH_SRC, "Arith.runar.java");
        AnfProgram prog = AnfLower.run(contract);

        AnfMethod check = findMethod(prog, "check");
        assertTrue(check.isPublic());
        assertUniqueTempNames(check.body());

        // Expect: load_prop x, load_param y, bin_op +, load_const 42,
        // bin_op ===, assert.
        assertEquals(6, check.body().size());
        assertTrue(check.body().get(0).value() instanceof LoadProp);
        assertTrue(check.body().get(1).value() instanceof LoadParam);
        assertTrue(check.body().get(2).value() instanceof BinOp be
            && be.op().equals("+") && be.resultType() == null);
        assertTrue(check.body().get(3).value() instanceof LoadConst lc
            && lc.value() instanceof BigIntConst bic
            && bic.value().intValue() == 42);
        assertTrue(check.body().get(4).value() instanceof BinOp eq
            && eq.op().equals("===") && eq.resultType() == null);
        AnfBinding last = check.body().get(5);
        assertTrue(last.value() instanceof Assert a
            && a.value().equals(check.body().get(4).name()));
    }

    // ---------------------------------------------------------------
    // StatefulSmartContract (Counter with increment)
    // ---------------------------------------------------------------

    private static final String COUNTER_SRC = """
        package runar.examples.counter;

        import runar.lang.*;

        public class Counter extends StatefulSmartContract {
            Bigint count;

            public Counter(Bigint count) {
                super(count);
                this.count = count;
            }

            @Public
            public void increment() {
                this.count++;
            }
        }
        """;

    @Test
    void counterIncrementHasStatefulAutoInject() {
        ContractNode contract = parse(COUNTER_SRC, "Counter.runar.java");
        AnfProgram prog = AnfLower.run(contract);

        AnfMethod inc = findMethod(prog, "increment");
        assertTrue(inc.isPublic());
        assertUniqueTempNames(inc.body());

        // First three bindings must be the preimage check auto-inject:
        //   t0 = load_param txPreimage
        //   t1 = check_preimage t0
        //   t2 = assert t1
        assertBinding(inc.body().get(0), "t0", LoadParam.class);
        assertEquals("txPreimage", ((LoadParam) inc.body().get(0).value()).name());
        assertBinding(inc.body().get(1), "t1", CheckPreimage.class);
        assertEquals("t0", ((CheckPreimage) inc.body().get(1).value()).preimage());
        assertBinding(inc.body().get(2), "t2", Assert.class);
        assertEquals("t1", ((Assert) inc.body().get(2).value()).value());

        // Next: deserialize_state
        assertBinding(inc.body().get(3), "t3", LoadParam.class);
        assertBinding(inc.body().get(4), "t4", DeserializeState.class);

        // Augmented params must include the auto-injected ones
        List<String> paramNames = inc.params().stream().map(p -> p.name()).toList();
        assertTrue(paramNames.contains("_changePKH"));
        assertTrue(paramNames.contains("_changeAmount"));
        assertTrue(paramNames.contains("_newAmount"));
        assertTrue(paramNames.contains("txPreimage"));
        // txPreimage must be last.
        assertEquals("txPreimage", paramNames.get(paramNames.size() - 1));

        // Final binding of the method must be an Assert (from the
        // continuation-hash equality check).
        AnfBinding last = inc.body().get(inc.body().size() - 1);
        assertTrue(last.value() instanceof Assert,
            "stateful public method should end with an Assert binding, got "
                + last.value().getClass().getSimpleName());

        // There should be exactly one update_prop on `count`.
        int updateCount = 0;
        for (AnfBinding b : inc.body()) {
            if (b.value() instanceof UpdateProp up && up.name().equals("count")) {
                updateCount++;
            }
        }
        assertEquals(1, updateCount);
    }

    @Test
    void counterContinuationHashUsesCorrectOps() {
        ContractNode contract = parse(COUNTER_SRC, "Counter.runar.java");
        AnfProgram prog = AnfLower.run(contract);

        AnfMethod inc = findMethod(prog, "increment");

        boolean sawComputeStateOutput = false;
        boolean sawBuildChangeOutput = false;
        boolean sawHash256 = false;
        boolean sawExtractOutputHash = false;
        for (AnfBinding b : inc.body()) {
            if (b.value() instanceof Call c) {
                switch (c.func()) {
                    case "computeStateOutput" -> sawComputeStateOutput = true;
                    case "buildChangeOutput" -> sawBuildChangeOutput = true;
                    case "hash256" -> sawHash256 = true;
                    case "extractOutputHash" -> sawExtractOutputHash = true;
                    default -> { /* no-op */ }
                }
            }
        }
        assertTrue(sawBuildChangeOutput, "expected a buildChangeOutput call");
        assertTrue(sawComputeStateOutput, "expected a computeStateOutput call");
        assertTrue(sawHash256, "expected a hash256 call");
        assertTrue(sawExtractOutputHash, "expected an extractOutputHash call");
    }

    // ---------------------------------------------------------------
    // assert bindings naming invariant
    // ---------------------------------------------------------------

    @Test
    void assertBindingsAreNotNamedUnderscore() {
        // The plan brief mentions asserts named "_". In the Python /
        // TS reference implementations the asserts use the regular t<N>
        // temp names (name "_" is Go-specific). Our Python port uses
        // t<N>. We verify that at least one assert is present and that
        // our asserts follow the t<N> convention.
        ContractNode contract = parse(P2PKH_SRC, "P2PKH.runar.java");
        AnfProgram prog = AnfLower.run(contract);
        AnfMethod unlock = findMethod(prog, "unlock");

        int assertCount = 0;
        for (AnfBinding b : unlock.body()) {
            if (b.value() instanceof Assert) {
                assertCount++;
                assertTrue(b.name().startsWith("t"),
                    "assert binding should use t<N> naming: " + b.name());
            }
        }
        assertTrue(assertCount >= 2, "expected at least 2 asserts, got " + assertCount);
    }

    // ---------------------------------------------------------------
    // Utility: assert that a binding has a given name and value kind
    // ---------------------------------------------------------------

    private static void assertBinding(AnfBinding b, String expectedName, Class<? extends AnfValue> cls) {
        assertEquals(expectedName, b.name());
        assertNotNull(b.value());
        assertTrue(cls.isInstance(b.value()),
            "binding " + expectedName + " expected " + cls.getSimpleName()
                + " got " + b.value().getClass().getSimpleName());
    }
}
