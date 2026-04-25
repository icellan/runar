package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BoolConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.DeserializeState;
import runar.compiler.ir.anf.GetStateScript;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.MethodCall;
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.ast.ContractNode;

/**
 * Direct unit tests for {@link AnfLoader}. The loader deserializes canonical
 * ANF JSON produced by the {@code --emit-ir} flag into an {@link AnfProgram}
 * usable by the rest of the pipeline.
 *
 * <p>Coverage strategy: round-trip a representative contract through
 * {@code AnfLower} → {@link Jcs#stringify(Object)} → {@code AnfLoader.parse},
 * asserting structural equivalence. Plus targeted tests per ANF kind to
 * catch typos in the {@code knownKinds} dispatch.
 */
class AnfLoaderTest {

    /* ---------------- Round-trip via real contract ---------------- */

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
            public void increment(SigHashPreimage preimage) {
                this.count = this.count + 1;
                this.addOutput(preimage, this.count);
            }
        }
        """;

    private static AnfProgram lower(String src, String file) {
        ContractNode contract = JavaParser.parse(src, file);
        Validate.run(contract);
        Typecheck.run(contract);
        return AnfLower.run(contract);
    }

    @Test
    void roundTripsP2pkhProgram() {
        AnfProgram original = lower(P2PKH_SRC, "P2PKH.runar.java");
        String json = Jcs.stringify(original);
        assertNotNull(json);
        assertTrue(json.startsWith("{"), "ANF JSON must be an object");

        AnfProgram reloaded = AnfLoader.parse(json);
        assertNotNull(reloaded);
        assertEquals(original.contractName(), reloaded.contractName());
        assertEquals(original.properties().size(), reloaded.properties().size());
        assertEquals(original.methods().size(), reloaded.methods().size());

        for (int i = 0; i < original.methods().size(); i++) {
            AnfMethod a = original.methods().get(i);
            AnfMethod b = reloaded.methods().get(i);
            assertEquals(a.name(), b.name());
            assertEquals(a.isPublic(), b.isPublic());
            assertEquals(a.params().size(), b.params().size());
            assertEquals(a.body().size(), b.body().size(),
                "Method " + a.name() + " body size diverges after round-trip");
        }
    }

    @Test
    void roundTripsCounterProgram() {
        AnfProgram original = lower(COUNTER_SRC, "Counter.runar.java");
        String json = Jcs.stringify(original);
        AnfProgram reloaded = AnfLoader.parse(json);
        assertEquals(original.contractName(), reloaded.contractName());
        assertEquals(original.methods().size(), reloaded.methods().size());

        // The increment method has stateful auto-injected nodes
        // (CheckPreimage, DeserializeState, UpdateProp, AddOutput) — verify
        // they all survive the round-trip.
        AnfMethod inc = findMethod(reloaded, "increment");
        boolean sawCheckPreimage = false;
        boolean sawDeserializeState = false;
        boolean sawUpdateProp = false;
        boolean sawAddOutput = false;
        for (AnfBinding b : inc.body()) {
            if (b.value() instanceof CheckPreimage) sawCheckPreimage = true;
            if (b.value() instanceof DeserializeState) sawDeserializeState = true;
            if (b.value() instanceof UpdateProp) sawUpdateProp = true;
            if (b.value() instanceof AddOutput) sawAddOutput = true;
        }
        assertTrue(sawCheckPreimage, "round-trip must preserve check_preimage");
        assertTrue(sawDeserializeState, "round-trip must preserve deserialize_state");
        assertTrue(sawUpdateProp, "round-trip must preserve update_prop");
        assertTrue(sawAddOutput, "round-trip must preserve add_output");
    }

    @Test
    void roundTripIsIdempotent() {
        AnfProgram original = lower(P2PKH_SRC, "P2PKH.runar.java");
        String json1 = Jcs.stringify(original);
        AnfProgram reloaded = AnfLoader.parse(json1);
        String json2 = Jcs.stringify(reloaded);
        assertEquals(json1, json2,
            "Serialize → parse → serialize must be byte-identical to the first JSON");
    }

    private static AnfMethod findMethod(AnfProgram p, String name) {
        for (AnfMethod m : p.methods()) {
            if (m.name().equals(name)) return m;
        }
        throw new IllegalArgumentException("method not found: " + name);
    }

    /* ---------------- Per-kind direct deserialization ---------------- */

    private static final String EMPTY_SHELL = """
        {
          "contractName":"X",
          "properties":[],
          "methods":[
            {"name":"m","isPublic":true,"params":[],"body":[%s]}
          ]
        }
        """;

    private static AnfBinding firstBinding(String body) {
        AnfProgram p = AnfLoader.parse(EMPTY_SHELL.formatted(body));
        return p.methods().get(0).body().get(0);
    }

    @Test
    void parsesLoadParam() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}}");
        assertTrue(b.value() instanceof LoadParam lp && "x".equals(lp.name()));
    }

    @Test
    void parsesLoadProp() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"load_prop\",\"name\":\"count\"}}");
        assertTrue(b.value() instanceof LoadProp lp && "count".equals(lp.name()));
    }

    @Test
    void parsesLoadConstBigInt() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"load_const\",\"value\":42}}");
        assertTrue(b.value() instanceof LoadConst lc
            && lc.value() instanceof BigIntConst bc
            && bc.value().equals(BigInteger.valueOf(42)));
    }

    @Test
    void parsesLoadConstBool() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"load_const\",\"value\":true}}");
        assertTrue(b.value() instanceof LoadConst lc
            && lc.value() instanceof BoolConst bc
            && bc.value());
    }

    @Test
    void parsesLoadConstBytes() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"load_const\",\"value\":\"deadbeef\"}}");
        assertTrue(b.value() instanceof LoadConst lc
            && lc.value() instanceof BytesConst bc
            && "deadbeef".equals(bc.hex()));
    }

    @Test
    void parsesBinOp() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"bin_op\",\"op\":\"+\",\"left\":\"a\",\"right\":\"b\"}}");
        assertTrue(b.value() instanceof BinOp bo
            && "+".equals(bo.op())
            && "a".equals(bo.left())
            && "b".equals(bo.right()));
    }

    @Test
    void parsesUnaryOp() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"unary_op\",\"op\":\"!\",\"operand\":\"x\"}}");
        assertTrue(b.value() instanceof UnaryOp uo
            && "!".equals(uo.op())
            && "x".equals(uo.operand()));
    }

    @Test
    void parsesCallWithArgs() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"call\",\"func\":\"hash160\",\"args\":[\"a\"]}}");
        assertTrue(b.value() instanceof Call c
            && "hash160".equals(c.func())
            && c.args().size() == 1
            && "a".equals(c.args().get(0)));
    }

    @Test
    void parsesMethodCall() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"method_call\","
                + "\"object\":\"this\",\"method\":\"helper\",\"args\":[\"x\",\"y\"]}}");
        assertTrue(b.value() instanceof MethodCall mc
            && "this".equals(mc.object())
            && "helper".equals(mc.method())
            && mc.args().size() == 2);
    }

    @Test
    void parsesIfWithThenAndElse() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"if\",\"cond\":\"c\","
                + "\"then\":[{\"name\":\"t1\",\"value\":{\"kind\":\"load_const\",\"value\":1}}],"
                + "\"else\":[{\"name\":\"t2\",\"value\":{\"kind\":\"load_const\",\"value\":0}}]}}");
        assertTrue(b.value() instanceof If iv
            && "c".equals(iv.cond())
            && iv.thenBranch().size() == 1
            && iv.elseBranch().size() == 1);
    }

    @Test
    void parsesAssertNode() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"assert\",\"value\":\"cond\"}}");
        assertTrue(b.value() instanceof Assert a && "cond".equals(a.value()));
    }

    @Test
    void parsesUpdatePropNode() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"update_prop\",\"name\":\"count\",\"value\":\"newCount\"}}");
        assertTrue(b.value() instanceof UpdateProp up
            && "count".equals(up.name())
            && "newCount".equals(up.value()));
    }

    @Test
    void parsesGetStateScriptNode() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"get_state_script\"}}");
        assertTrue(b.value() instanceof GetStateScript);
    }

    @Test
    void parsesCheckPreimageNode() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"check_preimage\",\"preimage\":\"p\"}}");
        assertTrue(b.value() instanceof CheckPreimage cp && "p".equals(cp.preimage()));
    }

    @Test
    void parsesDeserializeStateNode() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"deserialize_state\",\"preimage\":\"p\"}}");
        assertTrue(b.value() instanceof DeserializeState ds && "p".equals(ds.preimage()));
    }

    @Test
    void parsesAddOutputNode() {
        AnfBinding b = firstBinding(
            "{\"name\":\"t0\",\"value\":{\"kind\":\"add_output\","
                + "\"satoshis\":\"sats\",\"stateValues\":[\"a\",\"b\"],\"preimage\":\"p\"}}");
        assertTrue(b.value() instanceof AddOutput ao
            && "sats".equals(ao.satoshis())
            && ao.stateValues().size() == 2
            && "p".equals(ao.preimage()));
    }

    /* ---------------- Negative tests: malformed JSON ---------------- */

    @Test
    void rejectsUnknownKind() {
        RuntimeException ex = assertThrows(
            RuntimeException.class,
            () -> firstBinding(
                "{\"name\":\"t0\",\"value\":{\"kind\":\"totally_made_up_kind\"}}")
        );
        assertTrue(ex.getMessage().contains("totally_made_up_kind")
                || ex.getMessage().toLowerCase().contains("unknown"),
            "Expected message to mention the unknown kind, got: " + ex.getMessage());
    }

    @Test
    void rejectsTrailingGarbage() {
        assertThrows(RuntimeException.class, () -> AnfLoader.parse(
            "{\"contractName\":\"X\",\"properties\":[],\"methods\":[]} GARBAGE"));
    }

    @Test
    void rejectsNonObjectRoot() {
        assertThrows(RuntimeException.class, () -> AnfLoader.parse("[]"));
        assertThrows(RuntimeException.class, () -> AnfLoader.parse("\"string\""));
        assertThrows(RuntimeException.class, () -> AnfLoader.parse("42"));
    }

    @Test
    void rejectsTruncatedJson() {
        assertThrows(RuntimeException.class, () -> AnfLoader.parse(
            "{\"contractName\":\"X\",\"properties\":[]"));
    }

    @Test
    void rejectsMalformedString() {
        assertThrows(RuntimeException.class, () -> AnfLoader.parse(
            "{\"contractName\":\"X\\\",\"properties\":[],\"methods\":[]}"));
    }

    @Test
    void rejectsBadEscapeSequence() {
        assertThrows(RuntimeException.class, () -> AnfLoader.parse(
            "{\"contractName\":\"X\\q\",\"properties\":[],\"methods\":[]}"));
    }
}
