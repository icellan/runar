package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.ast.ContractNode;

/**
 * F-024 (CL-BUG-079, user decision R14) — Java-tier port of
 * packages/runar-compiler/src/__tests__/f024-continuation-amount.test.ts.
 *
 * <p>Proves (Java tier, TS surface): every default single-output continuation
 * carries the injected {@code assert(_newAmount >= extractAmount(txPreimage))}
 * ANF (load_param txPreimage; call extractAmount; load_param _newAmount;
 * bin_op >=; assert) after the body; addOutput and terminal methods do not;
 * {@code continuationAmount()} lowers to load_param _newAmount where that
 * witness exists and is refused everywhere else; a write to it is refused.
 * Does NOT prove on-chain rejection of a drain (the TS Spend test does) or
 * cross-tier byte parity (conformance).
 */
class F024ContinuationAmountTest {

    private static final String COUNTER = String.join("\n",
        "class Counter extends StatefulSmartContract {",
        "  count: bigint;",
        "  constructor(count: bigint) { super(count); this.count = count; }",
        "  public increment() { this.count = this.count + 1n; }",
        "  public addTo(amount: bigint) { this.addOutput(1000n, this.count + amount); }",
        "  public close() { assert(this.count > 0n); }",
        "  public log(payload: ByteString) { this.addDataOutput(0n, payload); }",
        "}", "");

    private static final String READ_ONLY = "continuationAmount() is read-only and cannot be assigned";
    private static final String UNAVAILABLE =
        "continuationAmount() is only available in a public StatefulSmartContract method whose state "
            + "continues through the default single-output continuation";

    private static String pot(String body) {
        return "class Pot extends StatefulSmartContract {\n  count: bigint;\n"
            + "  constructor(count: bigint) { super(count); this.count = count; }\n  " + body + "\n}\n";
    }

    private static AnfProgram lower(String src) throws Exception {
        ContractNode contract = ParserDispatch.parse(src, "C.runar.ts");
        Validate.run(contract);
        Typecheck.run(contract);
        contract = ExpandFixedArrays.run(contract);
        return AnfLower.run(contract);
    }

    private static String refusal(String src) {
        try {
            lower(src);
        } catch (Exception | Error e) {
            return String.valueOf(e.getMessage());
        }
        fail("expected a refusal, it compiled:\n" + src);
        return null;
    }

    private static AnfMethod publicMethod(AnfProgram p, String name) {
        for (AnfMethod m : p.methods()) {
            if (m.isPublic() && m.name().equals(name)) return m;
        }
        throw new AssertionError("no public method " + name);
    }

    private static List<String> kinds(List<AnfBinding> body) {
        List<String> out = new ArrayList<>();
        for (AnfBinding b : body) {
            out.add(b.value() instanceof Call c ? "call:" + c.func() : b.value().kind());
        }
        return out;
    }

    private static List<Integer> injectedCheckAt(List<AnfBinding> body) {
        List<Integer> hits = new ArrayList<>();
        for (int i = 0; i + 4 < body.size(); i++) {
            AnfBinding a = body.get(i), b = body.get(i + 1), c = body.get(i + 2), d = body.get(i + 3), e = body.get(i + 4);
            boolean ok = a.value() instanceof LoadParam la && la.name().equals("txPreimage")
                && b.value() instanceof Call cb && cb.func().equals("extractAmount") && cb.args().equals(List.of(a.name()))
                && c.value() instanceof LoadParam lc && lc.name().equals("_newAmount")
                && d.value() instanceof BinOp bo && bo.op().equals(">=") && bo.left().equals(c.name()) && bo.right().equals(b.name())
                && e.value() instanceof Assert as && as.value().equals(d.name()) && !as.isAutoInjectedStateCheck();
            if (ok) hits.add(i);
        }
        return hits;
    }

    @Test
    void defaultContinuationCarriesTheValueCheck() throws Exception {
        AnfProgram p = lower(COUNTER);
        List<AnfBinding> body = publicMethod(p, "increment").body();
        List<Integer> hits = injectedCheckAt(body);
        assertEquals(1, hits.size(), kinds(body).toString());
        List<String> k = kinds(body);
        assertTrue(k.subList(0, hits.get(0)).contains("update_prop"));
        List<String> after = k.subList(hits.get(0) + 5, k.size());
        for (String w : List.of("if", "get_state_script", "call:computeStateOutput")) {
            assertTrue(after.contains(w), w + " must follow the check: " + k);
        }
        assertEquals(1, injectedCheckAt(publicMethod(p, "log").body()).size());
        for (String name : List.of("addTo", "close")) {
            AnfMethod m = publicMethod(p, name);
            assertFalse(m.params().stream().anyMatch(x -> x.name().equals("_newAmount")), name);
            assertFalse(kinds(m.body()).contains("call:extractAmount"), name);
        }
    }

    @Test
    void continuationAmountReadLowersToNewAmount() throws Exception {
        AnfProgram p = lower(pot("public join(bet: bigint) {\n"
            + "    assert(continuationAmount() == extractAmount(this.txPreimage) + bet);\n"
            + "    this.count = this.count + 1n;\n  }"));
        List<AnfBinding> body = publicMethod(p, "join").body();
        List<Integer> hits = injectedCheckAt(body);
        assertEquals(1, hits.size());
        int first = -1;
        for (int i = 0; i < body.size(); i++) {
            if (body.get(i).value() instanceof LoadParam lp && lp.name().equals("_newAmount")) { first = i; break; }
        }
        assertTrue(first >= 0 && first < hits.get(0), "the author's read is its own load before the check");
    }

    @Test
    void continuationAmountRefusals() {
        String stateless = "class P extends SmartContract {\n  readonly x: bigint;\n"
            + "  constructor(x: bigint) { super(x); this.x = x; }\n"
            + "  public unlock() { assert(continuationAmount() > this.x); }\n}\n";
        String[][] cases = {
            {"write", pot("public join() { continuationAmount() = 5n; this.count = this.count + 1n; }"), READ_ONLY},
            {"increment", pot("public join() { continuationAmount()++; this.count = this.count + 1n; }"), READ_ONLY},
            {"stateless", stateless, "continuationAmount() is only available in StatefulSmartContract methods"},
            {"terminal", pot("public close() { assert(continuationAmount() > 0n); }"), UNAVAILABLE},
            {"addOutput", pot("public split() { this.addOutput(continuationAmount(), this.count); }"), UNAVAILABLE},
            {"private", pot("private amt(): bigint { return continuationAmount(); }\n"
                + "  public bump() { this.count = this.count + this.amt(); }"), UNAVAILABLE},
        };
        for (String[] c : cases) {
            String msg = refusal(c[1]);
            assertTrue(msg.contains(c[2]), c[0] + ": want \"" + c[2] + "\" in: " + msg);
        }
    }
}
