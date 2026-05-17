package runar.compiler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.GoParser;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.passes.AnfLower;
import runar.compiler.passes.Typecheck;
import runar.compiler.passes.Validate;

/**
 * Tests for the intent sub-covenant intrinsics ({@code extractPrevOutputScript},
 * {@code requireOutputP2PKH}, {@code currentBlockHeight}) ported from the Go
 * tier (BSVM Phase 13). Mirrors
 * {@code compilers/go/frontend/intent_intrinsics_test.go}.
 */
class IntentIntrinsicsTest {

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static AnfProgram mustLower(String source) {
        ContractNode contract;
        try {
            contract = GoParser.parse(source, "Test.runar.go");
        } catch (GoParser.ParseException e) {
            throw new AssertionError("parse failed: " + e.getMessage(), e);
        }
        assertNotNull(contract, "parse returned null contract");
        Validate.run(contract);
        Typecheck.run(contract);
        return AnfLower.run(contract);
    }

    private static AnfMethod findMethod(AnfProgram p, String name) {
        for (AnfMethod m : p.methods()) {
            if (m.name().equals(name)) return m;
        }
        throw new AssertionError("method '" + name + "' not found in " + methodNames(p));
    }

    private static String methodNames(AnfProgram p) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < p.methods().size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(p.methods().get(i).name());
        }
        return sb.append(']').toString();
    }

    private static List<String> paramNames(AnfMethod m) {
        List<String> out = new java.util.ArrayList<>(m.params().size());
        for (AnfParam p : m.params()) out.add(p.name());
        return out;
    }

    private static void expectTypeError(String source, String substr) {
        ContractNode contract;
        try {
            contract = GoParser.parse(source, "Test.runar.go");
        } catch (GoParser.ParseException e) {
            throw new AssertionError("parse failed: " + e.getMessage(), e);
        }
        assertNotNull(contract);
        Typecheck.TypeCheckException ex = assertThrows(
            Typecheck.TypeCheckException.class,
            () -> Typecheck.run(contract)
        );
        boolean matched = false;
        for (String e : ex.errors()) {
            if (e.contains(substr)) { matched = true; break; }
        }
        assertTrue(
            matched,
            "expected typecheck error containing '" + substr + "' but got: " + ex.errors()
        );
    }

    // ------------------------------------------------------------------
    // extractPrevOutputScript
    // ------------------------------------------------------------------

    @Test
    void extractPrevOutputScript_autoInjectsWitnessParam() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type IntentCov struct {
            \trunar.StatefulSmartContract
            \tStateCovScriptHash runar.ByteString `runar:"readonly"`
            }

            func (c *IntentCov) CoSpend() {
            \tstateCovScript := runar.ExtractPrevOutputScript(0, c.StateCovScriptHash)
            \t_ = stateCovScript
            }
            """;
        AnfProgram p = mustLower(src);
        AnfMethod m = findMethod(p, "coSpend");
        List<String> names = paramNames(m);
        assertTrue(names.contains("_prevOutScript_0"),
            "expected param '_prevOutScript_0' in " + names);
        assertTrue(names.contains("txPreimage"),
            "expected param 'txPreimage' in " + names);
    }

    @Test
    void extractPrevOutputScript_twoIndicesProduceTwoParams() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type IntentCov struct {
            \trunar.StatefulSmartContract
            \tH0 runar.ByteString `runar:"readonly"`
            \tH1 runar.ByteString `runar:"readonly"`
            }

            func (c *IntentCov) CoSpend() {
            \ta := runar.ExtractPrevOutputScript(0, c.H0)
            \tb := runar.ExtractPrevOutputScript(1, c.H1)
            \t_ = a
            \t_ = b
            }
            """;
        AnfProgram p = mustLower(src);
        AnfMethod m = findMethod(p, "coSpend");
        List<String> names = paramNames(m);
        assertTrue(names.contains("_prevOutScript_0"), "missing _prevOutScript_0 in " + names);
        assertTrue(names.contains("_prevOutScript_1"), "missing _prevOutScript_1 in " + names);
    }

    @Test
    void extractPrevOutputScript_sameIndexIsIdempotent() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type IntentCov struct {
            \trunar.StatefulSmartContract
            \tH0 runar.ByteString `runar:"readonly"`
            }

            func (c *IntentCov) CoSpend() {
            \ta := runar.ExtractPrevOutputScript(0, c.H0)
            \tb := runar.ExtractPrevOutputScript(0, c.H0)
            \t_ = a
            \t_ = b
            }
            """;
        AnfProgram p = mustLower(src);
        AnfMethod m = findMethod(p, "coSpend");
        int count = 0;
        for (AnfParam prm : m.params()) {
            if ("_prevOutScript_0".equals(prm.name())) count++;
        }
        assertEquals(1, count,
            "expected exactly one _prevOutScript_0 param across duplicate calls");
    }

    @Test
    void extractPrevOutputScript_nonLiteralIndex_errors() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type IntentCov struct {
            \trunar.StatefulSmartContract
            \tH0 runar.ByteString `runar:"readonly"`
            }

            func (c *IntentCov) CoSpend(idx runar.Bigint) {
            \t_ = runar.ExtractPrevOutputScript(idx, c.H0)
            }
            """;
        expectTypeError(src, "must be an integer literal");
    }

    // ------------------------------------------------------------------
    // requireOutputP2PKH
    // ------------------------------------------------------------------

    @Test
    void requireOutputP2PKH_autoInjectsSerialisedOutputs() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tBondPKH runar.ByteString `runar:"readonly"`
            \tBond    runar.Bigint     `runar:"readonly"`
            }

            func (c *Cov) PayBond() {
            \trunar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
            }
            """;
        AnfProgram p = mustLower(src);
        AnfMethod m = findMethod(p, "payBond");
        assertTrue(paramNames(m).contains("_serialisedOutputs"),
            "expected '_serialisedOutputs' in " + paramNames(m));
    }

    @Test
    void requireOutputP2PKH_multipleCalls_oneSerialisedOutputsParam() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tBondPKH runar.ByteString `runar:"readonly"`
            \tBond    runar.Bigint     `runar:"readonly"`
            }

            func (c *Cov) PayMulti() {
            \trunar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
            \trunar.RequireOutputP2PKH(1, c.BondPKH, c.Bond)
            }
            """;
        AnfProgram p = mustLower(src);
        AnfMethod m = findMethod(p, "payMulti");
        int count = 0;
        for (AnfParam prm : m.params()) {
            if ("_serialisedOutputs".equals(prm.name())) count++;
        }
        assertEquals(1, count,
            "expected exactly one _serialisedOutputs param across multiple intrinsic calls");
    }

    // ------------------------------------------------------------------
    // Crit-2 — extractPrevOutputScript prefix-hash 3-arg form
    // ------------------------------------------------------------------

    @Test
    void extractPrevOutputScript_prefixForm_lowersWithSubstr() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type IntentTemplate struct {
            \trunar.StatefulSmartContract
            \tExpectedPolicyPrefixHash runar.ByteString `runar:"readonly"`
            }

            func (c *IntentTemplate) Bind() {
            \ts := runar.ExtractPrevOutputScript(0, c.ExpectedPolicyPrefixHash, 600)
            \t_ = s
            }
            """;
        AnfProgram p = mustLower(src);
        AnfMethod m = findMethod(p, "bind");
        // Expect a substr call inside the method body (the prefix
        // extraction preceding the hash256). Distinguish from any other
        // substr by checking it consumes a load_param ref to
        // _prevOutScript_0.
        boolean sawPrefixSubstr = false;
        var body = m.body();
        for (int i = 0; i < body.size(); i++) {
            AnfValue v = body.get(i).value();
            if (v instanceof Call c && "substr".equals(c.func()) && c.args().size() == 3) {
                String ref = c.args().get(0);
                for (int j = 0; j < i; j++) {
                    var prior = body.get(j);
                    if (prior.name().equals(ref)
                        && prior.value() instanceof runar.compiler.ir.anf.LoadParam lp
                        && "_prevOutScript_0".equals(lp.name())) {
                        sawPrefixSubstr = true;
                        break;
                    }
                }
                if (sawPrefixSubstr) break;
            }
        }
        assertTrue(sawPrefixSubstr,
            "expected substr(load_param(_prevOutScript_0), …) for 3-arg prefix form");
    }

    @Test
    void extractPrevOutputScript_prefixForm_nonLiteralPrefixLen_errors() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tH runar.ByteString `runar:"readonly"`
            }

            func (c *Cov) Bind(n runar.Bigint) {
            \t_ = runar.ExtractPrevOutputScript(0, c.H, n)
            }
            """;
        expectTypeError(src, "prefixLen) must be an integer literal");
    }

    @Test
    void extractPrevOutputScript_tooManyArgs_errors() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tH runar.ByteString `runar:"readonly"`
            }

            func (c *Cov) Bind() {
            \t_ = runar.ExtractPrevOutputScript(0, c.H, 600, 999)
            }
            """;
        expectTypeError(src, "expects 2 or 3 arguments");
    }

    // ------------------------------------------------------------------
    // Crit-3 — requireOutputP2PKH + addDataOutput mix rejection
    // ------------------------------------------------------------------

    @Test
    void requireOutputP2PKH_mixedWithAddDataOutput_errors() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tBondPKH runar.ByteString `runar:"readonly"`
            \tBond    runar.Bigint     `runar:"readonly"`
            \tTag     runar.ByteString `runar:"readonly"`
            }

            func (c *Cov) PayBondAndAnnounce() {
            \tc.AddDataOutput(0, c.Tag)
            \trunar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
            }
            """;
        expectTypeError(src, "mixes requireOutputP2PKH() with addDataOutput()");
    }

    @Test
    void requireOutputP2PKH_withoutAddDataOutput_ok() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tBondPKH runar.ByteString `runar:"readonly"`
            \tBond    runar.Bigint     `runar:"readonly"`
            }

            func (c *Cov) PayBond() {
            \trunar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
            }
            """;
        mustLower(src); // must not throw
    }

    @Test
    void requireOutputP2PKH_nonLiteralIndex_errors() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tBondPKH runar.ByteString `runar:"readonly"`
            \tBond    runar.Bigint     `runar:"readonly"`
            }

            func (c *Cov) PayBond(idx runar.Bigint) {
            \trunar.RequireOutputP2PKH(idx, c.BondPKH, c.Bond)
            }
            """;
        expectTypeError(src, "must be an integer literal");
    }

    // ------------------------------------------------------------------
    // currentBlockHeight
    // ------------------------------------------------------------------

    @Test
    void currentBlockHeight_desugarsToExtractLocktime() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Cov struct {
            \trunar.StatefulSmartContract
            \tDeadline runar.Bigint `runar:"readonly"`
            }

            func (c *Cov) Spend() {
            \th := runar.CurrentBlockHeight()
            \trunar.Assert(h <= c.Deadline)
            }
            """;
        AnfProgram p = mustLower(src);
        AnfMethod m = findMethod(p, "spend");
        boolean saw = false;
        for (var b : m.body()) {
            AnfValue v = b.value();
            if (v instanceof Call c && "extractLocktime".equals(c.func())) {
                saw = true;
                break;
            }
        }
        assertTrue(saw, "expected currentBlockHeight() to desugar to extractLocktime call");
    }

    @Test
    void currentBlockHeight_statelessContract_errors() {
        String src = """
            package x

            import runar "github.com/icellan/runar/packages/runar-go"

            type Sl struct {
            \trunar.SmartContract
            \tDeadline runar.Bigint `runar:"readonly"`
            }

            func (c *Sl) Spend() bool {
            \th := runar.CurrentBlockHeight()
            \treturn h > c.Deadline
            }
            """;
        expectTypeError(src, "StatefulSmartContract");
    }
}
