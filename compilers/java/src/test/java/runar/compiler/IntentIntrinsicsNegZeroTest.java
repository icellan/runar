package runar.compiler;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.GoParser;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.passes.AnfLower;
import runar.compiler.passes.Typecheck;
import runar.compiler.passes.Validate;

/**
 * N-060 — a {@code -0} index evades the literal gate and silently DELETES the
 * covenant.
 *
 * <p>The typecheck index gate in {@code Typecheck.java} accepts
 * {@code UnaryExpr{NEG, BigIntLiteral}} only so that a negative index reports
 * "must be &gt;= 0" instead of the misleading "must be an integer literal".
 * {@code -0} negates to {@code 0}, so it passes that bound check — but
 * {@code AnfLower} matches on a BARE {@code BigIntLiteral} and, finding a
 * {@code UnaryExpr}, falls through to {@code load_const ""}: no witness param,
 * no hash assertion, NO COVENANT, and no diagnostic. A contract whose whole
 * purpose is the covenant compiles to a script that does not carry it.
 *
 * <p>Mirrors {@code compilers/rust/tests/intent_intrinsics_bounds.rs} (R-068).
 */
class IntentIntrinsicsNegZeroTest {

    private static final String EPS_NEG_ZERO_SRC = """
        package x

        import runar "github.com/icellan/runar/packages/runar-go"

        type Cov struct {
        \trunar.StatefulSmartContract
        \tH     runar.ByteString
        \tCount runar.Bigint
        }

        func (c *Cov) Bind() {
        \ts := runar.ExtractPrevOutputScript(-0, c.H)
        \trunar.Assert(runar.Len(s) > 0)
        \tc.Count = c.Count + 1
        }
        """;

    private static final String ROP_NEG_ZERO_SRC = """
        package x

        import runar "github.com/icellan/runar/packages/runar-go"

        type Cov struct {
        \trunar.StatefulSmartContract
        \tPKH   runar.ByteString
        \tAmt   runar.Bigint
        \tCount runar.Bigint
        }

        func (c *Cov) Pay() {
        \trunar.RequireOutputP2PKH(-0, c.PKH, c.Amt)
        \tc.Count = c.Count + 1
        }
        """;

    private static ContractNode parse(String source) {
        try {
            return GoParser.parse(source, "Test.runar.go");
        } catch (GoParser.ParseException e) {
            throw new AssertionError("parse failed: " + e.getMessage(), e);
        }
    }

    private static void expectTypeError(String source, String substr) {
        ContractNode contract = parse(source);
        List<String> errors;
        try {
            Typecheck.run(contract);
            errors = List.of();
        } catch (Typecheck.TypeCheckException e) {
            errors = e.errors();
        }
        boolean matched = false;
        for (String e : errors) {
            if (e.contains(substr)) { matched = true; break; }
        }
        assertTrue(
            matched,
            "expected typecheck error containing '" + substr + "' but got: " + errors);
    }

    /** Lower to ANF, or null when typecheck rejected the source. */
    private static List<String> loweredParamNames(String source) {
        ContractNode contract = parse(source);
        Validate.run(contract);
        try {
            Typecheck.run(contract);
        } catch (Typecheck.TypeCheckException e) {
            return null;
        }
        AnfProgram program = AnfLower.run(contract);
        List<String> names = new ArrayList<>();
        for (AnfMethod m : program.methods()) {
            for (AnfParam p : m.params()) names.add(p.name());
        }
        return names;
    }

    private static boolean anyStartsWith(List<String> names, String prefix) {
        for (String n : names) if (n.startsWith(prefix)) return true;
        return false;
    }

    @Test
    void extractPrevOutputScript_negativeZeroIndex_rejects() {
        expectTypeError(EPS_NEG_ZERO_SRC, "must be an integer literal");
    }

    @Test
    void requireOutputP2PKH_negativeZeroIndex_rejects() {
        expectTypeError(ROP_NEG_ZERO_SRC, "must be an integer literal");
    }

    /**
     * The funds-safety half of the pair: a {@code -0} index must never reach
     * codegen, because when it does the intrinsic lowers to a bare
     * empty-string constant and the covenant it was supposed to install is
     * simply absent.
     */
    @Test
    void negativeZeroIndex_neverSilentlyDropsTheCovenant() {
        String[][] cases = {
            {"extractPrevOutputScript", EPS_NEG_ZERO_SRC},
            {"requireOutputP2PKH", ROP_NEG_ZERO_SRC},
        };
        for (String[] c : cases) {
            List<String> names = loweredParamNames(c[1]);
            if (names == null) continue;
            fail(c[0] + "(-0, ...) compiled with NO diagnostic; covenant params present: "
                + "_prevOutScript_=" + anyStartsWith(names, "_prevOutScript_")
                + " _serialisedOutputs=" + names.contains("_serialisedOutputs"));
        }
    }

    // Controls — the valid forms must keep lowering exactly as before.

    @Test
    void control_literalZeroIndexStillInstallsTheCovenant() {
        String eps = EPS_NEG_ZERO_SRC.replace(
            "ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(0,");
        List<String> names = loweredParamNames(eps);
        assertNotNull(names, "valid eps contract must lower");
        assertTrue(
            names.contains("_prevOutScript_0"),
            "extractPrevOutputScript(0, ...) must still auto-inject its witness param");

        String rop = ROP_NEG_ZERO_SRC.replace(
            "RequireOutputP2PKH(-0,", "RequireOutputP2PKH(1,");
        names = loweredParamNames(rop);
        assertNotNull(names, "valid rop contract must lower");
        assertTrue(
            names.contains("_serialisedOutputs"),
            "requireOutputP2PKH(1, ...) must still auto-inject _serialisedOutputs");
    }

    @Test
    void control_plainNegativeIndexStillReportsTheBoundMessage() {
        String src = EPS_NEG_ZERO_SRC.replace(
            "ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(-3,");
        expectTypeError(src, "must be >= 0");
    }
}
