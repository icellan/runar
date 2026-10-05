package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;

/**
 * N-104: the EC identity rewrites R1-R4 (ecAdd(q, O) -> q, ecAdd(O, q) -> q,
 * ecMul(q, 1) -> q, ecMul(q, 0) -> O) must keep the replaced builtin's operand
 * validation in place of the call. They used to drop it, so a malformed or
 * off-curve q was accepted by the optimized script and aborted by the
 * unoptimized one.
 *
 * <p>Pins the exact gate bindings — names, kinds, operands, order — every tier
 * emits (the "gate" entries in optimizer/ec-rules.json), so the seven tiers
 * stay ANF- and hex-identical. Proves this tier emits the gate; the gate's
 * script semantics are executed on the real Spend engine by
 * packages/runar-testing/src/__tests__/n104-ec-optimizer-operand-gate.test.ts.
 */
class N104EcOperandGateTest {

    private static final String INF = "0".repeat(128);
    private static final String FIELD_P_DEC =
        "115792089237316195423570985008687907853269984665640564039457584007908834671663";

    private static final List<String> ADD_GATE = List.of(
        "t_px = call ecPointX p",
        "t_py = call ecPointY p",
        "t_fp = const " + FIELD_P_DEC,
        "t_pxok = bin_op < t_px t_fp",
        "t_pyok = bin_op < t_py t_fp",
        "t_ok = bin_op && t_pxok t_pyok",
        "t_gate = assert t_ok");

    private static final List<String> MUL_GATE = List.of(
        "t_inf = const INFINITY",
        "t_isinf = bin_op === p t_inf bytes",
        "t_oncurve = call ecOnCurve p",
        "t_ok = bin_op || t_isinf t_oncurve",
        "t_gate = assert t_ok");

    private static String describe(AnfBinding b) {
        AnfValue v = b.value();
        String d;
        if (v instanceof LoadParam lp) {
            d = "load_param " + lp.name();
        } else if (v instanceof LoadConst lc && lc.value() instanceof BytesConst bc) {
            String s = bc.hex();
            d = s.equals(INF) ? "const INFINITY" : s.startsWith("@ref:") ? "ref " + s.substring(5) : "const " + s;
        } else if (v instanceof LoadConst lc && lc.value() instanceof BigIntConst bi) {
            d = "const " + bi.value();
        } else if (v instanceof Call c) {
            d = "call " + c.func() + " " + String.join(" ", c.args());
        } else if (v instanceof BinOp bo) {
            d = "bin_op " + bo.op() + " " + bo.left() + " " + bo.right() + (bo.resultType() != null ? " " + bo.resultType() : "");
        } else if (v instanceof Assert a) {
            d = "assert " + a.value();
        } else {
            d = v.kind();
        }
        return b.name() + " = " + d;
    }

    private static List<String> run(AnfBinding second, AnfValue call) {
        List<AnfBinding> body = List.of(
            new AnfBinding("p", new LoadParam("pt"), null),
            second,
            new AnfBinding("t", call, null),
            new AnfBinding("a", new Assert("t"), null));
        AnfProgram prog = new AnfProgram("Test", List.of(),
            List.of(new AnfMethod("test", List.<AnfParam>of(), body, true)));
        List<String> out = new ArrayList<>();
        for (AnfBinding b : AnfOptimize.run(prog).methods().get(0).body()) out.add(describe(b));
        return out;
    }

    private static List<String> expected(List<String> gate, String result) {
        List<String> out = new ArrayList<>();
        out.add("p = load_param pt");
        out.addAll(gate);
        out.add("t = " + result);
        out.add("a = assert t");
        return out;
    }

    private static AnfBinding inf() {
        return new AnfBinding("inf", new LoadConst(new BytesConst(INF)), null);
    }

    private static AnfBinding integer(String name, long n) {
        return new AnfBinding(name, new LoadConst(new BigIntConst(BigInteger.valueOf(n))), null);
    }

    @Test
    void ecAddIdentityRightKeepsGate() {
        assertEquals(expected(ADD_GATE, "ref p"), run(inf(), new Call("ecAdd", List.of("p", "inf"))));
    }

    @Test
    void ecAddIdentityLeftKeepsGate() {
        assertEquals(expected(ADD_GATE, "ref p"), run(inf(), new Call("ecAdd", List.of("inf", "p"))));
    }

    @Test
    void ecMulOneKeepsGate() {
        assertEquals(expected(MUL_GATE, "ref p"), run(integer("one", 1), new Call("ecMul", List.of("p", "one"))));
    }

    @Test
    void ecMulZeroKeepsGate() {
        assertEquals(expected(MUL_GATE, "const INFINITY"), run(integer("zero", 0), new Call("ecMul", List.of("p", "zero"))));
    }
}
