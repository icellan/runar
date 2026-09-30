package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.LoadConst;

/**
 * F-086 — a name minted by the EC optimizer must never collide with a name the
 * method already uses.
 *
 * <p>The scalar-fusing rules (9, 10, 11) bind the folded scalar under a
 * generated name ({@code __ec_opt_N} in this tier) just before the rewritten
 * binding. {@code freshConstName} never checked whether that name was taken.
 * ANF is single-assignment and stack lowering resolves a name to its
 * shallowest slot, so when {@code __ec_opt_N} is already a body binding or a
 * method param the two values alias. Reachable from {@code --ir}, where names
 * are attacker-chosen. Pre-fix, {@code __ec_opt_1 = 999; s = ecAdd(ecMulGen(2),
 * ecMulGen(3)); assert(k == __ec_opt_1)} compiled to a script that accepts
 * k = 5 and rejects the honest k = 999 (@bsv/sdk Spend.validate, strict v1 —
 * F-086 remediation log).
 *
 * <p>Proves: the minted name is fresh w.r.t. every binding (at any depth),
 * param and property; colliding programs compile to exactly the script of
 * their renamed twins. Does not prove: anything about names minted by stack
 * lowering ({@code _codePart}, {@code __param_*}, {@code __merge$*}).
 *
 * <p>The counter is JVM-global and cannot be reset, so each test first
 * observes the name the optimizer mints for the collision-free program and
 * then plants the NEXT one ({@code __ec_opt_<K+1>}) in the program under test.
 */
class F086EcFreshNameCollisionTest {

    private static String programJson(String bodyName, String kParam) {
        List<String> body = new ArrayList<>();
        if (bodyName != null) {
            body.add("{\"name\":\"" + bodyName + "\",\"value\":{\"kind\":\"load_const\",\"value\":999}}");
        }
        body.add("{\"name\":\"t1\",\"value\":{\"kind\":\"load_const\",\"value\":2}}");
        body.add("{\"name\":\"t2\",\"value\":{\"kind\":\"call\",\"func\":\"ecMulGen\",\"args\":[\"t1\"]}}");
        body.add("{\"name\":\"t3\",\"value\":{\"kind\":\"load_const\",\"value\":3}}");
        body.add("{\"name\":\"t4\",\"value\":{\"kind\":\"call\",\"func\":\"ecMulGen\",\"args\":[\"t3\"]}}");
        body.add("{\"name\":\"s\",\"value\":{\"kind\":\"call\",\"func\":\"ecAdd\",\"args\":[\"t2\",\"t4\"]}}");
        body.add("{\"name\":\"t5\",\"value\":{\"kind\":\"load_param\",\"name\":\"p\"}}");
        body.add("{\"name\":\"t6\",\"value\":{\"kind\":\"bin_op\",\"op\":\"===\",\"left\":\"s\",\"right\":\"t5\"}}");
        body.add("{\"name\":\"t7\",\"value\":{\"kind\":\"assert\",\"value\":\"t6\"}}");
        body.add("{\"name\":\"t8\",\"value\":{\"kind\":\"load_param\",\"name\":\"" + kParam + "\"}}");
        String rhs = bodyName;
        if (bodyName == null) {
            body.add("{\"name\":\"t9c\",\"value\":{\"kind\":\"load_const\",\"value\":999}}");
            rhs = "t9c";
        }
        body.add("{\"name\":\"t9\",\"value\":{\"kind\":\"bin_op\",\"op\":\"===\",\"left\":\"t8\",\"right\":\"" + rhs + "\"}}");
        body.add("{\"name\":\"t10\",\"value\":{\"kind\":\"assert\",\"value\":\"t9\"}}");
        return "{\"contractName\":\"EcOptCollide\",\"properties\":[],\"methods\":["
            + "{\"name\":\"constructor\",\"isPublic\":false,\"params\":[],"
            + "\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"call\",\"func\":\"super\",\"args\":[]}}]},"
            + "{\"name\":\"unlock\",\"isPublic\":true,"
            + "\"params\":[{\"name\":\"p\",\"type\":\"Point\"},{\"name\":\"" + kParam + "\",\"type\":\"bigint\"}],"
            + "\"body\":[" + String.join(",", body) + "]}]}";
    }

    private static AnfMethod optimizedUnlock(String json) {
        return AnfOptimize.run(AnfLoader.parse(json)).methods().stream()
            .filter(m -> m.name().equals("unlock")).findFirst().orElseThrow();
    }

    /** The name the fused `s` consumes. */
    private static String fusedArg(AnfMethod m) {
        AnfBinding s = m.body().stream().filter(b -> b.name().equals("s")).findFirst().orElseThrow();
        Call c = assertInstanceOf(Call.class, s.value());
        assertEquals("ecMulGen", c.func());
        return c.args().get(0);
    }

    /** The constant the fused `s` consumes: the unique prior binding of its arg. */
    private static BigInteger fusedScalar(AnfMethod m) {
        String arg = fusedArg(m);
        for (AnfParam p : m.params()) {
            assertFalse(p.name().equals(arg), "fused scalar " + arg + " is a param name");
        }
        List<AnfBinding> prior = new ArrayList<>();
        for (AnfBinding b : m.body()) {
            if (b.name().equals("s")) break;
            if (b.name().equals(arg)) prior.add(b);
        }
        assertEquals(1, prior.size(), "fused scalar name " + arg + " bound " + prior.size() + " times");
        LoadConst lc = assertInstanceOf(LoadConst.class, prior.get(0).value());
        return assertInstanceOf(BigIntConst.class, lc.value()).value();
    }

    private static void assertSingleAssignment(AnfMethod m) {
        Set<String> seen = new HashSet<>();
        for (AnfParam p : m.params()) seen.add(p.name());
        for (AnfBinding b : m.body()) {
            assertTrue(seen.add(b.name()), "binding " + b.name() + " reuses a param or binding name");
        }
    }

    /** The `__ec_opt_N` the NEXT fusing rewrite will mint. */
    private static String nextMintedName() {
        String last = fusedArg(optimizedUnlock(programJson(null, "k")));
        assertTrue(last.startsWith("__ec_opt_"), last);
        return "__ec_opt_" + (Integer.parseInt(last.substring("__ec_opt_".length())) + 1);
    }

    private static String hex(String json) {
        return Emit.run(Peephole.run(StackLower.run(Cli.optimizeAnf(AnfLoader.parse(json), true))));
    }

    @Test
    void noCollisionFusesToFive() {
        assertEquals(BigInteger.valueOf(5), fusedScalar(optimizedUnlock(programJson(null, "k"))));
    }

    @Test
    void preexistingBodyBindingIsNotShadowed() {
        AnfMethod m = optimizedUnlock(programJson(nextMintedName(), "k"));
        assertSingleAssignment(m);
        assertEquals(BigInteger.valueOf(5), fusedScalar(m));
    }

    @Test
    void paramIsNotShadowed() {
        AnfMethod m = optimizedUnlock(programJson(null, nextMintedName()));
        assertSingleAssignment(m);
        assertEquals(BigInteger.valueOf(5), fusedScalar(m));
    }

    @Test
    void collidingProgramsCompileLikeTheirRenamedTwins() {
        String ref = hex(programJson("zz_unused", "k"));
        assertEquals(ref, hex(programJson(nextMintedName(), "k")));
        String refParam = hex(programJson(null, "zz"));
        assertEquals(refParam, hex(programJson(null, nextMintedName())));
    }
}
