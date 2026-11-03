package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * N-288: the N-109 summary covered parameters only. A helper that consumes a
 * PROPERTY ({@code checkSig(this.sig, ..)}, {@code checkPreimage(this.txPreimage)})
 * is inlined at every call site, so calling it twice must get the diagnostic a
 * direct double use of the property gets, also per loop iteration, after a
 * direct consume, through an alias and transitively; a single call, one call per
 * if/else arm, and a helper that only reads the property stay legal.
 *
 * <p>Proves the type checker's verdict only, not the emitted script.
 */
class N288AffinePropertyHelperConsumptionTest {

    private static final String H = "private h(): void { assert(checkSig(this.sig, this.pk)); }";

    private static final String STATELESS = "class C extends SmartContract {\n"
        + "  readonly pk: PubKey;\n"
        + "  readonly sig: Sig;\n"
        + "  constructor(pk: PubKey, sig: Sig) { super(pk, sig); this.pk = pk; this.sig = sig; }\n";

    private static final String STATEFUL = "class C extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  constructor(count: bigint) { super(count); this.count = count; }\n";

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "S | H |  | this.h(); this.h(); | affine value 'this.sig' has already been consumed",
        "S | H |  | for (let i = 0n; i < 2n; i++) { this.h(); } | affine value 'this.sig' has already been consumed",
        "S | H |  | assert(checkSig(this.sig, this.pk)); this.h(); | affine value 'this.sig' has already been consumed",
        "S | H private g(t: bigint): void { assert(t > 0n); this.h(); } |  | this.g(1n); this.g(2n); | affine value 'this.sig' has already been consumed",
        "S | private h(): void { const a: Sig = this.sig; assert(checkSig(a, this.pk)); } |  | this.h(); this.h(); | affine value 'this.sig' has already been consumed",
        "F | private h(): void { assert(checkPreimage(this.txPreimage)); } |  | this.h(); this.h(); this.count = this.count + 1n; | affine value 'this.txPreimage' has already been consumed",
        "S | H |  | this.h(); | ",
        "S | H | flag: boolean | if (flag) { this.h(); } else { this.h(); } | ",
        "S | private n(): bigint { return len(this.sig); } |  | assert(this.n() > 0n); assert(this.n() > 0n); assert(checkSig(this.sig, this.pk)); | ",
    })
    void affinePropertyConsumptionThroughHelpers(String kind, String helpers, String params, String body, String want) throws Exception {
        String src = ("F".equals(kind) ? STATEFUL : STATELESS)
            + "  " + helpers.replaceFirst("^H\\b", H) + "\n"
            + "  public m(" + (params == null ? "" : params) + ") {\n    " + body + "\n    assert(true);\n  }\n}\n";
        ContractNode c = ParserDispatch.parse(src, "C.runar.ts");
        List<String> errs = Typecheck.collect(c);
        if (want == null) {
            assertTrue(errs.isEmpty(), body + ": expected no errors, got " + errs);
        } else {
            assertTrue(errs.stream().anyMatch(e -> e.contains(want)), body + ": expected '" + want + "', got " + errs);
        }
    }
}
