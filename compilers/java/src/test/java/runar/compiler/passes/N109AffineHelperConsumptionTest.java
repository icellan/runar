package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * N-109: private helpers are inlined, so a call consumes the arguments at the
 * parameter positions the helper consumes (directly, through an alias, or
 * transitively through another helper). {@code this.h(sig)} twice, or once in a
 * 2-iteration loop, must get the same diagnostic as a sequential double use; a
 * single call, one call per if/else arm, and a helper that takes a Sig without
 * consuming it stay legal.
 *
 * <p>Proves the type checker's verdict only. Does not cover a helper consuming a
 * PROPERTY (the summary is over parameters).
 */
class N109AffineHelperConsumptionTest {

    private static final String H = "private h(s: Sig): void { assert(checkSig(s, this.pk)); }";

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "H | sig: Sig | this.h(sig); this.h(sig); | affine value 'sig' has already been consumed",
        "H | sig: Sig | for (let i = 0n; i < 2n; i++) { this.h(sig); } | affine value 'sig' has already been consumed",
        "H | sig: Sig | assert(checkSig(sig, this.pk)); this.h(sig); | affine value 'sig' has already been consumed",
        "H private g(t: bigint, s2: Sig): void { assert(t > 0n); this.h(s2); } | sig: Sig | this.g(1n, sig); this.g(2n, sig); | affine value 'sig' has already been consumed",
        "private h(s: Sig): void { const a: Sig = s; assert(checkSig(a, this.pk)); } | sig: Sig | this.h(sig); this.h(sig); | affine value 'sig' has already been consumed",
        "private p(x: SigHashPreimage): void { assert(checkPreimage(x)); } | preimage: SigHashPreimage | this.p(preimage); this.p(preimage); | affine value 'preimage' has already been consumed",
        "H | sig: Sig | this.h(sig); | ",
        "H | sig: Sig, flag: boolean | if (flag) { this.h(sig); } else { this.h(sig); } | ",
        "H | sig1: Sig, sig2: Sig | this.h(sig1); this.h(sig2); | ",
        "private n(s: Sig): bigint { return len(s); } | sig: Sig | assert(this.n(sig) > 0n); assert(this.n(sig) > 0n); assert(checkSig(sig, this.pk)); | ",
    })
    void affineConsumptionThroughHelpers(String helpers, String params, String body, String want) throws Exception {
        String src = "class C extends SmartContract {\n"
            + "  readonly pk: PubKey;\n"
            + "  constructor(pk: PubKey) { super(pk); this.pk = pk; }\n"
            + "  " + helpers.replaceFirst("^H\\b", H) + "\n"
            + "  public m(" + params + ") {\n    " + body + "\n    assert(true);\n  }\n}\n";
        ContractNode c = ParserDispatch.parse(src, "C.runar.ts");
        List<String> errs = Typecheck.collect(c);
        if (want == null) {
            assertTrue(errs.isEmpty(), body + ": expected no errors, got " + errs);
        } else {
            assertTrue(errs.stream().anyMatch(e -> e.contains(want)), body + ": expected '" + want + "', got " + errs);
        }
    }
}
