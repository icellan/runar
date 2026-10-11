package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * F-222: the then and else arms of an if are mutually exclusive, so a Sig
 * consumed once in each arm is consumed once on every path and must typecheck.
 * Every shape where some path consumes twice (an arm plus after the if, before
 * plus an arm, twice in one arm, once per arm inside a 2-iteration loop) must
 * still be refused.
 *
 * <p>Proves the type checker's verdict only. Does not cover the ternary form,
 * which is not an if statement and is still refused.
 */
class F222AffineIfElseArmsTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } | ",
        "if (flag) { const a: Sig = sig; assert(checkSig(a, this.pk)); } else { assert(checkSig(sig, this.pk)); } | ",
        "if (flag) { assert(checkSig(sig, this.pk)); } else { if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } } | ",
        "if (flag) { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk)); | affine value 'sig' has already been consumed",
        "if (flag) { assert(true); } else { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk)); | affine value 'sig' has already been consumed",
        "if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk)); | affine value 'sig' has already been consumed",
        "if (flag) { if (flag) { assert(checkSig(sig, this.pk)); } } else { assert(true); } assert(checkSig(sig, this.pk)); | affine value 'sig' has already been consumed",
        "const a: Sig = sig; if (flag) { assert(checkSig(a, this.pk)); } else { assert(true); } assert(checkSig(sig, this.pk)); | affine value 'sig' has already been consumed",
        "assert(checkSig(sig, this.pk)); if (flag) { assert(checkSig(sig, this.pk)); } | affine value 'sig' has already been consumed",
        "if (flag) { assert(checkSig(sig, this.pk)); assert(checkSig(sig, this.pk)); } else { assert(true); } | affine value 'sig' has already been consumed",
        "if (flag) { assert(true); } else { assert(checkSig(sig, this.pk)); assert(checkSig(sig, this.pk)); } | affine value 'sig' has already been consumed",
        "for (let i = 0n; i < 2n; i++) { if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } } | affine value 'sig' has already been consumed",
    })
    void affineConsumptionAcrossIfElseArms(String body, String want) throws Exception {
        String src = "class C extends SmartContract {\n"
            + "  readonly pk: PubKey;\n"
            + "  constructor(pk: PubKey) { super(pk); this.pk = pk; }\n"
            + "  public m(sig: Sig, flag: boolean) {\n    " + body + "\n    assert(true);\n  }\n}\n";
        ContractNode c = ParserDispatch.parse(src, "C.runar.ts");
        List<String> errs = Typecheck.collect(c);
        if (want == null) {
            assertTrue(errs.isEmpty(), body + ": expected no errors, got " + errs);
        } else {
            assertTrue(errs.stream().anyMatch(e -> e.contains(want)), body + ": expected '" + want + "', got " + errs);
        }
    }
}
