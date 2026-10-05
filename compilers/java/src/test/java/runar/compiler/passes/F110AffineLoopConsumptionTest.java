package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * F-110: a bounded loop is unrolled {@code count} times, so an affine value
 * bound outside a loop that runs two or more times and consumed in its body is
 * consumed once per iteration. It must get the same diagnostic as a sequential
 * double use; single-iteration loops stay legal.
 *
 * <p>Proves the type checker's verdict only. Does not cover consumption inside
 * private helpers (the affine check is intra-method).
 */
class F110AffineLoopConsumptionTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "sig: Sig | for (let i = 0n; i < 2n; i++) { assert(checkSig(sig, this.pk)); } | affine value 'sig' has already been consumed",
        "preimage: SigHashPreimage | for (let i = 3n; i > 0n; i--) { assert(checkPreimage(preimage)); } | affine value 'preimage' has already been consumed",
        "sig: Sig | for (let i = 0n; i <= 1n; i++) { const s: Sig = sig; assert(checkSig(s, this.pk)); } | affine value 's' has already been consumed",
        "sig: Sig | for (let i = 0n; i < 2n; i++) { for (let j = 0n; j < 1n; j++) { assert(checkSig(sig, this.pk)); } } | affine value 'sig' has already been consumed",
        "sig: Sig | assert(checkSig(sig, this.pk)); for (let i = 0n; i < 1n; i++) { assert(checkSig(sig, this.pk)); } | affine value 'sig' has already been consumed",
        "sig: Sig | for (let i = 0n; i < 1n; i++) { assert(checkSig(sig, this.pk)); } | ",
        "sig: Sig | for (let i = 5n; i >= 5n; i--) { for (let j = 0n; j <= 0n; j++) { assert(checkSig(sig, this.pk)); } } | ",
    })
    void affineConsumptionInRepeatingLoop(String params, String body, String want) throws Exception {
        String src = "class C extends SmartContract {\n"
            + "  readonly pk: PubKey;\n"
            + "  constructor(pk: PubKey) { super(pk); this.pk = pk; }\n"
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
